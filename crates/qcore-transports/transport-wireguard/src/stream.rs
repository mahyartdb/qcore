//! Tunnel-channel framing (TCP streams + UDP datagrams inside WireGuard
//! transport-data payloads).
//!
//! WireGuard carries IP packets, so every frame rides as the payload of a
//! minimal IPv4 packet (20-byte header, IP protocol 253 experimental,
//! correct total length + checksum). This is real IP framing, not a bypass:
//! a future TUN host integration routes these packets as-is.
//!
//! Inner frame format (all multi-byte integers big-endian):
//! - OPEN  `[0x01][stream u32][dst_len u8][dst "ip:port" utf8]`
//! - DATA  `[0x02][stream u32][seq u32][payload]`
//! - FIN   `[0x03][stream u32]`
//! - DGRAM `[0x04][dst_len u8][dst "ip:port" utf8][payload]`
//!
//! Delivery is in-order per stream with a small reorder buffer. Reliability
//! beyond the carrier's is out of scope for v1 (loopback/LAN carriers are
//! lossless; loss stalls a stream — documented, never silent corruption).

#[cfg(test)]
use std::sync::atomic::AtomicBool;

use bytes::Bytes;
use qcore_transport_api::{ByteStream, HopError, HopEvent};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{
    atomic::{AtomicU32, AtomicU64, Ordering},
    Arc, Mutex,
};

const OPEN: u8 = 0x01;
const DATA: u8 = 0x02;
const FIN: u8 = 0x03;
const DGRAM: u8 = 0x04;

/// Per-stream in-order lane cap (#12 queue decision: bounded-block). Matches
/// the reorder window below (1024 seqs): a reader more than a full window
/// behind is congested, not merely slow. Overflow drops (never blocks — the
/// dispatch path is sync and holds the table lock) and counts into
/// [`StreamTable::stream_drops`], surfaced as [`HopEvent::Congested`].
pub const STREAM_QUEUE_CAP: usize = 1024;

/// Reorder window in sequence numbers: a DATA chunk ahead of the in-order
/// cursor by less than this is buffered pending its predecessors; at or
/// beyond this it can never be re-ordered into place (the cursor advances
/// only via contiguous delivery) and the chunk is dropped — counted as
/// congestion (finding 4).
const REORDER_WINDOW: u32 = 1024;

/// Which end of the WireGuard handshake this table dials from. Stream ids
/// are `u32` split into two disjoint spaces by parity so both ends can dial
/// outward through one tunnel without collision (finding 3):
///
/// - the handshake **initiator** allocates local ids `1, 3, 5, …` (odd);
/// - the handshake **responder** allocates local ids `2, 4, 6, …` (even);
/// - the remote end's ids are the complementary space.
///
/// Invariant: an inbound OPEN never names a locally allocated id — the peer
/// allocates only from its own space. `dispatch` enforces this fail-closed:
/// a remote OPEN in our space is rejected and counted
/// ([`StreamTable::rejected_opens`]), never inserted over a local lane.
/// `u32` arithmetic with step 2 preserves parity through wrapping
/// (…, 4294967295, 1, … odd; …, 4294967294, 0, … even).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamSide {
    /// We initiated the WireGuard handshake (the only mode
    /// [`crate::WireguardFactory`] builds).
    Initiator,
    /// We answered the handshake (test responders, future server use).
    Responder,
}

/// Cap on concurrent streams per table: lanes are individually bounded
/// (1024 + 1024-seq window) but the id space is a full u32, so one
/// malicious/buggy authenticated peer opening streams without FIN could grow
/// memory without bound. Past the cap, new OPENs are dropped and counted
/// (fail-closed backpressure, observable as `Congested`).
pub const MAX_STREAMS: usize = 1024;

/// IP protocol number carrying tunnel-channel frames (RFC 3692 experimental).
pub const CHANNEL_IP_PROTO: u8 = 253;

/// Wrap a channel frame in a minimal IPv4 packet for the tunnel.
///
/// Built with `extend` (never `vec![0u8; len]`): the payload region is
/// overwritten immediately after allocation, so pre-zeroing it is a wasted
/// pass over up to MTU bytes per packet (#15 perf batch).
pub fn wrap_ip(frame: &[u8]) -> Vec<u8> {
    let total = (20 + frame.len()) as u16;
    let mut pkt = Vec::with_capacity(20 + frame.len());
    pkt.extend_from_slice(&[0x45, 0x00]); // version 4, IHL 5, DSCP 0
    pkt.extend_from_slice(&total.to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 64, CHANNEL_IP_PROTO]);
    // Header checksum over the first 20 bytes with the checksum field zero.
    // Checksum field lives at bytes 10..12; compute after src/dst are set.
    pkt.extend_from_slice(&[0x00, 0x00]); // checksum placeholder
    pkt.extend_from_slice(&[10, 0, 0, 2]); // src (cosmetic pre-TUN)
    pkt.extend_from_slice(&[10, 0, 0, 1]); // dst (cosmetic pre-TUN)
    let sum: u32 = pkt[..20]
        .chunks(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]) as u32)
        .sum();
    let mut sum = sum;
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    pkt[10..12].copy_from_slice(&(!sum as u16).to_be_bytes());
    pkt.extend_from_slice(frame);
    pkt
}

/// Strip the IPv4 envelope. Returns None for non-channel packets (which a
/// TUN integration would route instead of dispatching here).
pub fn unwrap_ip(packet: &[u8]) -> Option<&[u8]> {
    if packet.len() < 20 || packet[0] >> 4 != 4 || packet[9] != CHANNEL_IP_PROTO {
        return None;
    }
    let ihl = ((packet[0] & 0x0F) as usize) * 4;
    if packet.len() < ihl {
        return None;
    }
    let total = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    let end = total.min(packet.len());
    if end < ihl {
        return None;
    }
    Some(&packet[ihl..end])
}
pub type SendFrame = Arc<dyn FrameSender>;

/// Async frame sender: encrypt-and-queue with backpressure (#12 queue
/// decision: bounded-block egress). `send_frame` awaits queue space;
/// `try_send_frame` fails fast with [`HopError::overloaded`] (retryable);
/// `congestion_waiter` resolves when space frees so `poll_write` can park
/// its waker without busy-spinning. WG-internal trait (not the
/// transport-api boundary), so growing it needs no version window.
#[async_trait::async_trait]
pub trait FrameSender: Send + Sync {
    async fn send_frame(&self, frame: Vec<u8>) -> Result<(), HopError>;
    fn try_send_frame(&self, frame: Vec<u8>) -> Result<(), HopError>;
    /// Resolves when the egress queue has space (already ready when it
    /// does). `'static` so `poll_write` can hand it to a spawned waiter:
    /// at most one waiter task per `Poll::Pending`, created only on a full
    /// queue.
    fn congestion_waiter(&self) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>>;
}

enum StreamMsg {
    /// One in-order payload chunk. `Bytes` (not `Vec<u8>`): the dispatch
    /// path hands over its owned frame buffer zero-copy (`Bytes::from`)
    /// and slices the header off by refcount, so queueing never copies.
    /// Cloning a chunk for fan-out would be a refcount bump, not a copy.
    Data(Bytes),
    Fin,
}

struct StreamEntry {
    tx: tokio::sync::mpsc::Sender<StreamMsg>,
    /// Next sequence number the reader expects.
    expect: u32,
    pending: BTreeMap<u32, Bytes>,
}

/// Demultiplexing table shared by one hop.
pub struct StreamTable {
    inner: Mutex<TableInner>,
    /// Next locally allocated stream id (see [`StreamSide`] for the
    /// odd/even invariant). Stepped +2 from its start.
    next_id: AtomicU32,
    dgrams: tokio::sync::broadcast::Sender<(Vec<u8>, SocketAddr)>,
    /// Congestion sink (#12 observability hook): set once at hop bring-up.
    /// `Mutex` (never held across await) guards the one-time install;
    /// counters are atomics so hot paths never lock for accounting.
    sink: Mutex<Option<(String, tokio::sync::broadcast::Sender<HopEvent>)>>,
    /// Cumulative stream-lane drops (bounded lane overflow, FIN loss).
    stream_drops: AtomicU64,
    /// Cumulative datagram-lag skips (`Lagged` on the dgram fan-out).
    dgram_drops: AtomicU64,
    /// Remote OPENs rejected for naming a locally-allocated id (finding 3
    /// fail-closed accounting).
    rejected_opens: AtomicU64,
}

struct TableInner {
    streams: HashMap<u32, StreamEntry>,
}

impl StreamTable {
    /// Table dialing from `side`'s id space. The hop installs
    /// [`StreamSide::Initiator`] (it always initiates the WireGuard
    /// handshake); test responders install `Responder`.
    pub fn new_with_side(side: StreamSide) -> Self {
        let first = match side {
            StreamSide::Initiator => 1,
            StreamSide::Responder => 2,
        };
        let table = StreamTable::new();
        table.next_id.store(first, Ordering::Relaxed);
        table
    }

    pub fn new() -> Self {
        let (dgrams, _) = tokio::sync::broadcast::channel(256);
        StreamTable {
            inner: Mutex::new(TableInner {
                streams: HashMap::new(),
            }),
            next_id: AtomicU32::new(1),
            dgrams,
            sink: Mutex::new(None),
            stream_drops: AtomicU64::new(0),
            dgram_drops: AtomicU64::new(0),
            rejected_opens: AtomicU64::new(0),
        }
    }

    pub fn subscribe_dgrams(&self) -> tokio::sync::broadcast::Receiver<(Vec<u8>, SocketAddr)> {
        self.dgrams.subscribe()
    }

    /// Install the congestion sink once (hop bring-up). Later calls replace
    /// it; `None` (tests, table-only use) means count without emitting.
    pub fn observe(&self, hop_id: String, events: tokio::sync::broadcast::Sender<HopEvent>) {
        *self.sink.lock().unwrap() = Some((hop_id, events));
    }

    /// Cumulative stream-lane drops since creation.
    pub fn stream_drops(&self) -> u64 {
        self.stream_drops.load(Ordering::Relaxed)
    }

    /// Cumulative datagram-lag skips since creation.
    pub fn dgram_drops(&self) -> u64 {
        self.dgram_drops.load(Ordering::Relaxed)
    }

    /// Remote OPENs rejected for naming a locally-allocated (peer-space)
    /// stream id since creation (finding 3 accounting).
    pub fn rejected_opens(&self) -> u64 {
        self.rejected_opens.load(Ordering::Relaxed)
    }

    /// The locally allocated id space: odd for the handshake initiator,
    /// even for the responder (see [`StreamSide`]).
    fn allocates_parity(&self) -> u32 {
        self.next_id.load(Ordering::Relaxed) & 1
    }

    /// Drop every stream entry (hop stop): closing the per-lane channels
    /// delivers EOF/error to parked readers — writes already fail `Closed`.
    pub fn clear(&self) {
        self.inner.lock().unwrap().streams.clear();
    }

    /// Count stream-lane drops and emit one `Congested` carrying the new
    /// cumulative total (best-effort: a full event bus drops the event, and
    /// the session forwarder's own lag accounting re-emits the count).
    pub fn record_stream_drops(&self, n: u64) {
        if n == 0 {
            return;
        }
        let total = self.stream_drops.fetch_add(n, Ordering::Relaxed) + n;
        self.emit_congested(total);
    }

    /// Count datagram-lag skips (same emit rule as stream drops).
    pub fn record_dgram_drops(&self, n: u64) {
        if n == 0 {
            return;
        }
        let total = self.dgram_drops.fetch_add(n, Ordering::Relaxed) + n;
        self.emit_congested(total);
    }

    fn emit_congested(&self, dropped: u64) {
        let sink = self.sink.lock().unwrap();
        if let Some((hop_id, events)) = sink.as_ref() {
            let _ = events.send(HopEvent::Congested {
                hop_id: hop_id.clone(),
                dropped,
            });
        }
    }
}

impl Default for StreamTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Route one decrypted frame. Unknown/stale frames are ignored, never fatal.
///
/// Takes the frame buffer by value: `Bytes::from` reuses the caller's
/// allocation (the pump's copy out of its reused decrypt buffer is the one
/// and only copy on ingress) and `slice` drops the 9-byte DATA header by
/// refcount — the pre-`Bytes` code copied the payload a second time here.
pub fn dispatch(table: &StreamTable, frame: Vec<u8>) -> Result<(), String> {
    if frame.is_empty() {
        return Ok(());
    }
    match frame[0] {
        OPEN => {
            let (id, _dst) = parse_open(&frame[1..])?;
            // Parity invariant (finding 3): remote OPENs must name the
            // peer's id space — the complement of ours (odd initiator ⇄
            // even responder). An OPEN in OUR space would collide with a
            // locally allocated stream: pre-fix it was silently ignored
            // while later DATA cross-wired that local lane. Fail closed:
            // reject (never insert over a local lane) and count.
            if id & 1 == table.allocates_parity() {
                table.rejected_opens.fetch_add(1, Ordering::Relaxed);
                return Ok(());
            }
            let mut t = table.inner.lock().unwrap();
            if !t.streams.contains_key(&id) {
                if t.streams.len() >= MAX_STREAMS {
                    // Table full: drop the OPEN and count it (bounded,
                    // observable) instead of growing without bound.
                    drop(t);
                    table.record_stream_drops(1);
                    return Ok(());
                }
                let (tx, _) = tokio::sync::mpsc::channel(STREAM_QUEUE_CAP);
                t.streams.insert(
                    id,
                    StreamEntry {
                        tx,
                        expect: 0,
                        pending: BTreeMap::new(),
                    },
                );
            }
            Ok(())
        }
        DATA => {
            if frame.len() < 9 {
                return Ok(());
            }
            // Guarded by the `frame.len() < 9` early return above.
            let id = u32::from_be_bytes(frame[1..5].try_into().expect("DATA header is 8 bytes"));
            let seq = u32::from_be_bytes(frame[5..9].try_into().expect("DATA header is 8 bytes"));
            // Zero-copy handoff: no payload copy, header sliced by refcount.
            let payload = Bytes::from(frame).slice(9..);
            // Bounded lane: the queue step cannot block (sync path, table
            // lock held). A full lane drops and counts — and, per the module
            // contract (loss stalls a stream, never silent corruption), the
            // in-order cursor is NOT advanced until the chunk is actually
            // queued: advancing first would let seq N+1 take the slot the
            // dropped N was re-delivered into, punching a hole the reader
            // sees as corruption. A closed lane (reader gone) drops
            // silently: only `Full` is congestion. Emission happens after
            // the lock drops.
            let mut dropped = 0u64;
            {
                let mut t = table.inner.lock().unwrap();
                let Some(entry) = t.streams.get_mut(&id) else {
                    return Ok(());
                };
                // In-order delivery with reorder buffer.
                if seq == entry.expect {
                    match entry.tx.try_send(StreamMsg::Data(payload)) {
                        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                            // Congested: the chunk is dropped, the cursor
                            // stays on this seq, so the sender's stall-model
                            // re-delivery can queue it (and the buffered
                            // successors) once the lane drains.
                            dropped += 1;
                        }
                        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {}
                        Ok(()) => {
                            entry.expect = entry.expect.wrapping_add(1);
                            while let Some(next) = entry.pending.remove(&entry.expect) {
                                match entry.tx.try_send(StreamMsg::Data(next)) {
                                    Ok(()) => {
                                        entry.expect = entry.expect.wrapping_add(1);
                                    }
                                    Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                                        dropped += 1;
                                        break;
                                    }
                                    Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => break,
                                }
                            }
                        }
                    }
                } else if seq.wrapping_sub(entry.expect) < REORDER_WINDOW {
                    entry.pending.entry(seq).or_insert(payload);
                } else {
                    // Beyond the reorder window (finding 4): the cursor can
                    // only advance via contiguous delivery, so a chunk this
                    // far ahead can never be re-ordered into place — it is
                    // unrecoverable here. Count it (surfaced as
                    // `Congested`) instead of silently vanishing.
                    dropped += 1;
                }
            }
            table.record_stream_drops(dropped);
            Ok(())
        }
        FIN => {
            if frame.len() < 5 {
                return Ok(());
            }
            // Guarded by the `frame.len() < 5` early return above.
            let id = u32::from_be_bytes(frame[1..5].try_into().expect("FIN header is 4 bytes"));
            let mut t = table.inner.lock().unwrap();
            if let Some(entry) = t.streams.remove(&id) {
                // Best-effort: on a full lane the FIN is skipped, but the
                // entry (and its sender) is still removed above, so the
                // reader observes EOF via channel close either way.
                let _ = entry.tx.try_send(StreamMsg::Fin);
            }
            Ok(())
        }
        DGRAM => {
            let (dst, payload) = parse_dgram(&frame[1..])?;
            let _ = table.dgrams.send((payload, dst));
            Ok(())
        }
        _ => Ok(()),
    }
}

/// Parse a `[len u8][dst "ip:port" utf8]` tail shared by OPEN and DGRAM.
/// Returns the destination and the total bytes consumed (1 + len).
fn parse_dst(b: &[u8]) -> Result<(SocketAddr, usize), String> {
    if b.is_empty() {
        return Err("short dst".into());
    }
    let len = b[0] as usize;
    if b.len() < 1 + len {
        return Err("short dst".into());
    }
    let dst: SocketAddr = std::str::from_utf8(&b[1..1 + len])
        .map_err(|e| e.to_string())?
        .parse()
        .map_err(|e: std::net::AddrParseError| e.to_string())?;
    Ok((dst, 1 + len))
}

fn parse_open(mut b: &[u8]) -> Result<(u32, SocketAddr), String> {
    if b.len() < 5 {
        return Err("short OPEN".into());
    }
    // Guarded by the `b.len() < 5` check above: at least 4 id bytes.
    let id = u32::from_be_bytes(b[..4].try_into().expect("OPEN id is 4 bytes"));
    b = &b[4..];
    let (dst, _) = parse_dst(b)?;
    Ok((id, dst))
}

fn parse_dgram(b: &[u8]) -> Result<(SocketAddr, Vec<u8>), String> {
    let (dst, used) = parse_dst(b)?;
    Ok((dst, b[used..].to_vec()))
}

/// Open an outbound stream to `dst`. Sends OPEN, returns the stream handle.
///
/// The id is allocated from this table's parity space (see [`StreamSide`]):
/// odd when we initiated the WireGuard handshake, even when we answered.
/// The remote end allocates the complementary space, so `dispatch` can
/// reject any inbound OPEN that names our space (finding 3: pre-fix both
/// ends drew from one counter and a peer OPEN could collide with a local
/// stream, silently cross-wiring the lane).
pub async fn open_stream(
    table: &Arc<StreamTable>,
    dst: SocketAddr,
    send: SendFrame,
) -> Result<WgTcpStream, String> {
    let id = fresh_id(table);
    let dst_s = dst.to_string();
    let mut frame = Vec::with_capacity(5 + 1 + dst_s.len());
    frame.push(OPEN);
    frame.extend_from_slice(&id.to_be_bytes());
    frame.push(dst_s.len() as u8);
    frame.extend_from_slice(dst_s.as_bytes());
    send.send_frame(frame).await.map_err(|e| e.to_string())?;
    let (tx, rx) = tokio::sync::mpsc::channel(STREAM_QUEUE_CAP);
    {
        let mut t = table.inner.lock().unwrap();
        // Same bound as inbound OPENs: an unbounded outbound burst is the
        // same memory hole through the local API.
        if t.streams.len() >= MAX_STREAMS {
            return Err("too many concurrent streams".to_string());
        }
        t.streams.insert(
            id,
            StreamEntry {
                tx,
                expect: 0,
                pending: BTreeMap::new(),
            },
        );
    }
    Ok(WgTcpStream {
        id,
        table: table.clone(),
        rx,
        send,
        read_buf: VecDeque::new(),
        eof: false,
        write_seq: AtomicU32::new(0),
    })
}

fn fresh_id(table: &StreamTable) -> u32 {
    // Parity-stepped allocator (see [`StreamSide`]): odd for the initiator,
    // even for the responder. Uniqueness needs atomicity, not cross-thread
    // ordering; `fetch_add(2)` keeps every id in the same space (u32 wrap
    // preserves parity: …, 4294967295, 1, … odd / …, 4294967294, 0, … even).
    table.next_id.fetch_add(2, Ordering::Relaxed)
}

/// Encode one UDP datagram for `dst`.
pub fn encode_dgram(dst: &SocketAddr, payload: &[u8]) -> Vec<u8> {
    encode_dgram_prefixed(&dgram_prefix(dst), payload)
}

/// Pre-encode the `[DGRAM][len u8][dst]` header for a destination-bound
/// flow (encoded once per flow, not formatted per datagram — same reason
/// as the masque prefix).
pub fn dgram_prefix(dst: &SocketAddr) -> Vec<u8> {
    let dst_s = dst.to_string();
    let mut prefix = Vec::with_capacity(2 + dst_s.len());
    prefix.push(DGRAM);
    prefix.push(dst_s.len() as u8);
    prefix.extend_from_slice(dst_s.as_bytes());
    prefix
}

/// Append a payload to a pre-encoded [`dgram_prefix`].
pub fn encode_dgram_prefixed(prefix: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(prefix.len() + payload.len());
    frame.extend_from_slice(prefix);
    frame.extend_from_slice(payload);
    frame
}

/// Max bytes accepted per `poll_write` call (one DATA frame).
/// Sized for throughput, not for path MTU — measured 146 MiB/s vs 49 MiB/s
/// for 1400 B segments (loopback, 8K turns, release, i5-12400). The tradeoff is
/// explicit: an 8.2K outer datagram fragments on 1500-MTU paths (six
/// fragments; one lost fragment kills the datagram on a path documented as
/// stall-on-loss) and costs ~8 MB worst-case egress queue memory per hop at
/// full queue. 1400 B would stay unfragmented but costs 3x per-byte overhead
/// (6x boringtun encrypts, syscalls, queue ops). Revisit alongside
/// loss-aware reliability work; until then throughput wins and the lamp is
/// documented here, not hidden.
pub const WRITE_SEGMENT: usize = 8192;

/// A TCP-like byte stream over the tunnel channel.
pub struct WgTcpStream {
    id: u32,
    table: Arc<StreamTable>,
    rx: tokio::sync::mpsc::Receiver<StreamMsg>,
    send: SendFrame,
    /// Reassembly chunks in arrival order. `Bytes` chunks (not flat bytes):
    /// draining copies whole slices, never byte-by-byte.
    read_buf: VecDeque<Bytes>,
    eof: bool,
    write_seq: AtomicU32,
}

fn fin_frame(id: u32) -> Vec<u8> {
    let mut frame = vec![0u8; 5];
    frame[0] = FIN;
    frame[1..5].copy_from_slice(&id.to_be_bytes());
    frame
}

impl Drop for WgTcpStream {
    fn drop(&mut self) {
        // Best-effort FIN: under congestion the entry removal below still
        // delivers EOF via channel close. A congested FIN counts — it is a
        // real congestion loss, surfaced as `Congested`.
        match self.send.try_send_frame(fin_frame(self.id)) {
            Ok(()) => {}
            Err(e) if e.is_backpressure() => self.table.record_stream_drops(1),
            Err(_) => {}
        }
        self.table.inner.lock().unwrap().streams.remove(&self.id);
    }
}

impl tokio::io::AsyncRead for WgTcpStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = &mut *self;
        loop {
            // Drain buffered chunks slice-wise: each chunk crosses into the
            // caller's buffer with one `put_slice`, not one `pop_front` per
            // byte (the old loop cost a call per byte — ~32M iterations for
            // a 32 MiB transfer).
            while buf.remaining() > 0 {
                let Some(front) = this.read_buf.front_mut() else {
                    break;
                };
                let n = front.len().min(buf.remaining());
                buf.put_slice(&front.split_to(n));
                if this.read_buf[0].is_empty() {
                    this.read_buf.pop_front();
                }
            }
            if !buf.filled().is_empty() {
                return std::task::Poll::Ready(Ok(()));
            }
            if this.eof {
                return std::task::Poll::Ready(Ok(()));
            }
            match this.rx.poll_recv(cx) {
                std::task::Poll::Ready(Some(StreamMsg::Data(data))) => {
                    if !data.is_empty() {
                        this.read_buf.push_back(data);
                    }
                }
                std::task::Poll::Ready(Some(StreamMsg::Fin)) | std::task::Poll::Ready(None) => {
                    this.eof = true;
                }
                std::task::Poll::Pending => return std::task::Poll::Pending,
            }
        }
    }
}

impl tokio::io::AsyncWrite for WgTcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        // Cap segment size so the outer datagram stays unfragmented
        // (see WRITE_SEGMENT).
        let n = buf.len().min(WRITE_SEGMENT);
        let this = self.get_mut();
        // The seq is committed ONLY on an accepted frame (finding 2): the
        // pre-fix code consumed a seq via `fetch_add` before `try_send_frame`
        // and, on egress backpressure, dropped the frame while keeping the
        // seq — a permanent hole the receiver's in-order cursor parked on
        // forever (no sender re-delivery exists at this layer). A
        // backpressured write parks its waker and retries the SAME seq, so
        // acceptance order equals seq order and the receiver never sees a
        // gap (the retried frame is byte-identical: id, seq, payload).
        let seq = this.write_seq.load(Ordering::Relaxed);
        let mut frame = Vec::with_capacity(9 + n);
        frame.push(DATA);
        frame.extend_from_slice(&this.id.to_be_bytes());
        frame.extend_from_slice(&seq.to_be_bytes());
        frame.extend_from_slice(&buf[..n]);
        match this.send.try_send_frame(frame) {
            Ok(()) => {
                // Commit: this seq is now in flight.
                this.write_seq.store(seq.wrapping_add(1), Ordering::Relaxed);
                std::task::Poll::Ready(Ok(n))
            }
            Err(e) if e.is_backpressure() => {
                // Park on queue space: exactly one waiter task per
                // `Pending` (created only on a full queue), woken when
                // `reserve` succeeds. The seq stays uncommitted until the
                // retry lands. No busy-spin, no silent drop, no
                // consumed-but-unsent seq.
                let waker = cx.waker().clone();
                let waiter = this.send.congestion_waiter();
                tokio::spawn(async move {
                    waiter.await;
                    waker.wake();
                });
                std::task::Poll::Pending
            }
            Err(e) => std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                e.to_string(),
            ))),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        match this.send.try_send_frame(fin_frame(this.id)) {
            Ok(()) => std::task::Poll::Ready(Ok(())),
            Err(e) if e.is_backpressure() => {
                let waker = cx.waker().clone();
                let waiter = this.send.congestion_waiter();
                tokio::spawn(async move {
                    waiter.await;
                    waker.wake();
                });
                std::task::Poll::Pending
            }
            Err(e) => std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                e.to_string(),
            ))),
        }
    }
}

impl ByteStream for WgTcpStream {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    struct StubSender;

    #[async_trait::async_trait]
    impl FrameSender for StubSender {
        async fn send_frame(&self, _frame: Vec<u8>) -> Result<(), HopError> {
            Ok(())
        }
        fn try_send_frame(&self, _frame: Vec<u8>) -> Result<(), HopError> {
            Ok(())
        }
        fn congestion_waiter(&self) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
            Box::pin(async {})
        }
    }

    fn data_frame(id: u32, seq: u32, payload: &[u8]) -> Vec<u8> {
        let mut f = Vec::with_capacity(9 + payload.len());
        f.push(DATA);
        f.extend_from_slice(&id.to_be_bytes());
        f.extend_from_slice(&seq.to_be_bytes());
        f.extend_from_slice(payload);
        f
    }

    /// Failing-first (#12 handoff): burst overflow on a bounded lane yields a
    /// counted `Congested` event — never unbounded growth. Pre-fix this
    /// failed: the lane was unbounded, so `stream_drops()` stayed 0 no
    /// matter the burst. Stall-model adaptation: the cursor no longer
    /// advances past a Full lane (loss stalls, never corrupts), so beyond
    /// the first Full drop the burst's later seqs hold their place in the
    /// bounded reorder window instead of serially dropping — exactly one
    /// drop is counted and the rest stall for re-delivery.
    #[tokio::test]
    async fn burst_overflow_yields_counted_congested_event() {
        let table = Arc::new(StreamTable::new());
        let (events, rx) = tokio::sync::broadcast::channel(4096);
        table.observe("wg-test-0".to_string(), events);
        let rx = rx;
        let mut rx = rx;
        let dst: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let send: SendFrame = Arc::new(StubSender);
        let stream = open_stream(&table, dst, send).await.expect("opens");
        // Pin the reader shut: never poll `stream`, so the lane must absorb
        // the whole burst or count the overflow.
        let id = stream.id;
        let _stream = stream; // held, never read
        let burst = STREAM_QUEUE_CAP + 76;
        for seq in 0..burst as u32 {
            dispatch(&table, data_frame(id, seq, b"x")).expect("dispatches");
        }
        assert_eq!(
            table.stream_drops(),
            1,
            "the Full seq is counted, the rest stall"
        );
        // The cursor is parked at the Full seq: re-delivering it after a
        // drain must queue — no seq was silently skipped.
        assert_eq!(
            table
                .inner
                .lock()
                .unwrap()
                .streams
                .get(&id)
                .expect("lane alive")
                .expect,
            STREAM_QUEUE_CAP as u32,
            "cursor stalls on the dropped seq, never advances past it"
        );
        // The last emission carries the cumulative total.
        let mut max_seen = 0u64;
        let mut seen_hop = String::new();
        loop {
            match rx.try_recv() {
                Ok(HopEvent::Congested { hop_id, dropped }) => {
                    max_seen = max_seen.max(dropped);
                    seen_hop = hop_id;
                }
                Ok(_) => {}
                Err(tokio::sync::broadcast::error::TryRecvError::Empty) => break,
                Err(tokio::sync::broadcast::error::TryRecvError::Lagged(_)) => continue,
                Err(tokio::sync::broadcast::error::TryRecvError::Closed) => break,
            }
        }
        assert_eq!(max_seen, 1, "cumulative total survives bus lag");
        assert_eq!(seen_hop, "wg-test-0");
    }

    fn open_frame(id: u32) -> Vec<u8> {
        let dst = "127.0.0.1:1";
        let mut f = Vec::with_capacity(6 + dst.len());
        f.push(OPEN);
        f.extend_from_slice(&id.to_be_bytes());
        f.push(dst.len() as u8);
        f.extend_from_slice(dst.as_bytes());
        f
    }

    /// Stall-model contract (stream.rs 15-17: loss stalls a stream, never
    /// silent corruption): a Full on the expected seq must NOT advance the
    /// cursor past it — pre-fix the cursor advanced before try_send, so a
    /// chunk dropped on Full let its successor deliver in its place and the
    /// reader saw a silent hole. Fill the lane to its last slot, hit Full on
    /// the next in-order chunk, drain one, then re-deliver: the reader must
    /// see the predecessor and then the re-delivered chunk — never a hole.
    #[tokio::test]
    async fn full_lane_stalls_cursor_no_hole() {
        use tokio::io::AsyncReadExt;
        let table = Arc::new(StreamTable::new());
        let dst: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let send: SendFrame = Arc::new(StubSender);
        let mut stream = open_stream(&table, dst, send).await.expect("opens");
        let id = stream.id;
        // Fill the lane to its bound: seqs 0..=cap-1 queue in order, cursor
        // ends at cap.
        for seq in 0..STREAM_QUEUE_CAP as u32 {
            dispatch(&table, data_frame(id, seq, b"x")).expect("dispatches");
        }
        // Next in-order chunk hits Full: dropped + counted, cursor stays.
        dispatch(&table, data_frame(id, STREAM_QUEUE_CAP as u32, b"late"))
            .expect("full lane drops, not errors");
        assert_eq!(table.stream_drops(), 1, "full is counted congestion");
        // Drain exactly one chunk so exactly one slot frees.
        let mut first = [0u8; 1];
        let n = stream.read(&mut first).await.expect("one chunk");
        assert_eq!(&first[..n], b"x", "first in-order chunk");
        // Stall model: the sender re-delivers the dropped seq once space
        // exists. It must queue (cursor had stayed on it) and flush the
        // buffered predecessors in order.
        dispatch(&table, data_frame(id, STREAM_QUEUE_CAP as u32, b"late"))
            .expect("re-delivery queues after drain");
        // Drain the rest byte-wise until the lane goes quiet: the tail must
        // be the last pre-drop in-order chunk then the re-delivery — N then
        // N+1, no hole.
        let mut got: Vec<u8> = Vec::new();
        let deadline = Duration::from_millis(300);
        loop {
            let mut chunk = [0u8; 1];
            match tokio::time::timeout(deadline, stream.read(&mut chunk)).await {
                Ok(Ok(1)) => got.push(chunk[0]),
                _ => break,
            }
        }
        assert!(
            got.len() >= 5 && &got[got.len() - 5..] == b"xlate",
            "tail is the cap-1 chunk then the re-delivered late chunk, no hole: {:?}",
            String::from_utf8_lossy(&got[got.len().saturating_sub(10)..])
        );
        assert_eq!(table.stream_drops(), 1, "re-delivery was not another drop");
    }

    #[test]
    fn stream_table_caps_concurrent_opens() {
        // Peer-space ids only (finding 3 parity): the default table is
        // initiator-side (odd space), so inbound OPENs must use even ids.
        let table = StreamTable::new();
        for i in 0..MAX_STREAMS as u32 {
            dispatch(&table, open_frame(i * 2)).expect("opens within cap");
        }
        assert_eq!(table.stream_drops(), 0);
        for i in 0..50u32 {
            let id = (MAX_STREAMS as u32 + i) * 2;
            dispatch(&table, open_frame(id)).expect("over-cap OPENs drop, not error");
        }
        assert_eq!(table.stream_drops(), 50, "flood beyond cap is counted");
        assert_eq!(
            table.inner.lock().unwrap().streams.len(),
            MAX_STREAMS,
            "table stays bounded"
        );
    }

    #[test]
    fn wrap_ip_round_trips_with_valid_checksum() {
        // #15 changed the constructor (extend, no pre-zeroing): pin the
        // exact wire layout — IPv4/253 envelope, correct total length and
        // header checksum — so the perf rewrite cannot rot the framing.
        let frame = b"\x02hello".to_vec();
        let pkt = wrap_ip(&frame);
        assert_eq!(pkt.len(), 20 + frame.len());
        assert_eq!(pkt[0], 0x45);
        assert_eq!(pkt[9], CHANNEL_IP_PROTO);
        assert_eq!(u16::from_be_bytes([pkt[2], pkt[3]]) as usize, pkt.len());
        let sum: u32 = pkt[..20]
            .chunks(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]) as u32)
            .sum();
        let mut sum = sum;
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        assert_eq!(sum as u16, 0xFFFF, "checksum validates");
        assert_eq!(unwrap_ip(&pkt), Some(frame.as_slice()));
    }

    /// Gate sender for the poll_write regression: refuses the FIRST
    /// DATA `try_send_frame` (once, via a swap gate — never again), then
    /// accepts everything. Records every accepted frame verbatim so the
    /// test can assert the receiver-visible seq sequence.
    struct CongestedOnceSender {
        refused: AtomicBool,
        accepted: Mutex<Vec<Vec<u8>>>,
    }

    impl CongestedOnceSender {
        fn new() -> Self {
            CongestedOnceSender {
                refused: AtomicBool::new(false),
                accepted: Mutex::new(Vec::new()),
            }
        }

        fn accepted_frames(&self) -> Vec<Vec<u8>> {
            self.accepted.lock().unwrap().clone()
        }

        fn accepted_data_frames(&self) -> Vec<Vec<u8>> {
            self.accepted_frames()
                .into_iter()
                .filter(|f| f.first() == Some(&DATA))
                .collect()
        }

        fn accepted_seqs(&self) -> Vec<u32> {
            self.accepted_data_frames()
                .iter()
                .map(|f| u32::from_be_bytes(f[5..9].try_into().expect("DATA header is 8 bytes")))
                .collect()
        }
    }

    #[async_trait::async_trait]
    impl FrameSender for CongestedOnceSender {
        async fn send_frame(&self, frame: Vec<u8>) -> Result<(), HopError> {
            self.try_send_frame(frame)
        }
        fn try_send_frame(&self, frame: Vec<u8>) -> Result<(), HopError> {
            // Refuse exactly the first DATA frame, then accept everything
            // (OPEN/FIN included). A swap gate, not arithmetic: the counter
            // must never wrap back into refusing.
            if frame.first() == Some(&DATA) && !self.refused.swap(true, Ordering::Relaxed) {
                return Err(HopError::overloaded("wg-test-0", "egress queue full"));
            }
            self.accepted.lock().unwrap().push(frame);
            Ok(())
        }
        fn congestion_waiter(&self) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
            Box::pin(async {})
        }
    }

    /// Finding 2 regression: a seq consumed before `try_send_frame` on egress
    /// backpressure dropped the frame but kept the seq — the receiver's
    /// in-order cursor parked on the hole forever (no sender re-delivery at
    /// this layer). The seq must be committed ONLY on an accepted frame, and
    /// the retried frame must be byte-identical (same seq, same payload).
    /// Pre-fix this failed: the refused first write consumed seq 0 and the
    /// retry sent seq 1, so the accepted DATA seqs ran [1, 2]; post-fix the
    /// retry reuses seq 0 and they run [0, 1] contiguous.
    #[tokio::test]
    async fn poll_write_backpressure_does_not_consume_seq() {
        use tokio::io::AsyncWriteExt;
        let table = Arc::new(StreamTable::new());
        let dst: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let sender = Arc::new(CongestedOnceSender::new());
        let send: SendFrame = sender.clone();
        let mut stream = open_stream(&table, dst, send).await.expect("opens");

        // First DATA write: refused with backpressure once, retried with the
        // SAME seq after the (immediate) congestion waiter, then accepted.
        stream
            .write_all(b"first")
            .await
            .expect("first write completes after the congestion waiter");
        // Second write: uncontended.
        stream
            .write_all(b"second")
            .await
            .expect("second write completes");
        let _ = stream; // FIN attempt rides the always-accepting sender

        let data_frames = sender.accepted_data_frames();
        assert_eq!(
            data_frames
                .iter()
                .map(|f| f[9..].to_vec())
                .collect::<Vec<_>>(),
            vec![b"first".to_vec(), b"second".to_vec()],
            "exactly the two DATA payloads were accepted, in order"
        );
        let seqs = sender.accepted_seqs();
        assert_eq!(seqs, vec![0, 1], "receiver sees contiguous seqs: {seqs:?}");
    }

    /// Finding 3: stream ids are split into disjoint parity spaces — the
    /// handshake initiator allocates odd ids, the responder even — so both
    /// ends can dial outward through one tunnel without collision. Asserts
    /// the allocator's parity per side and that locally allocated ids always
    /// stay in their own space.
    #[test]
    fn stream_ids_split_by_parity_per_side() {
        for side in [StreamSide::Initiator, StreamSide::Responder] {
            let table = StreamTable::new_with_side(side);
            let expected_parity = match side {
                StreamSide::Initiator => 1,
                StreamSide::Responder => 0,
            };
            for i in 0..100u32 {
                let id = fresh_id(&table);
                assert_eq!(
                    id & 1,
                    expected_parity,
                    "{side:?} allocates only its parity space (id {id}, i {i})"
                );
            }
        }
        // Wrapping preserves parity through the full u32 space (u32::MAX is
        // odd → next initiator id wraps to 1, still odd).
        let table = StreamTable::new_with_side(StreamSide::Initiator);
        table.next_id.store(u32::MAX - 2, Ordering::Relaxed);
        assert_eq!(fresh_id(&table), u32::MAX - 2);
        assert_eq!(fresh_id(&table), u32::MAX);
        assert_eq!(fresh_id(&table), 1, "wrap keeps the odd space");
    }

    /// Finding 3, inbound side: a remote OPEN naming a locally allocated id
    /// (our parity space) must NOT create a lane in our space — it is
    /// rejected and counted. Pre-fix a peer OPEN for an id we had not yet
    /// allocated created a squatter lane in the shared namespace, so our
    /// next `open_stream` allocation (same counter!) collided with it and
    /// the two logical streams cross-wired. With the parity split the
    /// guard is defense-in-depth: a well-behaved peer never OPENs in our
    /// space; a buggy one fails closed here instead of corrupting lanes.
    /// Also asserts the complementary space is accepted.
    #[tokio::test]
    async fn inbound_open_in_local_parity_space_is_rejected_and_counted() {
        // Default table = initiator side (odd local space).
        let table = Arc::new(StreamTable::new());
        let dst: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let send: SendFrame = Arc::new(StubSender);
        let stream = open_stream(&table, dst, send).await.expect("opens");
        assert_eq!(stream.id & 1, 1, "initiator allocates odd ids");
        let local_id = stream.id;

        // Peer OPEN in OUR space (odd, not yet allocated by us): rejected,
        // counted, and NO lane created — our space stays ours.
        let squatter = local_id + 2;
        dispatch(&table, open_frame(squatter)).expect("rejection is not an error");
        assert_eq!(
            table.rejected_opens(),
            1,
            "remote OPEN in our space is counted"
        );
        assert!(
            !table.inner.lock().unwrap().streams.contains_key(&squatter),
            "rejected OPEN must not create a lane in our space"
        );

        // Peer OPEN in the complementary (even) space: accepted normally.
        dispatch(&table, open_frame(local_id - 1)).expect("peer-space OPEN accepted");
        assert_eq!(
            table.rejected_opens(),
            1,
            "peer-space OPEN is not a rejection"
        );
        assert!(table
            .inner
            .lock()
            .unwrap()
            .streams
            .contains_key(&(local_id - 1)));

        // And our own allocation can never land on an even (peer) id that a
        // peer lane occupies: next fresh id keeps the odd parity.
        let next = fresh_id(&table);
        assert_eq!(next & 1, 1, "local allocation stays in the odd space");
        assert_ne!(next, local_id - 1, "never collides with a peer lane");
    }

    /// Finding 4: DATA beyond the reorder window (>1024 ahead of expect) can
    /// never be re-ordered into place (the cursor advances only via
    /// contiguous delivery) — it must be counted as congestion, not
    /// silently vanished. Pre-fix the drop was uncounted.
    #[tokio::test]
    async fn data_beyond_reorder_window_is_counted_as_drop() {
        let table = Arc::new(StreamTable::new());
        let dst: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let send: SendFrame = Arc::new(StubSender);
        let stream = open_stream(&table, dst, send).await.expect("opens");
        let id = stream.id;
        let _stream = stream; // lane held shut

        // Exactly one window ahead: buffered, not a drop.
        dispatch(&table, data_frame(id, REORDER_WINDOW - 1, b"edge")).expect("dispatches");
        assert_eq!(table.stream_drops(), 0, "last in-window seq is buffered");
        // One past the window: dropped and counted.
        dispatch(&table, data_frame(id, REORDER_WINDOW, b"too far")).expect("dispatches");
        assert_eq!(
            table.stream_drops(),
            1,
            "beyond-window DATA is counted congestion"
        );
        // The beyond-window chunk must not be buffered anywhere (only the
        // in-window 1023 sits in pending).
        let pending = table
            .inner
            .lock()
            .unwrap()
            .streams
            .get(&id)
            .expect("lane alive")
            .pending
            .clone();
        assert_eq!(
            pending.keys().copied().collect::<Vec<_>>(),
            vec![REORDER_WINDOW - 1],
            "only the in-window seq is pending; the beyond-window chunk left nothing"
        );
    }
}
