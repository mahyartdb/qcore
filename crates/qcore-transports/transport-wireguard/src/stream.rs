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
    Data(Vec<u8>),
    Fin,
}

struct StreamEntry {
    tx: tokio::sync::mpsc::Sender<StreamMsg>,
    /// Next sequence number the reader expects.
    expect: u32,
    pending: BTreeMap<u32, Vec<u8>>,
}

/// Demultiplexing table shared by one hop.
pub struct StreamTable {
    inner: Mutex<TableInner>,
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
}

struct TableInner {
    streams: HashMap<u32, StreamEntry>,
}

impl StreamTable {
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
pub fn dispatch(table: &StreamTable, frame: &[u8]) -> Result<(), String> {
    if frame.is_empty() {
        return Ok(());
    }
    match frame[0] {
        OPEN => {
            let (id, _dst) = parse_open(&frame[1..])?;
            let mut t = table.inner.lock().unwrap();
            t.streams.entry(id).or_insert_with(|| {
                let (tx, _) = tokio::sync::mpsc::channel(STREAM_QUEUE_CAP);
                StreamEntry {
                    tx,
                    expect: 0,
                    pending: BTreeMap::new(),
                }
            });
            Ok(())
        }
        DATA => {
            if frame.len() < 9 {
                return Ok(());
            }
            // Guarded by the `frame.len() < 9` early return above.
            let id = u32::from_be_bytes(frame[1..5].try_into().expect("DATA header is 8 bytes"));
            let seq = u32::from_be_bytes(frame[5..9].try_into().expect("DATA header is 8 bytes"));
            let payload = frame[9..].to_vec();
            // Bounded lane: the queue step cannot block (sync path, table
            // lock held), so a full lane drops and counts — never unbounded
            // growth, never a stall. A closed lane (reader gone) drops
            // silently as before: only `Full` is congestion. Emission
            // happens after the lock drops.
            let mut dropped = 0u64;
            {
                let mut t = table.inner.lock().unwrap();
                let Some(entry) = t.streams.get_mut(&id) else {
                    return Ok(());
                };
                // In-order delivery with reorder buffer.
                if seq == entry.expect {
                    entry.expect = entry.expect.wrapping_add(1);
                    if matches!(
                        entry.tx.try_send(StreamMsg::Data(payload)),
                        Err(tokio::sync::mpsc::error::TrySendError::Full(_))
                    ) {
                        dropped += 1;
                    }
                    while let Some(next) = entry.pending.remove(&entry.expect) {
                        entry.expect = entry.expect.wrapping_add(1);
                        match entry.tx.try_send(StreamMsg::Data(next)) {
                            Ok(()) => {}
                            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                                dropped += 1;
                                break;
                            }
                            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => break,
                        }
                    }
                } else if seq.wrapping_sub(entry.expect) < 1024 {
                    entry.pending.entry(seq).or_insert(payload);
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

fn parse_open(mut b: &[u8]) -> Result<(u32, SocketAddr), String> {
    if b.len() < 5 {
        return Err("short OPEN".into());
    }
    // Guarded by the `b.len() < 5` check above: at least 4 id bytes.
    let id = u32::from_be_bytes(b[..4].try_into().expect("OPEN id is 4 bytes"));
    let len = b[4] as usize;
    b = &b[5..];
    if b.len() < len {
        return Err("short OPEN dst".into());
    }
    let dst: SocketAddr = std::str::from_utf8(&b[..len])
        .map_err(|e| e.to_string())?
        .parse()
        .map_err(|e: std::net::AddrParseError| e.to_string())?;
    Ok((id, dst))
}

fn parse_dgram(mut b: &[u8]) -> Result<(SocketAddr, Vec<u8>), String> {
    if b.is_empty() {
        return Err("short DGRAM".into());
    }
    let len = b[0] as usize;
    b = &b[1..];
    if b.len() < len {
        return Err("short DGRAM dst".into());
    }
    let dst: SocketAddr = std::str::from_utf8(&b[..len])
        .map_err(|e| e.to_string())?
        .parse()
        .map_err(|e: std::net::AddrParseError| e.to_string())?;
    Ok((dst, b[len..].to_vec()))
}

/// Open an outbound stream to `dst`. Sends OPEN, returns the stream handle.
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
    table.next_id.fetch_add(1, Ordering::SeqCst)
}

/// Encode one UDP datagram for `dst`.
pub fn encode_dgram(dst: &SocketAddr, payload: &[u8]) -> Vec<u8> {
    let dst_s = dst.to_string();
    let mut frame = Vec::with_capacity(1 + 1 + dst_s.len() + payload.len());
    frame.push(DGRAM);
    frame.push(dst_s.len() as u8);
    frame.extend_from_slice(dst_s.as_bytes());
    frame.extend_from_slice(payload);
    frame
}

/// A TCP-like byte stream over the tunnel channel.
pub struct WgTcpStream {
    id: u32,
    table: Arc<StreamTable>,
    rx: tokio::sync::mpsc::Receiver<StreamMsg>,
    send: SendFrame,
    read_buf: VecDeque<u8>,
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
            while let Some(b) = this.read_buf.pop_front() {
                if buf.remaining() == 0 {
                    return std::task::Poll::Ready(Ok(()));
                }
                buf.put_slice(&[b]);
            }
            if !buf.filled().is_empty() {
                return std::task::Poll::Ready(Ok(()));
            }
            if this.eof {
                return std::task::Poll::Ready(Ok(()));
            }
            match this.rx.poll_recv(cx) {
                std::task::Poll::Ready(Some(StreamMsg::Data(data))) => {
                    this.read_buf.extend(data);
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
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        // Cap segment size to stay well under tunnel MTU.
        let n = buf.len().min(8192);
        let this = self.get_mut();
        let seq = this.write_seq.fetch_add(1, Ordering::SeqCst);
        let mut frame = Vec::with_capacity(9 + n);
        frame.push(DATA);
        frame.extend_from_slice(&this.id.to_be_bytes());
        frame.extend_from_slice(&seq.to_be_bytes());
        frame.extend_from_slice(&buf[..n]);
        match this.send.try_send_frame(frame) {
            Ok(()) => std::task::Poll::Ready(Ok(n)),
            Err(e) if e.is_backpressure() => {
                // Park on queue space: exactly one waiter task per
                // `Pending` (created only on a full queue), woken when
                // `reserve` succeeds. No busy-spin, no silent drop.
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
    /// matter the burst.
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
            dispatch(&table, &data_frame(id, seq, b"x")).expect("dispatches");
        }
        assert_eq!(table.stream_drops(), 76, "overflow is counted, not grown");
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
        assert_eq!(max_seen, 76, "cumulative total survives bus lag");
        assert_eq!(seen_hop, "wg-test-0");
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
}
