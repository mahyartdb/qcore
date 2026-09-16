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

use qcore_transport_api::ByteStream;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::{
    atomic::{AtomicU32, Ordering},
    Arc, Mutex,
};

const OPEN: u8 = 0x01;
const DATA: u8 = 0x02;
const FIN: u8 = 0x03;
const DGRAM: u8 = 0x04;

/// IP protocol number carrying tunnel-channel frames (RFC 3692 experimental).
pub const CHANNEL_IP_PROTO: u8 = 253;

/// Wrap a channel frame in a minimal IPv4 packet for the tunnel.
pub fn wrap_ip(frame: &[u8]) -> Vec<u8> {
    let total = (20 + frame.len()) as u16;
    let mut pkt = vec![0u8; 20 + frame.len()];
    pkt[0] = 0x45; // version 4, IHL 5
    pkt[2..4].copy_from_slice(&total.to_be_bytes());
    pkt[8] = 64; // TTL
    pkt[9] = CHANNEL_IP_PROTO;
    pkt[12..16].copy_from_slice(&[10, 0, 0, 2]); // src (cosmetic pre-TUN)
    pkt[16..20].copy_from_slice(&[10, 0, 0, 1]); // dst (cosmetic pre-TUN)
                                                 // Header checksum.
    let sum: u32 = pkt[..20]
        .chunks(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]) as u32)
        .sum();
    let mut sum = sum;
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    pkt[10..12].copy_from_slice(&(!sum as u16).to_be_bytes());
    pkt[20..].copy_from_slice(frame);
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
pub type SendFrame = Arc<dyn Fn(&[u8]) -> Result<(), qcore_transport_api::HopError> + Send + Sync>;

enum StreamMsg {
    Data(Vec<u8>),
    Fin,
}

struct StreamEntry {
    tx: tokio::sync::mpsc::UnboundedSender<StreamMsg>,
    /// Next sequence number the reader expects.
    expect: u32,
    pending: BTreeMap<u32, Vec<u8>>,
}

/// Demultiplexing table shared by one hop.
pub struct StreamTable {
    inner: Mutex<TableInner>,
    next_id: AtomicU32,
    dgrams: tokio::sync::broadcast::Sender<(Vec<u8>, SocketAddr)>,
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
        }
    }

    pub fn subscribe_dgrams(&self) -> tokio::sync::broadcast::Receiver<(Vec<u8>, SocketAddr)> {
        self.dgrams.subscribe()
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
                let (tx, _) = tokio::sync::mpsc::unbounded_channel();
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
            let id = u32::from_be_bytes(frame[1..5].try_into().unwrap());
            let seq = u32::from_be_bytes(frame[5..9].try_into().unwrap());
            let payload = frame[9..].to_vec();
            let mut t = table.inner.lock().unwrap();
            let Some(entry) = t.streams.get_mut(&id) else {
                return Ok(());
            };
            // In-order delivery with reorder buffer.
            if seq == entry.expect {
                entry.expect = entry.expect.wrapping_add(1);
                let _ = entry.tx.send(StreamMsg::Data(payload));
                while let Some(next) = entry.pending.remove(&entry.expect) {
                    entry.expect = entry.expect.wrapping_add(1);
                    if entry.tx.send(StreamMsg::Data(next)).is_err() {
                        break;
                    }
                }
            } else if seq.wrapping_sub(entry.expect) < 1024 {
                entry.pending.entry(seq).or_insert(payload);
            }
            Ok(())
        }
        FIN => {
            if frame.len() < 5 {
                return Ok(());
            }
            let id = u32::from_be_bytes(frame[1..5].try_into().unwrap());
            let mut t = table.inner.lock().unwrap();
            if let Some(entry) = t.streams.remove(&id) {
                let _ = entry.tx.send(StreamMsg::Fin);
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
    let id = u32::from_be_bytes(b[..4].try_into().unwrap());
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
    send(&frame).map_err(|e| e.to_string())?;
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
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
    rx: tokio::sync::mpsc::UnboundedReceiver<StreamMsg>,
    send: SendFrame,
    read_buf: VecDeque<u8>,
    eof: bool,
    write_seq: AtomicU32,
}

impl Drop for WgTcpStream {
    fn drop(&mut self) {
        let mut frame = [0u8; 5];
        frame[0] = FIN;
        frame[1..5].copy_from_slice(&self.id.to_be_bytes());
        let _ = (self.send)(&frame);
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
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        // Cap segment size to stay well under tunnel MTU.
        let n = buf.len().min(8192);
        let seq = self.write_seq.fetch_add(1, Ordering::SeqCst);
        let mut frame = Vec::with_capacity(9 + n);
        frame.push(DATA);
        frame.extend_from_slice(&self.id.to_be_bytes());
        frame.extend_from_slice(&seq.to_be_bytes());
        frame.extend_from_slice(&buf[..n]);
        match (self.send)(&frame) {
            Ok(()) => std::task::Poll::Ready(Ok(n)),
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
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let mut frame = [0u8; 5];
        frame[0] = FIN;
        frame[1..5].copy_from_slice(&self.id.to_be_bytes());
        let _ = (self.send)(&frame);
        std::task::Poll::Ready(Ok(()))
    }
}

impl ByteStream for WgTcpStream {}
