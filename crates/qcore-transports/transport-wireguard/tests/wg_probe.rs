//! WireGuard loopback bulk-transfer regression test.
//!
//! The conformance suite covers small-payload roundtrips; this exercises an
//! 8 MiB stream roundtrip plus handshake latency through a real boringtun
//! responder. Throughput and handshake figures print as informational
//! `PROBE` lines (hardware/profile/payload-dependent, never asserted);
//! correctness (byte-exact echo, no EOF) is asserted. Application turns are
//! fixed at 8K so bursts fit loopback socket buffers on a stall-on-loss v1
//! path — this measures sustainable throughput, not burst tolerance.
//!
//! Run with `--nocapture` to see the figures:
//! `cargo test -p qcore-transport-wireguard --release --test wg_probe --
//! --nocapture`.

use qcore_transport_api::{
    ByteStream, Capabilities, Dialer, HopConfig, HopError, HopFactory, UdpFlow,
};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct TcpWrap(tokio::net::TcpStream);
impl ByteStream for TcpWrap {}
impl tokio::io::AsyncRead for TcpWrap {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}
impl tokio::io::AsyncWrite for TcpWrap {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

struct UdpWrap(tokio::net::UdpSocket);
#[async_trait::async_trait]
impl UdpFlow for UdpWrap {
    async fn send_to(&self, buf: &[u8], dst: SocketAddr) -> Result<(), HopError> {
        self.0
            .send_to(buf, dst)
            .await
            .map(|_| ())
            .map_err(HopError::from)
    }
    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), HopError> {
        self.0.recv_from(buf).await.map_err(HopError::from)
    }
    fn local_addr(&self) -> Result<SocketAddr, HopError> {
        self.0.local_addr().map_err(HopError::from)
    }
}

struct Direct;
#[async_trait::async_trait]
impl Dialer for Direct {
    async fn dial_tcp(&self, dst: SocketAddr) -> Result<Box<dyn ByteStream>, HopError> {
        let s = tokio::net::TcpStream::connect(dst)
            .await
            .map_err(HopError::from)?;
        Ok(Box::new(TcpWrap(s)))
    }
    async fn dial_udp(&self, _dst: SocketAddr) -> Result<Box<dyn UdpFlow>, HopError> {
        let s = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .map_err(HopError::from)?;
        Ok(Box::new(UdpWrap(s)))
    }
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            accepts_tcp_carrier: true,
            accepts_udp_carrier: true,
            dials_tcp: true,
            dials_udp: true,
        }
    }
}

fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[tokio::test]
async fn wg_loopback_throughput_and_handshake() {
    let (c_sk, c_pk) = qcore_transport_wireguard::test_support::generate_keypair();
    let (s_sk, s_pk) = qcore_transport_wireguard::test_support::generate_keypair();
    let responder = qcore_transport_wireguard::test_support::WgResponder::spawn(
        "127.0.0.1".parse().unwrap(),
        s_sk,
        c_pk,
    )
    .await
    .unwrap();

    let mut cfg = HopConfig::new("wireguard");
    cfg.fields.insert("hop_id".into(), "wg-probe-0".into());
    cfg.fields.insert("peer".into(), "warp".into());
    cfg.fields
        .insert("endpoint".into(), responder.addr.to_string());
    cfg.fields.insert("private_key".into(), hex(&c_sk));
    cfg.fields.insert("peer_public_key".into(), hex(&s_pk));

    let t0 = Instant::now();
    let hop = qcore_transport_wireguard::WireguardFactory
        .build(cfg, Arc::new(Direct))
        .await
        .expect("handshake");
    let handshake = t0.elapsed();
    eprintln!("PROBE handshake: {handshake:?}");

    let mut stream = hop.dialer().dial_tcp(responder.addr).await.expect("dial");
    const TOTAL: usize = 8 * 1024 * 1024;
    // Fixed 8K application turns at both segment sizes: 6-frame bursts at
    // 1400 (ladder-proven to fit loopback socket buffers), 1 frame at
    // 8192. Identical app behavior — only the segment size differs.
    const TURN: usize = 8192;
    let chunk = vec![0xA5u8; TURN];
    let mut back = vec![0u8; TURN];
    // Warmup ladder (burst sizes known to fit loopback socket buffers;
    // a full 64K unpaced burst stalls a stall-on-loss v1 path — by design,
    // not by defect — so the bulk measurement below paces one segment
    // per turn instead). Reuses the bulk buffers; every turn is
    // content-checked, not just counted.
    for &size in &[8usize, 1024, 8192] {
        stream.write_all(&chunk[..size]).await.unwrap();
        let mut got = 0;
        while got < size {
            let r = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                stream.read(&mut back[got..size]),
            )
            .await
            .expect("read timeout")
            .unwrap();
            assert!(r > 0, "eof at size {size}");
            got += r;
        }
        assert_eq!(
            &back[..size],
            &chunk[..size],
            "echo mismatch at size {size}"
        );
        eprintln!("PROBE size {size} ok");
    }
    let t0 = Instant::now();
    let mut remaining = TOTAL;
    while remaining > 0 {
        let n = remaining.min(chunk.len());
        stream.write_all(&chunk[..n]).await.unwrap();
        let mut got = 0;
        while got < n {
            let r = tokio::time::timeout(
                std::time::Duration::from_secs(30),
                stream.read(&mut back[got..n]),
            )
            .await
            .expect("bulk read timeout")
            .unwrap();
            assert!(r > 0, "eof in bulk transfer");
            got += r;
        }
        assert_eq!(&back[..n], &chunk[..n], "bulk echo mismatch");
        remaining -= n;
    }
    let dt = t0.elapsed();
    let mbs = TOTAL as f64 / 1048576.0 / dt.as_secs_f64();
    eprintln!("PROBE roundtrip {TOTAL} bytes in {dt:?} = {mbs:.1} MiB/s");
    hop.stop().await.unwrap();
}

/// Counting sink: receives datagrams addressed to it and counts every byte
/// arrival (any packet — handshake retransmits, junk, anything).
struct CountingSink {
    pub arrivals: Arc<AtomicU32>,
    addr: SocketAddr,
    _task: tokio::task::JoinHandle<()>,
}

impl Drop for CountingSink {
    fn drop(&mut self) {
        self._task.abort();
    }
}

impl CountingSink {
    /// Bind a socket that never responds, counting received datagrams.
    async fn spawn() -> std::io::Result<Self> {
        let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        let addr = udp.local_addr()?;
        let arrivals = Arc::new(AtomicU32::new(0));
        let counter = arrivals.clone();
        let task = tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            while let Ok((_, _)) = udp.recv_from(&mut buf).await {
                counter.fetch_add(1, Ordering::Relaxed);
            }
        });
        Ok(CountingSink {
            arrivals,
            addr,
            _task: task,
        })
    }
}

/// Carrier for a direct (OS-socket) bring-up: dials nothing, so the hop
/// keeps its own OS UDP socket keyed to the dead endpoint.
struct DeadPeerDirect;

#[async_trait::async_trait]
impl Dialer for DeadPeerDirect {
    async fn dial_tcp(&self, _dst: SocketAddr) -> Result<Box<dyn ByteStream>, HopError> {
        Err(HopError::transport("test-carrier", "no tcp in this probe"))
    }

    async fn dial_udp(&self, _dst: SocketAddr) -> Result<Box<dyn UdpFlow>, HopError> {
        Err(HopError::transport("test-carrier", "no udp in this probe"))
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            accepts_tcp_carrier: true,
            accepts_udp_carrier: true,
            dials_tcp: true,
            dials_udp: true,
        }
    }

    fn nested_mtu(&self) -> Option<u16> {
        None
    }
}

/// Cancellation-safety contract (transport-api HopFactory): the engine
/// races `build` with a timeout and DROPS the future. A dropped bring-up
/// must leave no pump alive — no eternal retransmit loop, no orphaned
/// socket. Pre-fix the spawned pump detached holding Arc<HopInner> + its
/// own tx: the egress channel never closed and every 100 ms tick sent a
/// handshake initiation to the peer FOREVER (one orphaned socket + one
/// eternal task per timed-out dial, unbounded accumulation).
#[tokio::test]
async fn dropped_bring_up_future_leaves_no_pump_alive() {
    let sink = CountingSink::spawn().await.expect("dead-peer sink binds");
    let before = sink.arrivals.load(Ordering::Relaxed);

    let (c_sk, _c_pk) = qcore_transport_wireguard::test_support::generate_keypair();
    let (_s_sk, s_pk) = qcore_transport_wireguard::test_support::generate_keypair();
    let mut cfg = HopConfig::new("wireguard");
    cfg.fields.insert("hop_id".into(), "wg-cancel-0".into());
    cfg.fields.insert("peer".into(), "warp".into());
    cfg.fields.insert("endpoint".into(), sink.addr.to_string());
    cfg.fields.insert("private_key".into(), hex(&c_sk));
    cfg.fields.insert("peer_public_key".into(), hex(&s_pk));

    // Start bring-up against the never-responding peer, then cancel it
    // mid-handshake by dropping the polled future (spawn + abort = exactly
    // the engine's timeout race, which drops the future mid-await).
    let build = tokio::spawn(
        qcore_transport_wireguard::WireguardFactory.build(cfg, Arc::new(DeadPeerDirect)),
    );
    // Let the pump spawn and send at least one initiation.
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert!(
        sink.arrivals.load(Ordering::Relaxed) > before,
        "bring-up started transmitting (probe sanity)"
    );
    build.abort();
    let _ = build.await;

    // The guard must have aborted the pump; the Weak must starve any
    // residual iteration. Over a window covering several 100 ms retransmit
    // ticks, NOTHING further may arrive at the peer.
    let settled = sink.arrivals.load(Ordering::Relaxed);
    tokio::time::sleep(Duration::from_millis(700)).await;
    let after = sink.arrivals.load(Ordering::Relaxed);
    assert_eq!(
        after, settled,
        "no handshake retransmits after the build future dropped (pump must be dead)"
    );
}

/// Same contract on the engine-shaped path: racing build with a timeout and
/// dropping it (tokio::time::timeout cancel) must not leak a pump either.
#[tokio::test]
async fn timed_out_bring_up_leaves_no_pump_alive() {
    let sink = CountingSink::spawn().await.expect("dead-peer sink binds");
    let before = sink.arrivals.load(Ordering::Relaxed);

    let (c_sk, _c_pk) = qcore_transport_wireguard::test_support::generate_keypair();
    let (_s_sk, s_pk) = qcore_transport_wireguard::test_support::generate_keypair();
    let mut cfg = HopConfig::new("wireguard");
    cfg.fields.insert("hop_id".into(), "wg-cancel-1".into());
    cfg.fields.insert("peer".into(), "warp".into());
    cfg.fields.insert("endpoint".into(), sink.addr.to_string());
    cfg.fields.insert("private_key".into(), hex(&c_sk));
    cfg.fields.insert("peer_public_key".into(), hex(&s_pk));

    let _result: Result<std::sync::Arc<dyn qcore_transport_api::RunningHop>, HopError> =
        tokio::time::timeout(
            Duration::from_millis(300),
            qcore_transport_wireguard::WireguardFactory.build(cfg, Arc::new(DeadPeerDirect)),
        )
        .await
        .unwrap_or(Err(HopError::transport("probe", "cancelled")));

    let settled = sink.arrivals.load(Ordering::Relaxed);
    assert!(
        settled > before,
        "bring-up transmitted while alive (probe sanity)"
    );
    tokio::time::sleep(Duration::from_millis(700)).await;
    assert_eq!(
        sink.arrivals.load(Ordering::Relaxed),
        settled,
        "no retransmits after the raced build future dropped (pump must be dead)"
    );
}
