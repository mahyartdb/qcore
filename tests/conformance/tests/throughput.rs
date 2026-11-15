//! Throughput benchmark harness (T094; plan Performance Goals).
//!
//! - Single-hop throughput within ~15% of the direct loopback baseline on
//!   x64 (median of 5 rounds, 32 MiB payload, offline loopback echo).
//! - Chain setup (3 layers) completes within the connection timeout with
//!   wide margin (no unbounded hops).
//!
//! This is a regression gate, not a NIC benchmark: both paths share the
//! loopback stack, so the ratio isolates engine overhead. Under parallel
//! CI load one median can jitter past the bar, so the ratio gate retries
//! once (best of two) instead of failing the suite on a noisy neighbor.
//!
//! The ratio test is `#[ignore]`d in the PR gate (ci.yml nextest skips
//! ignored tests by default): shared-runner jitter still produced flaky
//! red PRs, and it now runs on the nightly ignored-only lane instead
//! (nightly.yml `cargo nextest run --run-ignored ignored-only`, with
//! retries). The setup-budget test below stays in the PR path — it asserts
//! a wall-clock budget, not a machine-dependent ratio.

use qcore_core::api::{Engine, EngineConfig};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const PAYLOAD: usize = 32 * 1024 * 1024;
const ROUNDS: usize = 5;

async fn echo_server() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65536];
                loop {
                    let Ok(n) = sock.read(&mut buf).await else {
                        return;
                    };
                    if n == 0 {
                        return;
                    }
                    if sock.write_all(&buf[..n]).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    addr
}

fn engine() -> Engine {
    let _ = qcore_transports::linked_kinds();
    Engine::new(EngineConfig::default())
}

/// Move PAYLOAD bytes through `stream` (write all, read echo back).
async fn roundtrip<S>(stream: &mut S) -> Duration
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let chunk = vec![0xA5u8; 65536];
    let mut back = vec![0u8; 65536];
    let mut remaining = PAYLOAD;
    let t0 = Instant::now();
    while remaining > 0 {
        let n = remaining.min(chunk.len());
        stream.write_all(&chunk[..n]).await.expect("write");
        let mut got = 0;
        while got < n {
            let r = stream.read(&mut back[got..n]).await.expect("read");
            assert!(r > 0, "echo closed early");
            got += r;
        }
        remaining -= n;
    }
    t0.elapsed()
}

fn median(mut v: Vec<Duration>) -> Duration {
    v.sort();
    v[v.len() / 2]
}

// Nightly-only (nightly.yml runs `-p tests-conformance --run-ignored
// ignored-only`): ratio gates need stable load, which PR runners do not
// give. The in-test best-of-two retry was not enough under parallel CI
// load (flaky reds blocking unrelated PRs).
#[ignore = "nightly: throughput ratio is load-sensitive; runs on the nightly ignored-only lane (nightly.yml)"]
#[tokio::test]
async fn single_hop_throughput_within_15pct_of_direct() {
    // One retry (best of two): median jitter under parallel load is
    // environmental, not engine overhead — but two consecutive misses fail.
    let mut ratio = measure_ratio().await;
    if ratio < 0.85 {
        ratio = measure_ratio().await;
    }
    assert!(
        ratio >= 0.85,
        "single-hop throughput {ratio:.2}x of baseline (want >= 0.85, best of two)"
    );
}

async fn measure_ratio() -> f64 {
    let addr = echo_server().await;
    let e = engine();
    let specs = e.parse_chain("mock").expect("parses");
    let handle = e.start(specs).await.expect("starts");

    // Warmup (connection setup, allocator, scheduler) is discarded; timed
    // rounds interleave baseline/engine so both share load conditions.
    {
        let mut sock = tokio::net::TcpStream::connect(addr).await.expect("connect");
        roundtrip(&mut sock).await;
        let mut stream = handle.dialer().dial_tcp(addr).await.expect("exit egress");
        roundtrip(&mut stream).await;
    }
    let mut base = Vec::new();
    let mut engine_times = Vec::new();
    for _ in 0..ROUNDS {
        let mut sock = tokio::net::TcpStream::connect(addr).await.expect("connect");
        base.push(roundtrip(&mut sock).await);
        let mut stream = handle.dialer().dial_tcp(addr).await.expect("exit egress");
        engine_times.push(roundtrip(&mut stream).await);
    }
    handle.stop_all().await.expect("stops");

    let base_ms = median(base).as_secs_f64() * 1000.0;
    let engine_ms = median(engine_times).as_secs_f64() * 1000.0;
    let ratio = base_ms / engine_ms;
    let mib = PAYLOAD as f64 / 1048576.0;
    eprintln!(
        "throughput: direct {mib:.0}MiB in {base_ms:.0}ms, engine {engine_ms:.0}ms (ratio {ratio:.2})"
    );
    ratio
}

#[tokio::test]
async fn three_layer_chain_setup_within_timeout() {
    let e = engine();
    let specs = e.parse_chain("mock,relay,mock").expect("parses");
    let t0 = Instant::now();
    let handle = e.start(specs).await.expect("3-layer chain starts");
    let setup = t0.elapsed();
    eprintln!("chain setup (3 layers): {setup:?}");
    assert!(
        setup < Duration::from_secs(10),
        "chain setup {setup:?} exceeds 10s budget"
    );
    handle.stop_all().await.expect("stops");
}
