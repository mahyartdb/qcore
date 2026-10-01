//! Fake Psiphon sidecar for tests: real SOCKS5 server + readiness protocol.
//!
//! Protocol: on start bind 127.0.0.1:0, print
//! `QCORE_SIDECAR_READY socks5=ADDR` on stdout, read one secret line on
//! stdin, report `SECRET_LEN=n` on stderr, serve forever.
//! Flags: `--fail` (exit 1 immediately), `--no-ready` (hang, never ready).

use std::net::SocketAddr;
use tokio::io::AsyncBufReadExt;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--fail") {
        std::process::exit(1);
    }
    if args.iter().any(|a| a == "--no-ready") {
        // Hang without any output: exercises supervisor readiness timeouts.
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
        }
    }
    let server = qcore_transport_psiphon::socks::Socks5Server::bind("127.0.0.1:0".parse().unwrap())
        .await
        .expect("bind");
    let addr: SocketAddr = server.local_addr().expect("addr");
    println!("QCORE_SIDECAR_READY socks5={addr}");
    // Die-after mode must serve until death (not sleep-then-exit without
    // serving): restart tests dial the revived sidecar, which is only
    // meaningful if the dying generation served traffic while alive.
    let die_ms: Option<u64> = args
        .iter()
        .filter_map(|a| a.strip_prefix("--die-after-ms="))
        .filter_map(|ms| ms.parse().ok())
        .next();
    if let Some(ms) = die_ms {
        tokio::spawn(async move {
            server.serve().await.ok();
        });
        tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
        std::process::exit(0);
    }
    // Read one secret line on stdin (never argv) concurrently with serving:
    // blocking serve on stdin would deadlock supervisor spawns that send no
    // secret (stdin stays open, no EOF). The reader task reports SECRET_LEN.
    tokio::spawn(async move {
        let mut line = String::new();
        let mut stdin = tokio::io::BufReader::new(tokio::io::stdin());
        if stdin.read_line(&mut line).await.is_ok() && !line.is_empty() {
            eprintln!("SECRET_LEN={}", line.trim_end().len());
        }
    });
    server.serve().await.ok();
}
