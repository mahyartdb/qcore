//! Fake Psiphon sidecar for tests: real SOCKS5 server + readiness protocol.
//!
//! Protocol: on start bind 127.0.0.1:0, print
//! `QCORE_SIDECAR_READY socks5=ADDR` on stdout, read one secret line on
//! stdin, report `SECRET_LEN=n` on stderr, serve forever.
//! Flags: `--fail` (exit 1 immediately), `--no-ready` (hang, never ready),
//! `--report-stdin-len=<path>` (write the byte length of the stdin line read
//! to that file — lets supervisor tests prove the secret they configured
//! actually arrived on the sidecar's stdin without racing stderr).

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
    // Read one secret line on stdin (never argv) concurrently with serving:
    // blocking serve on stdin would deadlock supervisor spawns that send no
    // secret (stdin stays open, no EOF). The reader task reports SECRET_LEN.
    // `--report-stdin-len=<path>` switches the report to a file: the byte
    // length of everything read from stdin. `read_line` returns only after
    // the `\n` (the supervisor's last written byte), so the line length is
    // the total the supervisor delivered — one reader, no competing reads.
    let report_path = args
        .iter()
        .filter_map(|a| a.strip_prefix("--report-stdin-len="))
        .map(|s| s.to_string())
        .next();
    tokio::spawn(async move {
        let mut line = String::new();
        let mut stdin = tokio::io::BufReader::new(tokio::io::stdin());
        let read = stdin.read_line(&mut line).await;
        match report_path {
            Some(path) => {
                // Report the delivered byte count even when the read fails:
                // the file's presence proves stdin was wired at all.
                let n = read.unwrap_or(0);
                if let Err(e) = std::fs::write(&path, n.to_string()) {
                    eprintln!("STDIN_REPORT_WRITE_FAILED={e}");
                }
            }
            None => {
                if read.is_ok() && !line.is_empty() {
                    eprintln!("SECRET_LEN={}", line.trim_end().len());
                }
            }
        }
    });
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
