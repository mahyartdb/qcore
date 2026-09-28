//! Embed-host example (T080, SC-002b): a Rust host drives a session using
//! only the public `qcore` facade types — start, subscribe to events, read
//! status, stop. Transport linkage is the host's one line
//! (`qcore_transports::linked_kinds()`); everything else is facade API.
//!
//! Runs offline against the mock transport (stub peer); no network, no
//! secrets, no config files beyond a temp dir.

use qcore::{api::EngineConfig, session::report::ConnectionReport, Engine, Preflight};

#[tokio::main]
async fn main() {
    // Optional `hold <secs>`: keep the session up that long (polling status
    // once per second) before stopping, so a sustained-session peak can be
    // sampled externally (see docs/perf-baselines.md). Default 0 preserves
    // the original start→status→stop lifecycle.
    let hold_secs: u64 = std::env::args()
        .nth(1)
        .and_then(|a| a.parse().ok())
        .unwrap_or(0);
    let work = std::env::temp_dir().join("qcore-embed-host");
    let _ = std::fs::remove_dir_all(&work);
    let dirs = qcore::config::profile_dir::ProfileDirs::resolve(
        Some(work.join("config")),
        Some(work.join("profiles")),
    );
    dirs.ensure_dirs().expect("dirs");

    // Host links the transports it embeds (mock here for an offline run).
    let _ = qcore_transports::linked_kinds();

    let engine = Engine::new(EngineConfig {
        dirs,
        ..Default::default()
    });
    let specs = engine.parse_chain("mock").expect("chain parses");

    // Preflight opens zero sockets; a rejection names the hop (exit 2).
    match engine.preflight(specs.clone()) {
        Preflight::Ok { depth } => eprintln!("preflight ok: depth {depth}"),
        Preflight::Rejected(e) => {
            eprintln!(
                "preflight rejected: {} ({})",
                e.hop_id.unwrap_or_default(),
                e.reason
            );
            std::process::exit(2);
        }
    }

    let mut events = engine.subscribe();
    let probe = tokio::spawn(async move {
        let mut seen = 0;
        while let Ok(ev) = events.recv().await {
            eprintln!("event: {ev:?}");
            seen += 1;
            if seen >= 2 {
                break;
            }
        }
    });

    let handle = engine.start(specs).await.expect("session starts");
    let report = ConnectionReport::new(handle.hop_reports(), handle.exit_hop_id.clone());
    assert_eq!(report.exit_hop_id, "mock-0");
    println!("{}", qcore::session::report::to_json(&report));

    let status = engine.status();
    eprintln!("status: {status:?}");

    for _ in 0..hold_secs {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        let _ = engine.status();
    }

    handle.stop_all().await.expect("session stops cleanly");
    let _ = probe.await;
    let _ = std::fs::remove_dir_all(&work);
    eprintln!("embed-host ok");
}
