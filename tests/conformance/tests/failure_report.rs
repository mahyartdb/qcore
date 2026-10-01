//! US1 acceptance (T037): failure reports. An unreachable transport fails
//! closed with a report naming the failing layer + cause (SC-007); a
//! transport-or-hop failure maps to exit 3 and names hop + cause
//! (contracts/cli.md exit codes).

use qcore_core::api::{Engine, EngineConfig};
use qcore_core::chain::ExpandedHop;
use qcore_transport_api::{FailureLayer, FailureReport};

fn engine_in(dir: &std::path::Path) -> Engine {
    let _ = qcore_transports::linked_kinds();
    Engine::new(EngineConfig {
        dirs: qcore_core::config::profile_dir::ProfileDirs::resolve(Some(dir.to_path_buf()), None),
        ..Default::default()
    })
}

fn is_transport_layer(layer: &FailureLayer) -> bool {
    matches!(
        layer,
        FailureLayer::Transport | FailureLayer::Chain | FailureLayer::Sidecar
    )
}

#[tokio::test]
async fn unreachable_hop_reports_layer_and_cause() {
    let work = std::env::temp_dir().join(format!("qcore-failrep-{}", std::process::id()));
    let engine = engine_in(&work);
    // H2 to a closed loopback port fails fast (refusal) or via the 15 s
    // QUIC/connect timeouts (filtered hangs) — either way the transport is
    // unreachable and start fails closed without waiting out the session.
    let spec = Engine::parse_single_hop("masque", "alpn=h2 endpoint=127.0.0.1:1")
        .expect("unreachable spec parses");
    let report: FailureReport = engine
        .start(vec![ExpandedHop::Hop(spec)])
        .await
        .expect_err("unreachable transport must fail");

    // SC-007: names the failing layer + cause.
    assert!(
        is_transport_layer(&report.layer),
        "transport layer, got {:?}",
        report.layer
    );
    assert!(report.hop_id.contains("masque"), "names the hop: {report}");
    assert!(
        report.cause.contains("masque"),
        "names transport + actionable cause: {report}"
    );

    // Exit 3 for transport/hop failure, naming hop + cause.
    assert_eq!(
        qcore_core::session::report::exit_code_for_failure(&report),
        qcore_core::session::report::EXIT_HOP_FAILURE
    );
    let text = format!("{report}");
    assert!(text.contains(&report.hop_id), "display names hop");
    assert!(text.contains(&report.cause), "display names cause");

    // Fail closed: no session record left behind.
    assert!(
        !work.join("session.json").exists(),
        "failed start leaves zero state"
    );
    let _ = std::fs::remove_dir_all(&work);
}

#[test]
fn validation_failure_maps_to_exit_2() {
    let report = FailureReport::new(
        FailureLayer::Validation,
        "hop-0",
        "chain depth 4 exceeds max depth 3",
        "validation",
    );
    assert_eq!(
        qcore_core::session::report::exit_code_for_failure(&report),
        qcore_core::session::report::EXIT_INVALID
    );
}
