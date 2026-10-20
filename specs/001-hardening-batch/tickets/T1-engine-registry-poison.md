# T1: engine-registry-poison

Scope: Engine live-session map must not panic on mutex poisoning. Clone handle out from under lock before building ConnectionReport.

Accept:
- Poisoned lock returns FailureReport / None, never panics, on start/session_report/stop_session/stop.
- `cargo nextest run --workspace --exclude tests-conformance` green.
- No public API break (signatures may gain Result only if already Result; otherwise restore-and-continue with logged restore).
