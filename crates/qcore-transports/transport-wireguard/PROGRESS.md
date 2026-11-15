# FIX WAVE WG — progress

Task: fix 7 verified findings in transport-wireguard (lib.rs / stream.rs / modes.rs).

- [x] 1 (P0) drive `Tunn::update_timers` on pump tick + bring-up retry; honest `TunnResult::Err` handling
- [x] 2 (P1) `poll_write` seq committed only on accepted frame + regression test
- [x] 3 (P1) odd/even stream-id split + unit test
- [x] 4 (P2) count window-overflow DATA drops
- [x] 5 (P2) `QCORE_WG_TRACE` resolved once (OnceLock)
- [x] 6 (P2) bounded pump `send_to` (5 s timeout → Failed + clean stop)
- [x] 7 (P2) `resolve_fields` rejects port-0 literal endpoints
- [x] red→green proof for 1a, 1b, 2, 3, 4, 6, 7 (fix temporarily reverted, test observed red, fix restored)
- [x] nextest -p qcore-transport-wireguard: 32/32 green (29 lib + 3 wg_probe)
- [x] clippy -p qcore-transport-wireguard --all-targets -D warnings green
- [x] cargo fmt -p qcore-transport-wireguard --check clean
- [x] wg_probe loopback test green (8 MiB roundtrip, byte-exact echo asserted)
