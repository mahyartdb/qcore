# T2: control-token-file

Scope: OS-RNG bearer token (128-bit hex, same length/location); constant-fold compare kept. Atomic temp+rename control.json with owner-only perms on Unix, best-effort note on Windows.

Accept:
- Token unique over large sample, no pid/nanos substring dependence on RandomState.
- Control file write atomic, 0600 on Unix (test-gated cfg(unix)).
- Blocking status/stop client paths unchanged in behavior.
