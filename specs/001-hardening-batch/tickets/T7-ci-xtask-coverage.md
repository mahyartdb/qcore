# T7: ci-xtask-coverage

Scope: Unify local release gate on workspace nextest. Fix nightly ignored-mode. Generate release matrix from targets manifest. Add Windows native gate leg. Fill relay conformance, empty Tor stub, import corpus, unique temp dirs, ephemeral closed ports, Go consumer CI-or-marked-untested.

Accept:
- `cargo xtask ci` and release gate use same workspace nextest lines.
- Nightly uses nextest ignored-mode.
- No hardcoded triple list drift; or documented stub.
- New/expanded tests green on Linux; Windows leg at least native subset.
