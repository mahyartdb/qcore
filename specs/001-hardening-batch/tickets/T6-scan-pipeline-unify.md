# T6: scan-pipeline-unify

Scope: Extract shared core scan-request pipeline (winner fast-path, seed expansion, verify, persist/evict) used by both CLI scan and FFI scan. Keep exit-4 empty contract and single-JSON stdout contract.

Accept:
- CLI and FFI scans populate/use winner cache identically on same inputs.
- Empty scan still code 4 with ranked JSON; no silent unverified reuse.
- Existing scan conformance green.
