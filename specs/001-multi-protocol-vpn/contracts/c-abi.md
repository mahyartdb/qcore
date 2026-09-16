# Contract: C ABI

The `ffi` crate builds `cdylib` + `staticlib` with a `cbindgen`-generated header
(`qcore.h`) and JNI bindings for Android. This is how non-Rust hosts (Go via cgo,
Android apps via JNI) embed the engine (FR-003d).

## ABI rules

- Opaque handle types only; no Rust types across the boundary.
- All strings are UTF-8, length-prefixed or NUL-terminated as documented per call.
- Errors returned as an `int32` status code plus an out-param error struct; never
  panic across FFI (`catch_unwind` at each entry).
- Memory ownership is explicit: every allocation has a matching `qcore_*_free`.
- No secrets are ever written to caller buffers (FR-026).
- Windows MSVC 32-bit: audit FFI struct alignment for 64-bit fields.

## Versioning

- `qcore_abi_version()` returns the ABI version (FR-003f).
- ABI changes are semver; breaking changes bump the major and are documented.

## Functions (illustrative surface)

```
uint32_t qcore_abi_version(void);

QcoreEngine* qcore_engine_new(const QcoreConfig* cfg, QcoreError* err);
void         qcore_engine_free(QcoreEngine* engine);

int32_t qcore_engine_start(QcoreEngine* engine, const char* chain_spec, QcoreError* err);
int32_t qcore_engine_status_json(QcoreEngine* engine, char** out_json, QcoreError* err);
int32_t qcore_engine_stop(QcoreEngine* engine, QcoreError* err);

int32_t qcore_scan(QcoreEngine* engine, const char* kind, const char* profile,
                   char** out_json, QcoreError* err);
int32_t qcore_import_config(const char* path, char** out_json, QcoreError* err);
int32_t qcore_export_config(const char* import_ref, char** out_yaml, QcoreError* err);

void qcore_string_free(char* s);
void qcore_error_free(QcoreError* err);
```

## JSON boundary

Structured results (status, scan, import) cross as JSON strings matching the
`ConnectionReport`, `EndpointCandidate` list, and `ConfigImport` entities in
data-model.md. This keeps the ABI small and versionable.

## Guarantees

- Any capability in the public Rust API is reachable through the ABI
  (FR-003c/FR-003d).
- Android JNI wrappers call the same ABI; no Android-only code paths in the core.
- The ABI never blocks: long operations are cancellable or bounded.