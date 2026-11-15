//! C ABI surface (T075, FR-003c/FR-003d): every engine capability reachable
//! from C through opaque handles, UTF-8 strings, int32 status codes and
//! JSON documents matching `ConnectionReport` / `ScanReport` / import refs.
//!
//! Rules: `catch_unwind` at each entry (Rust panics never cross the ABI);
//! strings are NUL-terminated UTF-8 owned by the callee and freed with
//! [`qcore_string_free`]; errors travel as an out-param [`QcoreError`]
//! freed with [`qcore_error_free`]; calls never block longer than the
//! engine's own bounded budgets (connection timeout / scan RTT budget).
//! Secrets are never written to caller buffers (FR-026): export goes
//! through the redacted form, reports are secret-free by construction.
//!
//! Handle lifetime: the registry owns one strong reference (`Arc`) per
//! live engine; every entry point acquires a clone of that reference under
//! the registry lock (the lock is never held across the call) and runs on
//! it. A freed engine is removed from the registry; in-flight calls on
//! other threads finish on the last strong reference before the engine
//! drops. Forged/double-free handles remain a usage error (6).

use qcore_core::api::{Engine, EngineConfig};
use qcore_core::config::profile_dir::ProfileDirs;
use qcore_transport_api::FailureLayer;
use std::ffi::{c_char, c_int, CStr, CString};
use std::time::Duration;

/// Opaque engine handle (see [`qcore_engine_new`]).
pub struct QcoreEngine {
    engine: Engine,
    rt: tokio::runtime::Runtime,
    timeout: Duration,
}

/// Out-param error record. `code` mirrors the CLI exit-code contract
/// (0 ok, 1 dead session, 2 invalid, 3 hop failure, 4 empty scan,
/// 5 import rejected, 6 usage, 10 no session, 12 unverifiable,
/// -1 internal); `message` is an owned NUL-terminated string.
#[repr(C)]
pub struct QcoreError {
    pub code: c_int,
    pub message: *mut c_char,
}

/// ABI version (matches `Engine::versions`, surfaced independently).
///
/// # Safety
/// Pure function; always safe to call.
#[no_mangle]
pub unsafe extern "C" fn qcore_abi_version() -> u32 {
    qcore_core::api::version::ABI_VERSION
}

fn ok_string(out: *mut *mut c_char, s: String, err_out: *mut *mut QcoreError) -> c_int {
    if out.is_null() {
        return fail(err_out, 6, "null out-param".to_string());
    }
    match CString::new(s) {
        Ok(c) => {
            // SAFETY: `out` is non-null (checked above) and points to a
            // writable caller pointer per the out-param contract.
            *unsafe { &mut *out } = c.into_raw();
            0
        }
        Err(_) => {
            // Interior NUL in JSON/ids is unexpected but must never yield a
            // code with no message: populate the error out-param.
            fail(
                err_out,
                -1,
                "response contains an interior NUL byte".to_string(),
            )
        }
    }
}

fn fail(err_out: *mut *mut QcoreError, code: c_int, message: String) -> c_int {
    if !err_out.is_null() {
        let message = CString::new(message).unwrap_or_else(|_| {
            CString::new("error").expect("static fallback literal has no interior NUL")
        });
        let err = Box::new(QcoreError {
            code,
            message: message.into_raw(),
        });
        *unsafe { &mut *err_out } = Box::into_raw(err);
    }
    code
}

/// Map a typed failure to its exit-code class. Single source with core
/// `exit_code_for_failure`: the typed [`FailureLayer`] drives the mapping
/// (validation 2, scan-empty 4, everything else hop-failure 3); the free-form
/// `kind` string is only a fallback for classes with no layer variant
/// (a `usage` kind), so message rewording cannot silently remap classes.
fn failure_code(r: &qcore_transport_api::FailureReport) -> c_int {
    match r.layer {
        FailureLayer::Validation => 2,
        FailureLayer::Scan => 4,
        FailureLayer::Transport
        | FailureLayer::Chain
        | FailureLayer::Config
        | FailureLayer::Sidecar => {
            if r.kind == "usage" {
                6
            } else {
                3
            }
        }
    }
}

fn fail_report(err_out: *mut *mut QcoreError, r: &qcore_transport_api::FailureReport) -> c_int {
    // Typed-layer mapping; the kind string is fallback-only (see
    // `failure_code`).
    let code = failure_code(r);
    // Shared masked rendering: this message crosses into caller-owned
    // buffers, which promise (module docs, FR-026) to never carry secrets.
    let message = qcore_core::diag::masked_failure_line(r);
    fail(err_out, code, message)
}

fn unwind_guard<F: FnOnce() -> c_int + std::panic::UnwindSafe>(f: F) -> c_int {
    std::panic::catch_unwind(f).unwrap_or(-1)
}

static LIVE_HANDLES: std::sync::OnceLock<
    std::sync::Mutex<std::collections::HashMap<usize, std::sync::Arc<QcoreEngine>>>,
> = std::sync::OnceLock::new();

fn live_handles(
) -> &'static std::sync::Mutex<std::collections::HashMap<usize, std::sync::Arc<QcoreEngine>>> {
    LIVE_HANDLES.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

/// Poison-tolerant guard for the live-handle set: a poisoned mutex is
/// restored (contents preserved) and the restore is logged, so a poisoned
/// set never silently drops a track/lookup/remove into a false answer.
fn lock_live_handles(
) -> std::sync::MutexGuard<'static, std::collections::HashMap<usize, std::sync::Arc<QcoreEngine>>> {
    live_handles().lock().unwrap_or_else(|e| {
        eprintln!("qcore: live handle set lock poisoned; restoring");
        e.into_inner()
    })
}

/// Register a freshly created engine: the registry takes one strong
/// reference and the handle (the `Arc` pointer, stable for the engine's
/// lifetime) maps to it. The handle stays an opaque pointer for callers —
/// ABI-identical to the former boxed-pointer representation.
fn track_handle(engine: std::sync::Arc<QcoreEngine>) -> *mut QcoreEngine {
    let handle = std::sync::Arc::as_ptr(&engine) as *mut QcoreEngine;
    lock_live_handles().insert(handle as usize, engine);
    handle
}

/// Acquire a strong reference for a live handle, or `None` when the handle
/// is null/forged/already freed. The clone is taken under the registry lock
/// and the lock is released before the caller uses the engine, so a
/// concurrent free can never race the dereference: worst case the acquire
/// sees the entry already removed and fails closed.
pub(crate) fn acquire_engine(handle: *mut QcoreEngine) -> Option<std::sync::Arc<QcoreEngine>> {
    if handle.is_null() {
        return None;
    }
    lock_live_handles().get(&(handle as usize)).cloned()
}

/// Removes from the live set and returns the registry's strong reference;
/// `None` when the handle was not live (forged or already freed). The
/// engine memory itself lives until the last in-flight reference drops.
fn untrack_handle(ptr: *mut QcoreEngine) -> Option<std::sync::Arc<QcoreEngine>> {
    lock_live_handles().remove(&(ptr as usize))
}

fn check_handle(
    handle: *mut QcoreEngine,
    err_out: *mut *mut QcoreError,
) -> Result<std::sync::Arc<QcoreEngine>, c_int> {
    if handle.is_null() {
        return Err(fail(err_out, 6, "null engine handle".to_string()));
    }
    match acquire_engine(handle) {
        Some(engine) => Ok(engine),
        None => Err(fail(
            err_out,
            6,
            "invalid or freed engine handle".to_string(),
        )),
    }
}

/// FFI runtime sizing knob (#15): clamped, advisory, default 2.
/// Non-integer/zero values fall back to the default (never an error).
fn ffi_worker_threads(v: &serde_json::Value) -> usize {
    v.get("worker_threads")
        .and_then(|x| x.as_u64())
        .filter(|t| *t >= 1)
        .map(|t| t.clamp(1, 32) as usize)
        .unwrap_or(2)
}

/// Read a NUL-terminated UTF-8 argument.
///
/// # Safety
/// `ptr` must be null-checked by the caller contract: null yields a usage
/// error, otherwise it must point to a valid NUL-terminated C string that
/// remains alive for this call.
unsafe fn c_str(ptr: *const c_char) -> Result<String, String> {
    if ptr.is_null() {
        return Err("null string argument".to_string());
    }
    // SAFETY: `ptr` is non-null (checked above) and points to a valid
    // NUL-terminated string per the caller's Safety contract.
    unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .map(str::to_string)
        .map_err(|_| "argument is not valid UTF-8".to_string())
}

/// Read an optional NUL-terminated UTF-8 argument (null selects default).
///
/// # Safety
/// Same contract as [`c_str`]: null is `None`, otherwise `ptr` must point
/// to a valid NUL-terminated C string alive for this call.
unsafe fn opt_c_str(ptr: *const c_char) -> Result<Option<String>, String> {
    if ptr.is_null() {
        Ok(None)
    } else {
        // SAFETY: non-null `ptr` satisfies `c_str`'s validity contract.
        unsafe { c_str(ptr) }.map(Some)
    }
}

/// Optional JSON engine config:
/// `{"config_dir","profile_dir","family","prefer","max_depth","timeout_secs","worker_threads","dns_resolver"}`.
/// Null selects defaults. Transports linked are the FFI defaults (same set
/// the CLI links, including tor; `qcore-transports` is built with the `tor`
/// feature for both surfaces).
///
/// On Android, where embedders typically have neither `HOME` nor
/// `USERPROFILE`, no default config location exists. The caller must pass an
/// absolute, writable `config_dir` in `config_json`; otherwise this returns 6
/// naming `config_dir` instead of placing the identity in the process CWD.
///
/// `worker_threads` sizes the private FFI runtime (#15 perf batch: the fixed
/// `worker_threads(2)` ignored host width — embedders driving parallel scans
/// or multi-hop pumps can raise it; single-session embedders can lower it to
/// 1). Clamped to 1..=32, default 2 (unchanged behavior when absent).
/// Non-integer/zero values fall back to the default (never an error: sizing
/// is advisory, not validation).
///
/// `dns_resolver` (optional string IP) is the DNS server reachable from
/// inside the tunnel, used for SOCKS5 domain targets so domain names never
/// reach the OS resolver. Absent = no resolver (domain targets refuse
/// fail-closed), mirroring the engine default.
///
/// # Safety
/// `config_json` must be null or point to valid NUL-terminated UTF-8;
/// `out`/`err_out` must be null or point to writable pointers.
#[no_mangle]
pub unsafe extern "C" fn qcore_engine_new(
    config_json: *const c_char,
    out: *mut *mut QcoreEngine,
    err_out: *mut *mut QcoreError,
) -> c_int {
    unwind_guard(|| {
        if out.is_null() {
            return fail(err_out, 6, "null out-param".to_string());
        }
        // SAFETY: `config_json` validity is the caller's Safety contract for this entry point.
        let v: serde_json::Value = match unsafe { opt_c_str(config_json) } {
            Err(e) => return fail(err_out, 6, e),
            Ok(None) => serde_json::Value::Null,
            Ok(Some(s)) => match serde_json::from_str(&s) {
                Err(e) => return fail(err_out, 6, format!("config_json invalid: {e}")),
                Ok(v) => v,
            },
        };
        let str_field = |k: &str| v.get(k).and_then(|x| x.as_str()).map(str::to_string);
        let dirs = match ProfileDirs::try_resolve(
            str_field("config_dir").map(std::path::PathBuf::from),
            str_field("profile_dir").map(std::path::PathBuf::from),
        ) {
            Ok(dirs) => dirs,
            Err(e) => return fail(err_out, 6, e),
        };
        if let Err(e) = dirs.ensure_dirs() {
            return fail(err_out, 3, format!("profile dirs unavailable: {e}"));
        }
        let max_depth = v
            .get("max_depth")
            .and_then(|x| x.as_u64())
            .map(|d| d.clamp(1, 5) as u32)
            .unwrap_or(3);
        let timeout_secs = v
            .get("timeout_secs")
            .and_then(|x| x.as_u64())
            .filter(|t| *t >= 1)
            .unwrap_or(30);
        // FFI runtime sizing knob (#15): clamped, advisory, default 2.
        // #10 profiled `block_on` dispatch at ~67 ns/op — sizing is not the
        // binding constraint, so this buys embedder control, not speed.
        let worker_threads = ffi_worker_threads(&v);
        // Engine budget for teardown paths: free/stop never block longer
        // than this (T5 bounded teardown).
        let timeout = Duration::from_secs(timeout_secs.max(1));
        // Host links the transports it embeds (FR-003g scoping lives here).
        let _ = qcore_transports::linked_kinds();
        // Tunnel-side DNS resolver for SOCKS5 domain targets (optional
        // string IP; absent = None = domain targets refuse fail-closed).
        // An unparseable value fails closed naming the field (6).
        let dns_resolver = match str_field("dns_resolver") {
            Some(s) => match s.parse::<std::net::IpAddr>() {
                Ok(ip) => Some(ip),
                Err(_) => {
                    return fail(
                        err_out,
                        6,
                        format!("dns_resolver invalid: `{s}` is not an IP address"),
                    )
                }
            },
            None => None,
        };
        let engine = Engine::new(EngineConfig {
            dirs,
            max_depth,
            family: str_field("family").unwrap_or_else(|| "dual".to_string()),
            prefer: str_field("prefer").unwrap_or_else(|| "ipv4".to_string()),
            timeout_secs,
            dns_resolver,
            ..Default::default()
        });
        let rt = match tokio::runtime::Builder::new_multi_thread()
            .worker_threads(worker_threads)
            .thread_name("qcore-ffi")
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => return fail(err_out, 3, format!("runtime unavailable: {e}")),
        };
        let engine = std::sync::Arc::new(QcoreEngine {
            engine,
            rt,
            timeout,
        });
        // The handle is the `Arc` allocation's address (stable, opaque to
        // callers): the registry owns this strong reference, entry points
        // acquire clones, and `qcore_engine_free` releases the registry's.
        *unsafe { &mut *out } = track_handle(engine);
        0
    })
}

/// Destroy an engine (also stops all live sessions, bounded by the engine
/// `timeout_secs` budget — never blocks indefinitely). Null is a no-op
/// success. Forged/double-free handles are a usage error (6).
///
/// # Safety
/// `handle` must be null or a live handle from [`qcore_engine_new`]; it must
/// not be used afterwards.
#[no_mangle]
pub unsafe extern "C" fn qcore_engine_free(handle: *mut QcoreEngine) -> c_int {
    unwind_guard(|| {
        if handle.is_null() {
            return 0;
        }
        // Untracking removes the registry entry and hands back its strong
        // reference; any in-flight call on another thread still holds its
        // own clone, so the engine memory outlives this teardown and
        // use-after-free cannot occur. Double-free finds nothing and is
        // the documented usage error.
        let engine = match untrack_handle(handle) {
            Some(engine) => engine,
            None => return 6,
        };
        let budget = engine.timeout;
        let stopped = engine
            .rt
            .block_on(async { tokio::time::timeout(budget, engine.engine.stop()).await });
        match stopped {
            Ok(Ok(())) => 0,
            // No `err_out` channel on free: surface the mapped class only.
            Ok(Err(r)) => failure_code(&r),
            Err(_) => 3,
        }
    })
}

/// Start a chain (`hop (, hop)*` grammar, presets, `@labels`). Bounded by
/// the engine connection timeout — never blocks indefinitely. On success
/// `out_session_id` receives the session id (free with `qcore_string_free`).
///
/// # Safety
/// `handle` must be a live engine; `chain_expr` valid UTF-8 C string;
/// `out_session_id`/`err_out` null or writable.
#[no_mangle]
pub unsafe extern "C" fn qcore_engine_start(
    handle: *mut QcoreEngine,
    chain_expr: *const c_char,
    out_session_id: *mut *mut c_char,
    err_out: *mut *mut QcoreError,
) -> c_int {
    unwind_guard(|| {
        let engine = match check_handle(handle, err_out) {
            Err(code) => return code,
            Ok(engine) => engine,
        };
        // SAFETY: `chain_expr` validity is the caller's Safety contract for this entry point.
        let expr = match unsafe { c_str(chain_expr) } {
            Err(e) => return fail(err_out, 6, e),
            Ok(s) => s,
        };
        let specs = match engine.engine.parse_chain(&expr) {
            Err(e) => return fail(err_out, 2, e.to_string()),
            Ok(s) => s,
        };
        match engine.rt.block_on(engine.engine.start(specs)) {
            Err(r) => fail_report(err_out, &r),
            Ok(h) => ok_string(out_session_id, h.id.clone(), err_out),
        }
    })
}

/// Status JSON for one live session (`ConnectionReport` shape). Unknown id
/// is exit-3-class "no such live session".
///
/// # Safety
/// Same pointer contract as [`qcore_engine_start`].
#[no_mangle]
pub unsafe extern "C" fn qcore_engine_status_json(
    handle: *mut QcoreEngine,
    session_id: *const c_char,
    out_json: *mut *mut c_char,
    err_out: *mut *mut QcoreError,
) -> c_int {
    unwind_guard(|| {
        let engine = match check_handle(handle, err_out) {
            Err(code) => return code,
            Ok(engine) => engine,
        };
        // SAFETY: `session_id` validity is the caller's Safety contract for this entry point.
        let id = match unsafe { c_str(session_id) } {
            Err(e) => return fail(err_out, 6, e),
            Ok(s) => s,
        };
        match engine.engine.session_report(&id) {
            None => fail(err_out, 3, format!("no such live session `{id}`")),
            Some(report) => ok_string(
                out_json,
                qcore_core::session::report::to_json(&report),
                err_out,
            ),
        }
    })
}

/// Stop one live session (bounded by the engine `timeout_secs` budget —
/// never blocks indefinitely). Unknown id is an error.
///
/// # Safety
/// Same pointer contract as [`qcore_engine_start`].
#[no_mangle]
pub unsafe extern "C" fn qcore_engine_stop(
    handle: *mut QcoreEngine,
    session_id: *const c_char,
    err_out: *mut *mut QcoreError,
) -> c_int {
    unwind_guard(|| {
        let e = match check_handle(handle, err_out) {
            Err(code) => return code,
            Ok(e) => e,
        };
        // SAFETY: `session_id` validity is the caller's Safety contract for this entry point.
        let id = match unsafe { c_str(session_id) } {
            Err(e) => return fail(err_out, 6, e),
            Ok(s) => s,
        };
        let budget = e.timeout;
        match e
            .rt
            .block_on(async { tokio::time::timeout(budget, e.engine.stop_session(&id)).await })
        {
            Ok(Ok(())) => 0,
            Ok(Err(r)) => fail_report(err_out, &r),
            Err(_) => fail(
                err_out,
                3,
                format!("stop timed out after {}s", budget.as_secs()),
            ),
        }
    })
}

/// Endpoint scan (`transport`, `profile`, `family`) over discovery seeds.
/// Bounded by the profile RTT budget. Empty discovery returns code 4 with
/// the (empty) ranked JSON — never a silent unverified fallback.
///
/// # Safety
/// Same pointer contract as [`qcore_engine_start`].
#[no_mangle]
pub unsafe extern "C" fn qcore_scan(
    handle: *mut QcoreEngine,
    transport: *const c_char,
    profile: *const c_char,
    family: *const c_char,
    out_json: *mut *mut c_char,
    err_out: *mut *mut QcoreError,
) -> c_int {
    unwind_guard(|| {
        if let Err(code) = check_handle(handle, err_out) {
            return code;
        }
        // SAFETY: scan string args' validity is the caller's Safety contract for this entry point.
        let (transport, profile_name, family) =
            match unsafe { (c_str(transport), c_str(profile), c_str(family)) } {
                (Ok(t), Ok(p), Ok(f)) => (t, p, f),
                _ => return fail(err_out, 6, "scan arguments must be UTF-8".to_string()),
            };
        if out_json.is_null() {
            return fail(err_out, 6, "null out-param".to_string());
        }
        let e = match check_handle(handle, err_out) {
            Err(code) => return code,
            Ok(e) => e,
        };
        let dirs = e.engine.config_dirs();
        let profile = match qcore_core::scan::load_profile(&dirs, &profile_name) {
            Err(msg) => return fail(err_out, 6, msg),
            Ok(p) => p,
        };
        // T6: shared core pipeline — same winner fast-path, warp-seed
        // expansion, verify, and persist/evict as CLI scan.
        let report = match e.rt.block_on(qcore_core::scan::run_scan_request(
            &dirs, &transport, profile, &family,
        )) {
            Err(msg) => return fail(err_out, 3, msg),
            Ok(r) => r,
        };
        let body = serde_json::json!({
            "transport": transport,
            "profile": profile_name,
            "ranked": report.ranked,
            "failed": report.failed,
        })
        .to_string();
        if report.ranked.is_empty() {
            let _ = ok_string(out_json, body, err_out);
            return fail(err_out, 4, "scan found nothing reachable".to_string());
        }
        ok_string(out_json, body, err_out)
    })
}

/// Import a WireGuard/AmneziaWG config file. Returns
/// `{"ref","format"}`. Rejection is code 5 naming the field.
///
/// # Safety
/// Same pointer contract as [`qcore_engine_start`].
#[no_mangle]
pub unsafe extern "C" fn qcore_import_config(
    handle: *mut QcoreEngine,
    path: *const c_char,
    out_json: *mut *mut c_char,
    err_out: *mut *mut QcoreError,
) -> c_int {
    unwind_guard(|| {
        if let Err(code) = check_handle(handle, err_out) {
            return code;
        }
        // SAFETY: `path` validity is the caller's Safety contract for this entry point.
        let path = match unsafe { c_str(path) } {
            Err(e) => return fail(err_out, 6, e),
            Ok(s) => s,
        };
        let e = match check_handle(handle, err_out) {
            Err(code) => return code,
            Ok(e) => e,
        };
        let imp = match qcore_core::config::import::ConfigImport::parse(std::path::Path::new(&path))
        {
            Err(msg) => return fail(err_out, 5, msg),
            Ok(imp) => imp,
        };
        if imp.verdict != qcore_core::config::import::ImportVerdict::Accepted {
            return fail(err_out, 5, imp.reasons.join("; "));
        }
        let dirs = e.engine.config_dirs();
        match qcore_core::config::import::store_import(&dirs, &imp) {
            Err(msg) => fail(err_out, 3, msg),
            Ok(stored_ref) => ok_string(
                out_json,
                serde_json::json!({
                    "ref": stored_ref,
                    "format": match imp.source_format {
                        qcore_core::config::import::SourceFormat::Wireguard => "wireguard",
                        qcore_core::config::import::SourceFormat::Amneziawg => "amneziawg",
                    },
                })
                .to_string(),
                err_out,
            ),
        }
    })
}

/// Export an imported config, secrets redacted (never plaintext, FR-026).
///
/// # Safety
/// Same pointer contract as [`qcore_engine_start`].
#[no_mangle]
pub unsafe extern "C" fn qcore_export_config(
    handle: *mut QcoreEngine,
    import_ref: *const c_char,
    out_text: *mut *mut c_char,
    err_out: *mut *mut QcoreError,
) -> c_int {
    unwind_guard(|| {
        if let Err(code) = check_handle(handle, err_out) {
            return code;
        }
        // SAFETY: `import_ref` validity is the caller's Safety contract for this entry point.
        let import_ref = match unsafe { c_str(import_ref) } {
            Err(e) => return fail(err_out, 6, e),
            Ok(s) => s,
        };
        let e = match check_handle(handle, err_out) {
            Err(code) => return code,
            Ok(e) => e,
        };
        let dirs = e.engine.config_dirs();
        let (stored, secrets) = match qcore_core::config::import::load_import(&dirs, &import_ref) {
            Err(msg) => return fail(err_out, 5, msg),
            Ok(v) => v,
        };
        let imp = qcore_core::config::export::from_stored(
            &stored,
            secrets,
            std::path::Path::new(&import_ref),
        );
        ok_string(
            out_text,
            qcore_core::config::export::export_redacted(&imp),
            err_out,
        )
    })
}

/// Free a string returned by this ABI. Null is a no-op success.
///
/// # Safety
/// `s` must be null or a string previously returned by this ABI.
#[no_mangle]
pub unsafe extern "C" fn qcore_string_free(s: *mut c_char) -> c_int {
    unwind_guard(|| {
        if s.is_null() {
            return 0;
        }
        let _ = unsafe { CString::from_raw(s) };
        0
    })
}

/// Free a [`QcoreError`] (message included). Null is a no-op success.
///
/// # Safety
/// `err` must be null or an error previously returned by this ABI.
#[no_mangle]
pub unsafe extern "C" fn qcore_error_free(err: *mut QcoreError) -> c_int {
    unwind_guard(|| {
        if err.is_null() {
            return 0;
        }
        let err = unsafe { Box::from_raw(err) };
        if !err.message.is_null() {
            let _ = unsafe { CString::from_raw(err.message) };
        }
        0
    })
}

/// Thread-local last-error channel for JNI entry points that fail without a
/// `QcoreError` out-param (e.g. `engineNew` returning handle 0). JNI has no
/// `err_out` pointer, so named failures (interior NUL in a config, decode
/// failures) park their message here; `qcore_take_last_error` drains it.
/// The message is static-shaped (no secrets, never caller-supplied text).
static LAST_ERROR: std::sync::Mutex<Option<CString>> = std::sync::Mutex::new(None);

/// Park a named failure message for the JNI layer (see [`LAST_ERROR`]).
/// Best effort: a poisoned/contended channel never panics the caller.
pub(crate) fn set_last_error_jni(msg: &str) {
    if let Ok(mut slot) = LAST_ERROR.lock() {
        *slot = CString::new(msg).ok();
    }
}

/// Drain the thread-local last-error message into `out`. Returns 0 with the
/// message moved out, or 6 when there is nothing parked / the out-param is
/// null. The caller frees the string with `qcore_string_free`.
///
/// # Safety
/// `out` must be null or a writable pointer.
#[no_mangle]
pub unsafe extern "C" fn qcore_take_last_error(out: *mut *mut c_char) -> c_int {
    unwind_guard(|| {
        if out.is_null() {
            return 6;
        }
        let taken = LAST_ERROR
            .lock()
            .ok()
            .and_then(|mut slot| slot.take())
            .map(|c| c.into_raw());
        match taken {
            Some(s) => {
                // SAFETY: `out` is non-null (checked above) and points to a
                // writable caller pointer per the out-param contract.
                *unsafe { &mut *out } = s;
                0
            }
            None => 6,
        }
    })
}

// Compile-time proof that engine handles are thread-safe: C callers may
// share a `QcoreEngine` across threads, so `Send + Sync` must hold — and
// with it `Arc<QcoreEngine>` (the registry's stored reference and every
// in-flight clone), which is Send+Sync exactly when `QcoreEngine` is.
#[allow(dead_code)]
fn _assert_thread_safe() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<QcoreEngine>();
    assert_send_sync::<std::sync::Arc<QcoreEngine>>();
}

/// Android JNI wrapper over this same C ABI (no Android-only core paths).
pub mod jni;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fail_report_masks_secret_like_cause() {
        let r = qcore_transport_api::FailureReport::new(
            qcore_transport_api::FailureLayer::Transport,
            "wg-0",
            "boom xT4vN7qW2zR5uY8iO1pA3sD6fG9hJ0kL2mN4bV6cX8dE0gH2==",
            "transport",
        );
        let mut err: *mut QcoreError = std::ptr::null_mut();
        let code = fail_report(&mut err as *mut _, &r);
        assert_eq!(code, 3);
        assert!(!err.is_null());
        let msg = unsafe { CStr::from_ptr((*err).message) }
            .to_str()
            .unwrap()
            .to_string();
        assert!(!msg.contains("xT4vN7qW"), "cause leaked to caller buffer");
        assert!(msg.contains("cause=<redacted>"), "got: {msg}");
        assert_eq!(unsafe { qcore_error_free(err) }, 0);
        // Ordinary causes pass through with the code mapping intact.
        let r2 = qcore_transport_api::FailureReport::new(
            qcore_transport_api::FailureLayer::Validation,
            "h",
            "bad option",
            "validation",
        );
        let mut err2: *mut QcoreError = std::ptr::null_mut();
        assert_eq!(fail_report(&mut err2 as *mut _, &r2), 2);
        let msg2 = unsafe { CStr::from_ptr((*err2).message) }
            .to_str()
            .unwrap()
            .to_string();
        assert!(msg2.contains("cause=bad option"), "got: {msg2}");
        assert_eq!(unsafe { qcore_error_free(err2) }, 0);
    }

    #[test]
    fn worker_threads_knob_is_clamped_and_advisory() {
        // #15: sizing is advisory — out-of-range/non-integer values fall back
        // to the default instead of failing engine creation.
        let v = |json: serde_json::Value| ffi_worker_threads(&json);
        assert_eq!(v(serde_json::Value::Null), 2, "absent → default");
        assert_eq!(v(serde_json::json!({"worker_threads": 4})), 4);
        assert_eq!(v(serde_json::json!({"worker_threads": 1})), 1);
        assert_eq!(
            v(serde_json::json!({"worker_threads": 0})),
            2,
            "zero → default"
        );
        assert_eq!(
            v(serde_json::json!({"worker_threads": 999})),
            32,
            "huge clamps to the ceiling"
        );
        assert_eq!(
            v(serde_json::json!({"worker_threads": "many"})),
            2,
            "non-integer → default"
        );
    }

    #[test]
    fn fail_report_maps_from_layer_with_string_fallback_only() {
        // Layer drives the class even when the kind string disagrees, so
        // message rewording cannot silently remap exit classes.
        let mismatched = qcore_transport_api::FailureReport::new(
            qcore_transport_api::FailureLayer::Validation,
            "h",
            "boom",
            "transport",
        );
        let mut err: *mut QcoreError = std::ptr::null_mut();
        assert_eq!(fail_report(&mut err as *mut _, &mismatched), 2);
        assert_eq!(unsafe { qcore_error_free(err) }, 0);
        // Scan layer maps to empty-scan (4), matching core's single source.
        let scan = qcore_transport_api::FailureReport::new(
            qcore_transport_api::FailureLayer::Scan,
            "h",
            "nothing",
            "whatever",
        );
        let mut err: *mut QcoreError = std::ptr::null_mut();
        assert_eq!(fail_report(&mut err as *mut _, &scan), 4);
        assert_eq!(unsafe { qcore_error_free(err) }, 0);
        // String fallback only: a `usage` kind with no Usage layer variant.
        let usage = qcore_transport_api::FailureReport::new(
            qcore_transport_api::FailureLayer::Transport,
            "h",
            "bad call",
            "usage",
        );
        let mut err: *mut QcoreError = std::ptr::null_mut();
        assert_eq!(fail_report(&mut err as *mut _, &usage), 6);
        assert_eq!(unsafe { qcore_error_free(err) }, 0);
    }

    #[test]
    fn ok_string_null_out_is_usage_not_success() {
        // Null out-param must not masquerade as success: out-params are
        // null-checked per the FFI contract (usage error 6, with err set).
        let mut err: *mut QcoreError = std::ptr::null_mut();
        assert_eq!(
            ok_string(std::ptr::null_mut(), "x".to_string(), &mut err as *mut _),
            6
        );
        assert!(!err.is_null());
        assert_eq!(unsafe { qcore_error_free(err) }, 0);
        let mut out: *mut c_char = std::ptr::null_mut();
        let mut err2: *mut QcoreError = std::ptr::null_mut();
        assert_eq!(
            ok_string(&mut out as *mut _, "ok".to_string(), &mut err2 as *mut _),
            0
        );
        assert!(!out.is_null());
        assert!(err2.is_null());
        // SAFETY: `out` was just written by `ok_string` per its contract.
        let s = unsafe { CStr::from_ptr(out) }.to_str().unwrap().to_string();
        assert_eq!(s, "ok");
        assert_eq!(unsafe { qcore_string_free(out) }, 0);
    }

    #[test]
    fn ok_string_interior_nul_populates_err_out() {
        // A code must never arrive with no message: interior NUL populates
        // the error out-param instead of returning bare -1.
        let mut out: *mut c_char = std::ptr::null_mut();
        let mut err: *mut QcoreError = std::ptr::null_mut();
        let rc = ok_string(&mut out as *mut _, "ab\0cd".to_string(), &mut err as *mut _);
        assert_eq!(rc, -1);
        assert!(out.is_null());
        assert!(!err.is_null());
        let msg = unsafe { CStr::from_ptr((*err).message) }
            .to_str()
            .unwrap()
            .to_string();
        assert!(msg.contains("NUL"), "got: {msg}");
        assert_eq!(unsafe { qcore_error_free(err) }, 0);
    }

    #[test]
    fn live_handle_set_restores_after_poison() {
        // Poison the set, then prove lookups still work (restore, not a
        // silent false) instead of failing closed on every handle.
        let poisoned = std::panic::catch_unwind(|| {
            let _guard = lock_live_handles();
            panic!("intentional poison probe");
        });
        assert!(poisoned.is_err());
        // The set is restored with contents preserved: a forged handle is
        // still rejected as usage-error, not as a poison artifact.
        let chain = CString::new("mock").unwrap();
        let mut out: *mut c_char = std::ptr::null_mut();
        let mut err: *mut QcoreError = std::ptr::null_mut();
        let forged = 0x1234 as *mut QcoreEngine;
        let rc = unsafe {
            qcore_engine_start(
                forged,
                chain.as_ptr(),
                &mut out as *mut _,
                &mut err as *mut _,
            )
        };
        assert_eq!(rc, 6);
        if !err.is_null() {
            assert_eq!(unsafe { qcore_error_free(err) }, 0);
        }
        // And a real engine still tracks through the restored set.
        let base = std::env::temp_dir().join(format!("qcore-ffi-poison-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let cfg = serde_json::json!({
            "config_dir": base.join("config").to_str().unwrap(),
            "profile_dir": base.join("profiles").to_str().unwrap(),
        })
        .to_string();
        let cfg = CString::new(cfg).unwrap();
        let mut out: *mut QcoreEngine = std::ptr::null_mut();
        let mut err: *mut QcoreError = std::ptr::null_mut();
        assert_eq!(
            unsafe { qcore_engine_new(cfg.as_ptr(), &mut out as *mut _, &mut err as *mut _) },
            0
        );
        assert!(acquire_engine(out).is_some());
        assert_eq!(unsafe { qcore_engine_free(out) }, 0);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn c_str_helpers_reject_null() {
        // SAFETY: null is the documented no-deref probe for both helpers.
        assert!(unsafe { c_str(std::ptr::null()) }.is_err());
        assert!(unsafe { opt_c_str(std::ptr::null()) }.unwrap().is_none());
    }

    #[test]
    fn engine_new_honors_worker_threads_end_to_end() {
        // Creation succeeds with an explicit knob value (dirs pointed at temp
        // so the test never touches the real profile).
        let base = std::env::temp_dir().join(format!("qcore-ffi-knob-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let cfg = serde_json::json!({
            "config_dir": base.join("config").to_str().unwrap(),
            "profile_dir": base.join("profiles").to_str().unwrap(),
            "worker_threads": 4,
        })
        .to_string();
        let cfg = CString::new(cfg).unwrap();
        let mut out: *mut QcoreEngine = std::ptr::null_mut();
        let mut err: *mut QcoreError = std::ptr::null_mut();
        let rc = unsafe { qcore_engine_new(cfg.as_ptr(), &mut out as *mut _, &mut err as *mut _) };
        assert_eq!(rc, 0, "engine_new accepts the knob");
        assert!(!out.is_null());
        assert_eq!(unsafe { qcore_engine_free(out) }, 0);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn forged_handle_fails_closed_not_ub() {
        let chain = CString::new("mock").unwrap();
        let mut out: *mut c_char = std::ptr::null_mut();
        let mut err: *mut QcoreError = std::ptr::null_mut();
        let forged = 0x1234 as *mut QcoreEngine;
        assert!(!forged.is_null());
        let rc = unsafe {
            qcore_engine_start(
                forged,
                chain.as_ptr(),
                &mut out as *mut _,
                &mut err as *mut _,
            )
        };
        assert_eq!(rc, 6, "forged handle must fail closed with usage error");
        assert!(out.is_null());
        if !err.is_null() {
            assert_eq!(unsafe { qcore_error_free(err) }, 0);
        }
    }

    #[test]
    fn double_free_is_usage_not_ub() {
        let base = std::env::temp_dir().join(format!("qcore-ffi-dfree-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let cfg = serde_json::json!({
            "config_dir": base.join("config").to_str().unwrap(),
            "profile_dir": base.join("profiles").to_str().unwrap(),
        })
        .to_string();
        let cfg = CString::new(cfg).unwrap();
        let mut out: *mut QcoreEngine = std::ptr::null_mut();
        let mut err: *mut QcoreError = std::ptr::null_mut();
        assert_eq!(
            unsafe { qcore_engine_new(cfg.as_ptr(), &mut out as *mut _, &mut err as *mut _) },
            0
        );
        assert!(!out.is_null());
        assert_eq!(unsafe { qcore_engine_free(out) }, 0);
        assert_eq!(
            unsafe { qcore_engine_free(out) },
            6,
            "second free must fail closed"
        );
        let chain = CString::new("mock").unwrap();
        let mut sout: *mut c_char = std::ptr::null_mut();
        let mut serr: *mut QcoreError = std::ptr::null_mut();
        let rc = unsafe {
            qcore_engine_start(
                out,
                chain.as_ptr(),
                &mut sout as *mut _,
                &mut serr as *mut _,
            )
        };
        assert_eq!(rc, 6, "use-after-free must fail closed");
        if !serr.is_null() {
            assert_eq!(unsafe { qcore_error_free(serr) }, 0);
        }
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn scan_null_out_is_usage_not_empty() {
        let base = std::env::temp_dir().join(format!("qcore-ffi-scan-null-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let cfg = serde_json::json!({
            "config_dir": base.join("config").to_str().unwrap(),
            "profile_dir": base.join("profiles").to_str().unwrap(),
        })
        .to_string();
        let cfg = CString::new(cfg).unwrap();
        let mut out: *mut QcoreEngine = std::ptr::null_mut();
        let mut err: *mut QcoreError = std::ptr::null_mut();
        assert_eq!(
            unsafe { qcore_engine_new(cfg.as_ptr(), &mut out as *mut _, &mut err as *mut _) },
            0
        );
        let t = CString::new("mock").unwrap();
        let p = CString::new("balanced").unwrap();
        let f = CString::new("dual").unwrap();
        let mut serr: *mut QcoreError = std::ptr::null_mut();
        let rc = unsafe {
            qcore_scan(
                out,
                t.as_ptr(),
                p.as_ptr(),
                f.as_ptr(),
                std::ptr::null_mut(),
                &mut serr as *mut _,
            )
        };
        assert_eq!(rc, 6, "null out_json must be usage error, not empty-scan 4");
        if !serr.is_null() {
            assert_eq!(unsafe { qcore_error_free(serr) }, 0);
        }
        assert_eq!(unsafe { qcore_engine_free(out) }, 0);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn free_during_call_is_safe() {
        // Registry-level model of the flagged race: an in-flight call holds
        // the strong ref it acquired under the registry lock while another
        // thread frees the engine. Free releases the registry's ref, but the
        // engine memory must stay alive and usable until the in-flight ref
        // drops (the engine's call cannot be made to block deterministically
        // in tests, so the clone-out proves the same invariant).
        let base = std::env::temp_dir().join(format!("qcore-ffi-fdc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let cfg = serde_json::json!({
            "config_dir": base.join("config").to_str().unwrap(),
            "profile_dir": base.join("profiles").to_str().unwrap(),
        })
        .to_string();
        let cfg = CString::new(cfg).unwrap();
        let mut out: *mut QcoreEngine = std::ptr::null_mut();
        let mut err: *mut QcoreError = std::ptr::null_mut();
        assert_eq!(
            unsafe { qcore_engine_new(cfg.as_ptr(), &mut out as *mut _, &mut err as *mut _) },
            0
        );
        let inflight = acquire_engine(out).expect("live handle acquires a strong ref");
        assert_eq!(
            std::sync::Arc::strong_count(&inflight),
            2,
            "registry + in-flight call own the engine"
        );
        assert_eq!(unsafe { qcore_engine_free(out) }, 0);
        assert_eq!(
            std::sync::Arc::strong_count(&inflight),
            1,
            "registry released its ref; the in-flight call still pins the engine"
        );
        assert!(
            inflight.engine.parse_chain("mock").is_ok(),
            "engine usable on the in-flight ref after free returned"
        );
        assert!(
            acquire_engine(out).is_none(),
            "freed handle is dead for new acquires"
        );
        let weak = std::sync::Arc::downgrade(&inflight);
        drop(inflight);
        assert!(weak.upgrade().is_none(), "engine dropped with the last ref");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn arc_strong_count_lifecycle() {
        // Strong-count contract of the registry: new → registry owns one
        // ref; free releases it; the last clone dropping drops the engine.
        let base = std::env::temp_dir().join(format!("qcore-ffi-arc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let cfg = serde_json::json!({
            "config_dir": base.join("config").to_str().unwrap(),
            "profile_dir": base.join("profiles").to_str().unwrap(),
        })
        .to_string();
        let cfg = CString::new(cfg).unwrap();
        let mut out: *mut QcoreEngine = std::ptr::null_mut();
        let mut err: *mut QcoreError = std::ptr::null_mut();
        assert_eq!(
            unsafe { qcore_engine_new(cfg.as_ptr(), &mut out as *mut _, &mut err as *mut _) },
            0
        );
        let clone = acquire_engine(out).expect("live handle acquires");
        assert_eq!(
            std::sync::Arc::strong_count(&clone),
            2,
            "registry + clone hold the engine"
        );
        assert_eq!(unsafe { qcore_engine_free(out) }, 0);
        assert_eq!(
            std::sync::Arc::strong_count(&clone),
            1,
            "free dropped the registry's ref"
        );
        assert!(
            acquire_engine(out).is_none(),
            "freed handle acquires nothing"
        );
        let weak = std::sync::Arc::downgrade(&clone);
        drop(clone);
        assert!(
            weak.upgrade().is_none(),
            "engine drops when the last strong ref drops"
        );
        let _ = std::fs::remove_dir_all(&base);
    }
}
