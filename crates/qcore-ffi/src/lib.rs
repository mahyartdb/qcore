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

use qcore_core::api::{Engine, EngineConfig};
use qcore_core::config::profile_dir::ProfileDirs;
use std::ffi::{c_char, c_int, CStr, CString};

/// Opaque engine handle (see [`qcore_engine_new`]).
pub struct QcoreEngine {
    engine: Engine,
    rt: tokio::runtime::Runtime,
}

/// Out-param error record. `code` mirrors the CLI exit-code contract
/// (2 invalid, 3 hop failure, 4 empty scan, 5 import rejected, 6 usage,
/// -1 internal panic); `message` is an owned NUL-terminated string.
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

fn ok_string(out: *mut *mut c_char, s: String) -> c_int {
    if out.is_null() {
        return 6;
    }
    match CString::new(s) {
        Ok(c) => {
            // SAFETY: `out` is non-null (checked above) and points to a
            // writable caller pointer per the out-param contract.
            *unsafe { &mut *out } = c.into_raw();
            0
        }
        Err(_) => {
            // Interior NUL cannot occur (JSON/ids are NUL-free); fail loud.
            -1
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

fn fail_report(err_out: *mut *mut QcoreError, r: &qcore_transport_api::FailureReport) -> c_int {
    // Failure kinds map onto the CLI exit-code contract for stability.
    let code = match r.kind.as_str() {
        "usage" => 6,
        "validation" => 2,
        "unreachable" | "timeout" | "shutdown" => 3,
        _ => 3,
    };
    // Shared masked rendering: this message crosses into caller-owned
    // buffers, which promise (module docs, FR-026) to never carry secrets.
    let message = qcore_core::diag::masked_failure_line(r);
    fail(err_out, code, message)
}

fn unwind_guard<F: FnOnce() -> c_int + std::panic::UnwindSafe>(f: F) -> c_int {
    std::panic::catch_unwind(f).unwrap_or(-1)
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
/// `{"config_dir","profile_dir","family","prefer","max_depth","timeout_secs","worker_threads"}`.
/// Null selects defaults. Transports linked are the FFI defaults (same set
/// the CLI links minus tor; see `qcore-transports` features).
///
/// `worker_threads` sizes the private FFI runtime (#15 perf batch: the fixed
/// `worker_threads(2)` ignored host width — embedders driving parallel scans
/// or multi-hop pumps can raise it; single-session embedders can lower it to
/// 1). Clamped to 1..=32, default 2 (unchanged behavior when absent).
/// Non-integer/zero values fall back to the default (never an error: sizing
/// is advisory, not validation).
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
        let dirs = ProfileDirs::resolve(
            str_field("config_dir").map(std::path::PathBuf::from),
            str_field("profile_dir").map(std::path::PathBuf::from),
        );
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
        // Host links the transports it embeds (FR-003g scoping lives here).
        let _ = qcore_transports::linked_kinds();
        let engine = Engine::new(EngineConfig {
            dirs,
            max_depth,
            family: str_field("family").unwrap_or_else(|| "dual".to_string()),
            prefer: str_field("prefer").unwrap_or_else(|| "ipv4".to_string()),
            timeout_secs,
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
        *unsafe { &mut *out } = Box::into_raw(Box::new(QcoreEngine { engine, rt }));
        0
    })
}

/// Destroy an engine (also stops all live sessions, bounded by the engine
/// timeout). Null is a no-op success.
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
        let engine = unsafe { Box::from_raw(handle) };
        let _ = engine.rt.block_on(engine.engine.stop());
        0
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
        if handle.is_null() {
            return fail(err_out, 6, "null engine handle".to_string());
        }
        // SAFETY: `chain_expr` validity is the caller's Safety contract for this entry point.
        let expr = match unsafe { c_str(chain_expr) } {
            Err(e) => return fail(err_out, 6, e),
            Ok(s) => s,
        };
        let engine = unsafe { &(*handle).engine };
        let specs = match engine.parse_chain(&expr) {
            Err(e) => return fail(err_out, 2, e.to_string()),
            Ok(s) => s,
        };
        let rt = unsafe { &(*handle).rt };
        match rt.block_on(engine.start(specs)) {
            Err(r) => fail_report(err_out, &r),
            Ok(h) => ok_string(out_session_id, h.id.clone()),
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
        if handle.is_null() {
            return fail(err_out, 6, "null engine handle".to_string());
        }
        // SAFETY: `session_id` validity is the caller's Safety contract for this entry point.
        let id = match unsafe { c_str(session_id) } {
            Err(e) => return fail(err_out, 6, e),
            Ok(s) => s,
        };
        let engine = unsafe { &(*handle).engine };
        match engine.session_report(&id) {
            None => fail(err_out, 3, format!("no such live session `{id}`")),
            Some(report) => ok_string(out_json, qcore_core::session::report::to_json(&report)),
        }
    })
}

/// Stop one live session (bounded). Unknown id is an error.
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
        if handle.is_null() {
            return fail(err_out, 6, "null engine handle".to_string());
        }
        // SAFETY: `session_id` validity is the caller's Safety contract for this entry point.
        let id = match unsafe { c_str(session_id) } {
            Err(e) => return fail(err_out, 6, e),
            Ok(s) => s,
        };
        let e = unsafe { &*handle };
        match e.rt.block_on(e.engine.stop_session(&id)) {
            Err(r) => fail_report(err_out, &r),
            Ok(()) => 0,
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
        if handle.is_null() {
            return fail(err_out, 6, "null engine handle".to_string());
        }
        // SAFETY: scan string args' validity is the caller's Safety contract for this entry point.
        let (transport, profile_name, family) =
            match unsafe { (c_str(transport), c_str(profile), c_str(family)) } {
                (Ok(t), Ok(p), Ok(f)) => (t, p, f),
                _ => return fail(err_out, 6, "scan arguments must be UTF-8".to_string()),
            };
        let e = unsafe { &*handle };
        let dirs = e.engine.config_dirs();
        let profile = match qcore_core::scan::load_profile(&dirs, &profile_name) {
            Err(msg) => return fail(err_out, 6, msg),
            Ok(p) => p,
        };
        let req = qcore_core::scan::ScanRequest {
            transport: transport.clone(),
            profile,
            family,
            candidates: qcore_core::scan::discovery_seeds(&dirs, &transport),
        };
        let report = match e.rt.block_on(qcore_core::scan::Scanner::scan(req)) {
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
            let _ = ok_string(out_json, body);
            return fail(err_out, 4, "scan found nothing reachable".to_string());
        }
        ok_string(out_json, body)
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
        if handle.is_null() {
            return fail(err_out, 6, "null engine handle".to_string());
        }
        // SAFETY: `path` validity is the caller's Safety contract for this entry point.
        let path = match unsafe { c_str(path) } {
            Err(e) => return fail(err_out, 6, e),
            Ok(s) => s,
        };
        let e = unsafe { &*handle };
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
        if handle.is_null() {
            return fail(err_out, 6, "null engine handle".to_string());
        }
        // SAFETY: `import_ref` validity is the caller's Safety contract for this entry point.
        let import_ref = match unsafe { c_str(import_ref) } {
            Err(e) => return fail(err_out, 6, e),
            Ok(s) => s,
        };
        let e = unsafe { &*handle };
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
        ok_string(out_text, qcore_core::config::export::export_redacted(&imp))
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

// Compile-time proof that engine handles are thread-safe: C callers may
// share a `QcoreEngine` across threads, so `Send + Sync` must hold.
#[allow(dead_code)]
fn _assert_thread_safe() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<QcoreEngine>();
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
    fn ok_string_null_out_is_usage_not_success() {
        // Null out-param must not masquerade as success: out-params are
        // null-checked per the FFI contract (usage error 6).
        assert_eq!(ok_string(std::ptr::null_mut(), "x".to_string()), 6);
        let mut out: *mut c_char = std::ptr::null_mut();
        assert_eq!(ok_string(&mut out as *mut _, "ok".to_string()), 0);
        assert!(!out.is_null());
        // SAFETY: `out` was just written by `ok_string` per its contract.
        let s = unsafe { CStr::from_ptr(out) }.to_str().unwrap().to_string();
        assert_eq!(s, "ok");
        assert_eq!(unsafe { qcore_string_free(out) }, 0);
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
}
