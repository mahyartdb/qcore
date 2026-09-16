//! ABI consumer test with the Rust harness (T081, SC-002b).
//!
//! A second host personality — alongside `embed-host` (Rust API) — that
//! starts a session, reads its state, and stops it through the *documented
//! C ABI only* (`qcore_*` symbols, `QcoreEngine`/`QcoreError` as opaque
//! pointers, JSON documents), with no access to engine internals.
//! Runs offline against the mock transport.

use qcore_ffi::{QcoreEngine, QcoreError};
use std::ffi::{c_char, CStr, CString};
use std::ptr;

fn take_string(ptr: *mut c_char) -> String {
    assert!(!ptr.is_null(), "ABI returned null string on success");
    let s = unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .expect("ABI strings are UTF-8")
        .to_string();
    assert_eq!(unsafe { qcore_ffi::qcore_string_free(ptr) }, 0);
    s
}

fn config_json() -> CString {
    let dir = std::env::temp_dir().join("qcore-abi-consumer");
    let _ = std::fs::remove_dir_all(&dir);
    CString::new(
        serde_json::json!({
            "config_dir": dir.join("config").to_str().unwrap(),
            "profile_dir": dir.join("profiles").to_str().unwrap(),
            "family": "dual",
            "timeout_secs": 30,
        })
        .to_string(),
    )
    .unwrap()
}

#[test]
fn abi_version_reported() {
    assert_eq!(
        unsafe { qcore_ffi::qcore_abi_version() },
        1,
        "ABI version pinned"
    );
}

#[test]
fn c_abi_session_lifecycle() {
    let cfg = config_json();
    let mut engine: *mut QcoreEngine = ptr::null_mut();
    let mut err: *mut QcoreError = ptr::null_mut();
    assert_eq!(
        unsafe { qcore_ffi::qcore_engine_new(cfg.as_ptr(), &mut engine, &mut err) },
        0,
        "engine_new"
    );
    assert!(!engine.is_null());

    // Start.
    let chain = CString::new("mock").unwrap();
    let mut session: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe { qcore_ffi::qcore_engine_start(engine, chain.as_ptr(), &mut session, &mut err) },
        0,
        "engine_start"
    );
    let session_id = take_string(session);
    assert!(!session_id.is_empty());

    // State.
    let id_c = CString::new(session_id.clone()).unwrap();
    let mut status: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe {
            qcore_ffi::qcore_engine_status_json(engine, id_c.as_ptr(), &mut status, &mut err)
        },
        0,
        "engine_status_json"
    );
    let doc = take_string(status);
    let v: serde_json::Value = serde_json::from_str(&doc).expect("status is JSON");
    assert_eq!(v["exit_hop_id"], "mock-0");
    assert_eq!(v["secret_redaction"], true);

    // Stop + free.
    assert_eq!(
        unsafe { qcore_ffi::qcore_engine_stop(engine, id_c.as_ptr(), &mut err) },
        0,
        "engine_stop"
    );
    // Unknown session is a shaped error, not a crash.
    let bogus = CString::new("sess-nope").unwrap();
    assert_ne!(
        unsafe { qcore_ffi::qcore_engine_stop(engine, bogus.as_ptr(), &mut err) },
        0,
        "unknown session errors"
    );
    assert_eq!(unsafe { qcore_ffi::qcore_engine_free(engine) }, 0);
}
