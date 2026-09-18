//! Android JNI wrapper over the C ABI (T079, FR-003d).
//!
//! No Android-only code paths in core: this module only translates
//! `JNIEnv`/`jstring` calls into the `qcore_*` C functions in `lib.rs`.
//! Dependency-free on purpose (no `jni` crate): the JNI ABI is plain C —
//! `JNIEnv` points at the standard `JNINativeInterface` table, of which we
//! type exactly the four slots we call (`NewStringUTF`,
//! `GetStringUTFLength`, `GetStringUTFChars`, `ReleaseStringUTFChars` at
//! indices 167–170); every other slot is an opaque placeholder so the
//! layout stays correct without 200+ unused signatures.
//!
//! Java side (`com.qcore.Qcore`): `long engineNew(String configJsonOrNull)`,
//! `String engineStart(long, String chain)`, `String engineStatusJson(long,
//! String sessionId)`, `int engineStop(long, String sessionId)`,
//! `String scanJson(long, String transport, String profile, String family)`,
//! `String importConfig(long, String path)`, `String exportConfig(long,
//! String ref)`, `void engineFree(long)`, `int abiVersion()`. Null/negative
//! returns are failures (OOM, internal, or unusable JVM input); error
//! detail rides the C ABI.

use std::ffi::{c_char, c_int, c_void, CStr, CString};

/// Raw JNI aliases (public for signature visibility; opaque to callers).
#[doc(hidden)]
pub type JniEnv = *mut *const JniTable;
#[doc(hidden)]
pub type JString = *mut c_void;

/// Raw JNI table prefix (public for signature visibility; opaque to callers).
#[doc(hidden)]
#[repr(C)]
pub struct JniTable {
    _reserved_and_unused: [*const c_void; 167],
    new_string_utf: unsafe extern "system" fn(env: JniEnv, bytes: *const c_char) -> JString,
    _get_string_utf_length: *const c_void,
    get_string_utf_chars:
        unsafe extern "system" fn(env: JniEnv, s: JString, is_copy: *mut u8) -> *const c_char,
    release_string_utf_chars:
        unsafe extern "system" fn(env: JniEnv, s: JString, chars: *const c_char),
}

/// Read a Java string into Rust. Returns `None` on null input, a null
/// table, a failed pin, or non-UTF-8 content (CESU-8 details aside, JVM
/// strings convert losslessly here for the ASCII/UTF-8 range this API
/// passes). The pin is always released before returning.
unsafe fn j_to_rust(env: JniEnv, s: JString) -> Option<String> {
    if s.is_null() || env.is_null() || (*env).is_null() {
        return None;
    }
    // SAFETY: `env` is non-null and points at the JVM's function table
    // (checked above; guaranteed by the JVM for these entry points), so
    // dereferencing two levels to reach the table is sound.
    let table = &**env;
    let chars = (table.get_string_utf_chars)(env, s, std::ptr::null_mut());
    if chars.is_null() {
        return None;
    }
    // SAFETY: `chars` is a valid NUL-terminated buffer pinned by the pin
    // call above; it stays pinned until the paired release below.
    let out = CStr::from_ptr(chars).to_str().ok().map(str::to_string);
    (table.release_string_utf_chars)(env, s, chars);
    out
}

/// Build a Java string from Rust text. Returns null when the table is
/// missing or the JVM cannot allocate (pending OOM exception).
unsafe fn rust_to_j(env: JniEnv, s: &str) -> JString {
    if env.is_null() || (*env).is_null() {
        return std::ptr::null_mut();
    }
    let bytes = CString::new(s).unwrap_or_else(|_| CString::new("").unwrap());
    // SAFETY: same table-validity argument as `j_to_rust`; `bytes` outlives
    // the call. Interior NULs fall back to empty (engine strings are
    // NUL-free JSON/ids).
    ((&**env).new_string_utf)(env, bytes.as_ptr())
}

/// Reinterpret a handle integer as the engine pointer it came from.
/// Only valid for values previously produced as `out as i64`; anything
/// else is a caller bug with undefined results.
///
/// # Safety
/// `handle` must be a live engine pointer from `engineNew` (or 0, which
/// the C functions reject as a null handle).
unsafe fn with_engine<T>(handle: i64, f: impl FnOnce(*mut crate::QcoreEngine) -> T) -> T {
    f(handle as *mut crate::QcoreEngine)
}

fn take_string(ptr: *mut c_char) -> String {
    if ptr.is_null() {
        return String::new();
    }
    // SAFETY: non-null `ptr` is a string previously returned by this ABI
    // (out-param contract), so reclaiming it here is sound; the copy below
    // is made before freeing.
    let s = unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .unwrap_or_default()
        .to_string();
    unsafe { crate::qcore_string_free(ptr) };
    s
}

fn take_error(ptr: *mut crate::QcoreError) {
    if !ptr.is_null() {
        // SAFETY: non-null `ptr` is an error record previously returned by
        // this ABI (out-param contract), so freeing it here is sound.
        unsafe { crate::qcore_error_free(ptr) };
    }
}

/// Run one string-returning C ABI call from a JNI entry point and convert
/// its out-string to Java. `args` convert in order; a `None` argument (null
/// Java string, failed pin, non-UTF-8 content) or an interior NUL fails the
/// whole call with null — JVM input problems never silently become empty
/// input, and NULs never rewrite into different valid input. The out buffer
/// is always reclaimed (`take_string` is null-safe); only code 0 returns a
/// string. Java-observable behavior matches the previous inline code (null
/// on every failure path); this only removes the five-fold triplication
/// and the silent coercions.
unsafe fn call_c_abi(
    env: JniEnv,
    args: &[JString],
    call: impl FnOnce(&[*const c_char]) -> (c_int, *mut c_char, *mut crate::QcoreError),
) -> JString {
    let mut owned = Vec::with_capacity(args.len());
    for &arg in args {
        let s = match j_to_rust(env, arg) {
            Some(s) => s,
            None => return std::ptr::null_mut(),
        };
        match CString::new(s) {
            Ok(c) => owned.push(c),
            Err(_) => return std::ptr::null_mut(),
        }
    }
    let ptrs: Vec<*const c_char> = owned.iter().map(|c| c.as_ptr()).collect();
    let (code, out, err) = call(&ptrs);
    take_error(err);
    let s = take_string(out);
    if code == 0 {
        rust_to_j(env, &s)
    } else {
        std::ptr::null_mut()
    }
}

/// `Qcore.abiVersion()`.
///
/// # Safety
/// Called by the JVM with a valid `JNIEnv`; never from any other caller.
#[no_mangle]
pub unsafe extern "system" fn Java_com_qcore_Qcore_abiVersion(
    _env: JniEnv,
    _class: *mut c_void,
) -> i32 {
    // Pure version query; no pointers dereferenced.
    unsafe { crate::qcore_abi_version() as i32 }
}

/// `Qcore.engineNew(configJsonOrNull)` → handle or 0.
///
/// # Safety
/// Called by the JVM with a valid `JNIEnv`; never from any other caller.
#[no_mangle]
pub unsafe extern "system" fn Java_com_qcore_Qcore_engineNew(
    env: JniEnv,
    _class: *mut c_void,
    config_json: JString,
) -> i64 {
    let result = std::panic::catch_unwind(|| unsafe {
        let cfg = if config_json.is_null() {
            None
        } else {
            j_to_rust(env, config_json)
        };
        let cfg_ptr = cfg
            .as_ref()
            .map(|s| CString::new(s.as_str()).unwrap_or_else(|_| CString::new("").unwrap()));
        let mut out: *mut crate::QcoreEngine = std::ptr::null_mut();
        let mut err: *mut crate::QcoreError = std::ptr::null_mut();
        let code = crate::qcore_engine_new(
            cfg_ptr
                .as_ref()
                .map(|c| c.as_ptr())
                .unwrap_or(std::ptr::null()),
            &mut out,
            &mut err,
        );
        take_error(err);
        if code == 0 {
            out as i64
        } else {
            0
        }
    });
    result.unwrap_or(0)
}

/// `Qcore.engineStart(handle, chain)` → session id or null.
///
/// # Safety
/// Called by the JVM with a valid `JNIEnv`; never from any other caller.
#[no_mangle]
pub unsafe extern "system" fn Java_com_qcore_Qcore_engineStart(
    env: JniEnv,
    _class: *mut c_void,
    handle: i64,
    chain: JString,
) -> JString {
    let result = std::panic::catch_unwind(|| unsafe {
        call_c_abi(env, &[chain], |args| {
            let mut out: *mut c_char = std::ptr::null_mut();
            let mut err: *mut crate::QcoreError = std::ptr::null_mut();
            let code = with_engine(handle, |e| {
                crate::qcore_engine_start(e, args[0], &mut out, &mut err)
            });
            (code, out, err)
        })
    });
    result.unwrap_or(std::ptr::null_mut())
}

/// `Qcore.engineStatusJson(handle, sessionId)` → JSON or null.
///
/// # Safety
/// Called by the JVM with a valid `JNIEnv`; never from any other caller.
#[no_mangle]
pub unsafe extern "system" fn Java_com_qcore_Qcore_engineStatusJson(
    env: JniEnv,
    _class: *mut c_void,
    handle: i64,
    session_id: JString,
) -> JString {
    let result = std::panic::catch_unwind(|| unsafe {
        call_c_abi(env, &[session_id], |args| {
            let mut out: *mut c_char = std::ptr::null_mut();
            let mut err: *mut crate::QcoreError = std::ptr::null_mut();
            let code = with_engine(handle, |e| {
                crate::qcore_engine_status_json(e, args[0], &mut out, &mut err)
            });
            (code, out, err)
        })
    });
    result.unwrap_or(std::ptr::null_mut())
}

/// `Qcore.engineStop(handle, sessionId)` → 0 or negative.
///
/// # Safety
/// Called by the JVM with a valid `JNIEnv`; never from any other caller.
#[no_mangle]
pub unsafe extern "system" fn Java_com_qcore_Qcore_engineStop(
    env: JniEnv,
    _class: *mut c_void,
    handle: i64,
    session_id: JString,
) -> i32 {
    let result = std::panic::catch_unwind(|| unsafe {
        let id = j_to_rust(env, session_id).unwrap_or_default();
        let id_c = CString::new(id).unwrap_or_else(|_| CString::new("").unwrap());
        let mut err: *mut crate::QcoreError = std::ptr::null_mut();
        let code = with_engine(handle, |e| {
            crate::qcore_engine_stop(e, id_c.as_ptr(), &mut err)
        });
        take_error(err);
        code
    });
    result.unwrap_or(-1)
}

/// `Qcore.engineFree(handle)`.
///
/// # Safety
/// Called by the JVM with a valid `JNIEnv`; never from any other caller.
#[no_mangle]
pub unsafe extern "system" fn Java_com_qcore_Qcore_engineFree(
    _env: JniEnv,
    _class: *mut c_void,
    handle: i64,
) {
    let _ = std::panic::catch_unwind(|| {
        // SAFETY: `handle` came from the JVM side holding a live engine;
        // `with_engine` documents the handle-validity contract.
        unsafe {
            with_engine(handle, |e| crate::qcore_engine_free(e));
        }
    });
}

/// `Qcore.scanJson(handle, transport, profile, family)` → ranked JSON or null.
///
/// # Safety
/// Called by the JVM with a valid `JNIEnv`; never from any other caller.
#[no_mangle]
pub unsafe extern "system" fn Java_com_qcore_Qcore_scanJson(
    env: JniEnv,
    _class: *mut c_void,
    handle: i64,
    transport: JString,
    profile: JString,
    family: JString,
) -> JString {
    let result = std::panic::catch_unwind(|| unsafe {
        call_c_abi(env, &[transport, profile, family], |args| {
            let mut out: *mut c_char = std::ptr::null_mut();
            let mut err: *mut crate::QcoreError = std::ptr::null_mut();
            let code = with_engine(handle, |e| {
                crate::qcore_scan(e, args[0], args[1], args[2], &mut out, &mut err)
            });
            (code, out, err)
        })
    });
    result.unwrap_or(std::ptr::null_mut())
}

/// `Qcore.importConfig(handle, path)` → `{"ref","format"}` JSON or null.
///
/// # Safety
/// Called by the JVM with a valid `JNIEnv`; never from any other caller.
#[no_mangle]
pub unsafe extern "system" fn Java_com_qcore_Qcore_importConfig(
    env: JniEnv,
    _class: *mut c_void,
    handle: i64,
    path: JString,
) -> JString {
    let result = std::panic::catch_unwind(|| unsafe {
        call_c_abi(env, &[path], |args| {
            let mut out: *mut c_char = std::ptr::null_mut();
            let mut err: *mut crate::QcoreError = std::ptr::null_mut();
            let code = with_engine(handle, |e| {
                crate::qcore_import_config(e, args[0], &mut out, &mut err)
            });
            (code, out, err)
        })
    });
    result.unwrap_or(std::ptr::null_mut())
}

/// `Qcore.exportConfig(handle, ref)` → redacted config text or null.
///
/// # Safety
/// Called by the JVM with a valid `JNIEnv`; never from any other caller.
#[no_mangle]
pub unsafe extern "system" fn Java_com_qcore_Qcore_exportConfig(
    env: JniEnv,
    _class: *mut c_void,
    handle: i64,
    import_ref: JString,
) -> JString {
    let result = std::panic::catch_unwind(|| unsafe {
        call_c_abi(env, &[import_ref], |args| {
            let mut out: *mut c_char = std::ptr::null_mut();
            let mut err: *mut crate::QcoreError = std::ptr::null_mut();
            let code = with_engine(handle, |e| {
                crate::qcore_export_config(e, args[0], &mut out, &mut err)
            });
            (code, out, err)
        })
    });
    result.unwrap_or(std::ptr::null_mut())
}
