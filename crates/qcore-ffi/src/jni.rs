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
//! String conversion uses JNI *modified UTF-8* on both sides: Rust → Java
//! re-encodes (NUL as `C0 80`, supplementary chars as CESU-8 surrogate
//! pairs) before `NewStringUTF`, and Java → Rust decodes that encoding back
//! to standard UTF-8. Standard UTF-8 passed raw corrupts emoji and other
//! non-BMP characters. Allocation failures surface as a null return with a
//! pending JVM exception — the JVM's own ExceptionCheck contract, which the
//! Java caller observes on return into managed code.
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

/// Convert standard UTF-8 to JNI *modified UTF-8* (the encoding
/// `NewStringUTF` actually expects): NUL becomes `C0 80`, and non-BMP
/// scalar values become CESU-8 surrogate pairs instead of 4-byte UTF-8.
/// Passing standard UTF-8 through raw corrupts emoji/supplementary
/// characters and would mis-encode interior NULs. Invalid sequences are
/// replaced (lossy) rather than panic — the JVM-visible string degrades
/// but the call never faults.
fn to_modified_utf8(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\0' => out.extend_from_slice(&[0xC0, 0x80]),
            '\u{1}'..='\u{7F}' => out.push(c as u8),
            c @ '\u{80}'..='\u{7FF}' => {
                out.push(0xC0 | (c as u32 >> 6) as u8);
                out.push(0x80 | (c as u32 & 0x3F) as u8);
            }
            c @ '\u{800}'..='\u{D7FF}' | c @ '\u{E000}'..='\u{FFFF}' => {
                out.push(0xE0 | (c as u32 >> 12) as u8);
                out.push(0x80 | ((c as u32 >> 6) & 0x3F) as u8);
                out.push(0x80 | (c as u32 & 0x3F) as u8);
            }
            c @ '\u{10000}'..='\u{10FFFF}' => {
                // CESU-8: encode the UTF-16 surrogate pair as two 3-byte
                // sequences. Supplementary chars are always valid pairs.
                let v = c as u32 - 0x1_0000;
                let high = 0xD800 + (v >> 10);
                let low = 0xDC00 + (v & 0x3FF);
                for unit in [high, low] {
                    out.push(0xE0 | (unit >> 12) as u8);
                    out.push(0x80 | ((unit >> 6) & 0x3F) as u8);
                    out.push(0x80 | (unit & 0x3F) as u8);
                }
            }
        }
    }
    out
}

/// Convert JNI modified UTF-8 (CESU-8 with `C0 80` for NUL) back to
/// standard UTF-8: re-joins surrogate pairs into scalar values and decodes
/// `C0 80` as NUL. Invalid sequences are replaced lossily.
fn from_modified_utf8(bytes: &[u8]) -> String {
    let mut units: Vec<u16> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        match b {
            0x00 => {
                // A real NUL byte cannot appear in C-string input, but
                // handle it defensively as U+0000.
                units.push(0);
                i += 1;
            }
            0x01..=0x7F => {
                units.push(b as u16);
                i += 1;
            }
            0xC0..=0xDF if i + 1 < bytes.len() && (bytes[i + 1] & 0xC0) == 0x80 => {
                units.push((((b & 0x1F) as u16) << 6) | (bytes[i + 1] & 0x3F) as u16);
                i += 2;
            }
            0xE0..=0xEF
                if i + 2 < bytes.len()
                    && (bytes[i + 1] & 0xC0) == 0x80
                    && (bytes[i + 2] & 0xC0) == 0x80 =>
            {
                units.push(
                    (((b & 0x0F) as u16) << 12)
                        | (((bytes[i + 1] & 0x3F) as u16) << 6)
                        | (bytes[i + 2] & 0x3F) as u16,
                );
                i += 3;
            }
            _ => {
                units.push(0xFFFD);
                i += 1;
            }
        }
    }
    String::from_utf16_lossy(&units)
}

/// Build a Java string from Rust text. Returns null when the table is
/// missing or the JVM cannot allocate (pending OOM exception — surfaced by
/// the JVM's ExceptionCheck on return into Java). Text is converted to JNI
/// modified UTF-8 first: `NewStringUTF` consumes that encoding, not
/// standard UTF-8 (supplementary chars / emoji corrupt otherwise).
unsafe fn rust_to_j(env: JniEnv, s: &str) -> JString {
    if env.is_null() || (*env).is_null() {
        return std::ptr::null_mut();
    }
    let mut bytes = to_modified_utf8(s);
    // SAFETY: same table-validity argument as `j_to_rust`; `bytes` is a
    // valid modified-UTF-8 buffer (never interior-NUL — the encoder maps
    // NUL to `C0 80`) and outlives the call, which reads it up to the
    // terminator it requires.
    bytes.push(0);
    ((&**env).new_string_utf)(env, bytes.as_ptr().cast::<c_char>())
}

/// Read a Java string into Rust. Returns `None` on null input, a null
/// table, a failed pin, or content that decodes to nothing. The pin is
/// always released before returning. The JVM hands back modified UTF-8
/// (CESU-8 + `C0 80`): it is decoded to standard UTF-8 here so emoji and
/// supplementary characters survive the round trip.
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
    let raw = CStr::from_ptr(chars).to_bytes();
    let out = if raw.is_ascii() {
        // Fast path: ASCII is identical in both encodings.
        Some(String::from_utf8_lossy(raw).into_owned())
    } else {
        Some(from_modified_utf8(raw))
    };
    (table.release_string_utf_chars)(env, s, chars);
    out
}

/// Reinterpret a handle integer as the engine pointer it came from.
/// Returns `None` for non-positive or non-live handles so callers fail
/// closed without dereferencing forged/stale pointers.
///
/// # Safety
/// A positive `handle` must be a live engine pointer previously produced
/// as `out as i64` by `engineNew` and not yet freed; anything else is
/// rejected before any pointer use.
unsafe fn with_engine<T>(handle: i64, f: impl FnOnce(*mut crate::QcoreEngine) -> T) -> Option<T> {
    if handle <= 0 {
        return None;
    }
    let ptr = handle as *mut crate::QcoreEngine;
    if !crate::handle_is_live(ptr) {
        return None;
    }
    // SAFETY: `ptr` is live per the check above.
    Some(f(ptr))
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
            // A non-null Java string that cannot be pinned or decoded is a
            // JVM input problem: fail closed (0), never silently fall back
            // to default config (same contract as `call_c_abi`).
            match j_to_rust(env, config_json) {
                Some(s) => Some(s),
                None => return 0,
            }
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
            })
            .unwrap_or(6);
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
            })
            .unwrap_or(6);
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
        // Fail closed on undecodable JVM input: null/pin-failure/non-UTF-8
        // never becomes empty input, and interior NULs never rewrite.
        let id = match j_to_rust(env, session_id) {
            Some(s) => s,
            None => return -1,
        };
        let id_c = match CString::new(id) {
            Ok(c) => c,
            Err(_) => return -1,
        };
        let mut err: *mut crate::QcoreError = std::ptr::null_mut();
        let code = match with_engine(handle, |e| {
            crate::qcore_engine_stop(e, id_c.as_ptr(), &mut err)
        }) {
            Some(c) => c,
            None => {
                take_error(err);
                return -1;
            }
        };
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
        // `with_engine` documents the handle-validity contract and rejects
        // non-positive handles before any pointer use.
        unsafe {
            let _ = with_engine(handle, |e| crate::qcore_engine_free(e));
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
            })
            .unwrap_or(6);
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
            })
            .unwrap_or(6);
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
            })
            .unwrap_or(6);
            (code, out, err)
        })
    });
    result.unwrap_or(std::ptr::null_mut())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Fake JVM table: pinning always fails (null chars), so `j_to_rust`
    // returns `None` for any non-null Java string.
    unsafe extern "system" fn failing_chars(
        _env: JniEnv,
        _s: JString,
        _is_copy: *mut u8,
    ) -> *const c_char {
        std::ptr::null()
    }

    unsafe extern "system" fn noop_release(_env: JniEnv, _s: JString, _chars: *const c_char) {}

    unsafe extern "system" fn null_new_string(_env: JniEnv, _bytes: *const c_char) -> JString {
        std::ptr::null_mut()
    }

    fn failing_table() -> JniTable {
        JniTable {
            _reserved_and_unused: [std::ptr::null(); 167],
            new_string_utf: null_new_string,
            _get_string_utf_length: std::ptr::null(),
            get_string_utf_chars: failing_chars,
            release_string_utf_chars: noop_release,
        }
    }

    #[test]
    fn engine_new_with_undecodable_config_fails_closed() {
        // A non-null Java string the JVM cannot pin/decode must yield
        // handle 0 (failure), never a default-config engine.
        let table = failing_table();
        let mut slot: *const JniTable = &table;
        let env: JniEnv = &mut slot as *mut *const JniTable;
        let bogus: JString = std::ptr::dangling_mut::<c_void>();
        let handle = unsafe { Java_com_qcore_Qcore_engineNew(env, std::ptr::null_mut(), bogus) };
        assert_eq!(
            handle, 0,
            "undecodable config must fail closed, not default"
        );
    }

    #[test]
    fn with_engine_rejects_non_positive_handles() {
        // SAFETY: non-positive probes never dereference; the closure is
        // unreachable for these inputs.
        assert!(unsafe { with_engine(0, |_| 1) }.is_none());
        assert!(unsafe { with_engine(-1, |_| 1) }.is_none());
        assert!(unsafe { with_engine(i64::MIN, |_| 1) }.is_none());
    }

    #[test]
    fn engine_stop_fails_closed_on_undecodable_session() {
        // Pin failure => `j_to_rust` None => -1, never empty-string dispatch.
        let table = failing_table();
        let mut slot: *const JniTable = &table;
        let env: JniEnv = &mut slot as *mut *const JniTable;
        let bogus: JString = std::ptr::dangling_mut::<c_void>();
        let rc = unsafe { Java_com_qcore_Qcore_engineStop(env, std::ptr::null_mut(), 1, bogus) };
        assert_eq!(rc, -1, "undecodable session must fail closed");
        // Non-positive handle also fails closed without touching the engine.
        let rc2 = unsafe { Java_com_qcore_Qcore_engineStop(env, std::ptr::null_mut(), 0, bogus) };
        assert_eq!(rc2, -1, "non-positive handle must fail closed");
    }

    #[test]
    fn modified_utf8_encodes_nul_and_bmp() {
        assert_eq!(to_modified_utf8("abc"), b"abc".to_vec());
        assert_eq!(to_modified_utf8("a\0b"), vec![b'a', 0xC0, 0x80, b'b']);
        assert_eq!(to_modified_utf8("é"), vec![0xC3, 0xA9]);
        // BMP astral-adjacent planes stay 3-byte CESU-8 (same as UTF-8).
        assert_eq!(to_modified_utf8("€"), vec![0xE2, 0x82, 0xAC]);
    }

    #[test]
    fn modified_utf8_encodes_supplementary_as_cesu8_pair() {
        // U+1F600 (😀): standard UTF-8 is 4 bytes; modified UTF-8 is the
        // surrogate pair D83D DE00 each 3-byte encoded. This is the defect
        // the fix removes: passing the 4-byte form to NewStringUTF corrupts
        // the Java string.
        let std_utf8 = "\u{1F600}".as_bytes();
        assert_eq!(std_utf8.len(), 4);
        let got = to_modified_utf8("\u{1F600}");
        assert_eq!(
            got,
            vec![0xED, 0xA0, 0xBD, 0xED, 0xB8, 0x80],
            "CESU-8 surrogate pair, not 4-byte UTF-8"
        );
    }

    #[test]
    fn modified_utf8_round_trips_supplementary_and_nul() {
        for s in [
            "plain ascii",
            "emoji \u{1F600} \u{1F9DF} path",
            "nul\u{0}inside",
            "mixed \u{10FFFF} top",
        ] {
            let decoded = from_modified_utf8(&to_modified_utf8(s));
            assert_eq!(decoded, s, "round trip of {s:?}");
        }
    }

    #[test]
    fn from_modified_utf8_joins_surrogate_pairs() {
        // The JVM-side encoding for 😀.
        let cesu = [0xED, 0xA0, 0xBD, 0xED, 0xB8, 0x80];
        assert_eq!(from_modified_utf8(&cesu), "\u{1F600}");
        // `C0 80` decodes to NUL.
        assert_eq!(from_modified_utf8(&[0xC0, 0x80]), "\0");
        // Invalid lead byte degrades to U+FFFD, never panics.
        assert_eq!(from_modified_utf8(&[0xFF]), "\u{FFFD}");
    }

    #[test]
    fn rust_to_j_passes_modified_utf8_to_new_string_utf() {
        // A recording JVM table: captures the bytes handed to NewStringUTF.
        static CAPTURED: std::sync::Mutex<Vec<u8>> = std::sync::Mutex::new(Vec::new());
        unsafe extern "system" fn recording_new_string(
            _env: JniEnv,
            bytes: *const c_char,
        ) -> JString {
            let c = unsafe { CStr::from_ptr(bytes) };
            CAPTURED.lock().unwrap().clear();
            CAPTURED.lock().unwrap().extend_from_slice(c.to_bytes());
            std::ptr::dangling_mut::<c_void>()
        }
        let table = JniTable {
            _reserved_and_unused: [std::ptr::null(); 167],
            new_string_utf: recording_new_string,
            _get_string_utf_length: std::ptr::null(),
            get_string_utf_chars: failing_chars,
            release_string_utf_chars: noop_release,
        };
        let mut slot: *const JniTable = &table;
        let env: JniEnv = &mut slot as *mut *const JniTable;
        let emoji = "\u{1F600}";
        let j = unsafe { rust_to_j(env, emoji) };
        assert!(!j.is_null(), "allocation stub returned a token");
        let captured = CAPTURED.lock().unwrap().clone();
        assert_eq!(
            captured,
            vec![0xED, 0xA0, 0xBD, 0xED, 0xB8, 0x80],
            "NewStringUTF receives modified UTF-8 (CESU-8), never 4-byte UTF-8"
        );
    }

    #[test]
    fn j_to_rust_decodes_cesu8_from_jvm() {
        // A fake JVM table whose pin hands back modified UTF-8 bytes.
        static CELLS: std::sync::Mutex<Vec<CString>> = std::sync::Mutex::new(Vec::new());
        unsafe extern "system" fn cesu_chars(
            _env: JniEnv,
            _s: JString,
            _is_copy: *mut u8,
        ) -> *const c_char {
            let cell = CString::new(vec![0xED, 0xA0, 0xBD, 0xED, 0xB8, 0x80]).unwrap();
            let ptr = cell.as_ptr();
            CELLS.lock().unwrap().push(cell);
            ptr
        }
        let table = JniTable {
            _reserved_and_unused: [std::ptr::null(); 167],
            new_string_utf: null_new_string,
            _get_string_utf_length: std::ptr::null(),
            get_string_utf_chars: cesu_chars,
            release_string_utf_chars: noop_release,
        };
        let mut slot: *const JniTable = &table;
        let env: JniEnv = &mut slot as *mut *const JniTable;
        let bogus: JString = std::ptr::dangling_mut::<c_void>();
        let got = unsafe { j_to_rust(env, bogus) };
        assert_eq!(
            got.as_deref(),
            Some("\u{1F600}"),
            "CESU-8 decodes to the emoji"
        );
    }
}
