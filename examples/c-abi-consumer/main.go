// C ABI consumer (Go harness, T081, SC-002b): start a session, read its
// state, and stop it through the documented C ABI only (qcore.h), with no
// access to internal types. Offline against the mock transport.
//
// CI coverage (T7 story 23): exercised on Linux by the `go-consumer` job in
// `.github/workflows/ci.yml` (FFI release build + `go run .`). The Windows
// MSVC/MinGW link paths below are documented but NOT CI-gated; verify by
// hand after ABI or harness changes.
//
// Build (from the workspace root; requires a C toolchain for cgo):
//
//	cargo build -p qcore-ffi --release
//	cd examples/c-abi-consumer
//
// MSVC toolchain: link the staticlib directly:
//
//	set CGO_CFLAGS=-I../../crates/qcore-ffi
//	set CGO_LDFLAGS=-L../../target/release -lqcore_ffi -lws2_32 -luserenv -lbcrypt -lncrypt
//	go run .
//
// MinGW toolchain: the MSVC staticlib is not linkable by GNU ld; generate
// an import lib from the cdylib once and link that instead:
//
//	gendef ../../target/release/qcore_ffi.dll
//	dlltool --dllname qcore_ffi.dll --def qcore_ffi.def --output-lib libqcore_ffi_gnu.a
//	set CGO_LDFLAGS=-L. -lqcore_ffi_gnu -lws2_32 -luserenv -lbcrypt -lncrypt
//	go run .   (qcore_ffi.dll must sit next to the exe)
//
// On Linux replace the system libs with: -ldl -lm -lpthread.
package main

/*
#cgo CFLAGS: -I../../crates/qcore-ffi
// Link flags come from CGO_LDFLAGS in the environment (toolchain-specific;
// see the build notes above).
#include <stdlib.h>
#include "qcore.h"
*/
import "C"

import (
	"encoding/json"
	"fmt"
	"os"
	"unsafe"
)

func must(code C.int32_t, err *C.QcoreError, op string) {
	if code == 0 {
		return
	}
	msg := ""
	if err != nil && err.message != nil {
		msg = C.GoString(err.message)
		C.qcore_error_free(err)
	}
	fmt.Fprintf(os.Stderr, "c-abi-consumer: %s failed (code %d): %s\n", op, int32(code), msg)
	os.Exit(1)
}

func takeString(p *C.char) string {
	if p == nil {
		fmt.Fprintln(os.Stderr, "c-abi-consumer: ABI returned null string")
		os.Exit(1)
	}
	s := C.GoString(p)
	C.qcore_string_free(p)
	return s
}

func main() {
	chain := "mock"
	if len(os.Args) > 1 {
		chain = os.Args[1]
	}

	if v := C.qcore_abi_version(); v != 1 {
		fmt.Fprintf(os.Stderr, "c-abi-consumer: unexpected ABI version %d\n", uint32(v))
		os.Exit(1)
	}
	fmt.Println("abi_version=1")

	cfg := C.CString(`{"family":"dual","timeout_secs":30}`)
	defer C.free(unsafe.Pointer(cfg))
	var engine *C.QcoreEngine
	var err *C.QcoreError
	must(C.qcore_engine_new(cfg, &engine, &err), err, "engine_new")
	defer C.qcore_engine_free(engine)

	cChain := C.CString(chain)
	defer C.free(unsafe.Pointer(cChain))
	var sess *C.char
	must(C.qcore_engine_start(engine, cChain, &sess, &err), err, "engine_start")
	sessionID := takeString(sess)
	fmt.Println("session=" + sessionID)

	cID := C.CString(sessionID)
	defer C.free(unsafe.Pointer(cID))
	var status *C.char
	must(C.qcore_engine_status_json(engine, cID, &status, &err), err, "engine_status_json")
	doc := takeString(status)
	var report struct {
		ExitHopID string `json:"exit_hop_id"`
		Ordered   []struct {
			HopID string `json:"hop_id"`
		} `json:"ordered_chain"`
	}
	if e := json.Unmarshal([]byte(doc), &report); e != nil {
		fmt.Fprintln(os.Stderr, "c-abi-consumer: status is not JSON:", e)
		os.Exit(1)
	}
	fmt.Println("exit=" + report.ExitHopID)
	if len(report.Ordered) == 0 {
		fmt.Fprintln(os.Stderr, "c-abi-consumer: empty ordered chain")
		os.Exit(1)
	}

	must(C.qcore_engine_stop(engine, cID, &err), err, "engine_stop")
	fmt.Println("c-abi-consumer ok")
}
