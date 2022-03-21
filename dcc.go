// Package dcc Package provides dcc common code.
package dcc

// #cgo CFLAGS: -g -Wno-unused-variable
// #cgo linux LDFLAGS: -ldl -Wl,--unresolved-symbols=ignore-all
// #cgo darwin LDFLAGS: -ldl -Wl,-undefined,dynamic_lookup
// #cgo LDFLAGS: -L${SRCDIR}/. -shared -lpthread -lm -lresolv -ldccmj
// #include <stdlib.h>
// #include <stdio.h>
// #include "dccmj.h"
import "C"      //nolint:depguard,gocritic // Required for calling c library
import "unsafe" //nolint:depguard,gocritic // Required for free the memory

//ChecksumGenerator generates dcc checksum
func ChecksumGenerator(html string) string {
	var checksum string
	input := C.CString(html)
	defer C.free(unsafe.Pointer(input))
	ptr := C.CString(checksum)
	defer C.free(unsafe.Pointer(ptr))
	C.fingerprint(input, ptr)
	return C.GoString(ptr)
}
