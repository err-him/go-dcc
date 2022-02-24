// Package dcc Package provides dcc common code.
package dcc

// #cgo CFLAGS: -g -Wall
// #cgo LDFLAGS: -L${SRCDIR}/. -ldcc -lm -lresolv
// #include <stdlib.h>
// #include <stdio.h>
// #include "dccmj.h"
import "C"      //nolint:typecheck // Required for calling c library
import "unsafe" //nolint:depguard // Required for free the memory

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
