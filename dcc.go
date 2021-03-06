// Package dcc Package provides dcc common code.
package dcc

// #cgo linux LDFLAGS: -ldl -Wl,--unresolved-symbols=ignore-in-object-files -L${SRCDIR}/ -l:libdccmj.a -L. -lpthread -lm -lresolv
// #cgo darwin LDFLAGS: -ldl -Wl,-undefined,dynamic_lookup -L${SRCDIR}/ -ldccmj -L. -lpthread -lm -lresolv
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
