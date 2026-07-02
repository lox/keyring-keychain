//go:build darwin && cgo

// Package sec provides cgo bindings to the parts of the macOS Security and
// LocalAuthentication frameworks used by the keychain provider: generic
// password items, legacy file-based keychains and ACLs, and Secure Enclave
// keys with biometric access control.
package sec

/*
#cgo CFLAGS: -x objective-c -Wno-deprecated-declarations
#cgo LDFLAGS: -framework CoreFoundation -framework Security -framework Foundation -framework LocalAuthentication
#include <CoreFoundation/CoreFoundation.h>

static void sec_dict_set(CFMutableDictionaryRef d, CFTypeRef key, CFTypeRef value) {
	CFDictionarySetValue(d, (const void *)key, (const void *)value);
}

static CFTypeRef sec_dict_get(CFDictionaryRef d, CFTypeRef key) {
	return (CFTypeRef)CFDictionaryGetValue(d, (const void *)key);
}
*/
import "C"

import (
	"bytes"
	"time"
	"unsafe"
)

func release(ref C.CFTypeRef) {
	if ref != 0 {
		C.CFRelease(ref)
	}
}

func cfString(s string) C.CFStringRef {
	b := []byte(s)
	var ptr *C.UInt8
	if len(b) > 0 {
		ptr = (*C.UInt8)(unsafe.Pointer(&b[0]))
	}
	return C.CFStringCreateWithBytes(C.kCFAllocatorDefault, ptr, C.CFIndex(len(b)), C.kCFStringEncodingUTF8, C.Boolean(0))
}

func goString(ref C.CFStringRef) string {
	if ref == 0 {
		return ""
	}
	length := C.CFStringGetLength(ref)
	if length == 0 {
		return ""
	}
	maxLen := C.CFStringGetMaximumSizeForEncoding(length, C.kCFStringEncodingUTF8) + 1
	buf := make([]byte, int(maxLen))
	if C.CFStringGetCString(ref, (*C.char)(unsafe.Pointer(&buf[0])), maxLen, C.kCFStringEncodingUTF8) == 0 {
		return ""
	}
	if i := bytes.IndexByte(buf, 0); i >= 0 {
		buf = buf[:i]
	}
	return string(buf)
}

func cfData(b []byte) C.CFDataRef {
	var ptr *C.UInt8
	if len(b) > 0 {
		ptr = (*C.UInt8)(unsafe.Pointer(&b[0]))
	}
	return C.CFDataCreate(C.kCFAllocatorDefault, ptr, C.CFIndex(len(b)))
}

func goData(ref C.CFDataRef) []byte {
	if ref == 0 {
		return nil
	}
	length := C.CFDataGetLength(ref)
	if length == 0 {
		return []byte{}
	}
	return C.GoBytes(unsafe.Pointer(C.CFDataGetBytePtr(ref)), C.int(length))
}

// goTime converts a CFDateRef to a time.Time. CFAbsoluteTime is seconds
// since 2001-01-01T00:00:00Z, which is 978307200 seconds after the Unix epoch.
func goTime(ref C.CFDateRef) time.Time {
	if ref == 0 {
		return time.Time{}
	}
	abs := float64(C.CFDateGetAbsoluteTime(ref))
	const cfEpochOffset = 978307200
	sec := int64(abs)
	nsec := int64((abs - float64(sec)) * 1e9)
	return time.Unix(sec+cfEpochOffset, nsec).UTC()
}

func newDict() C.CFMutableDictionaryRef {
	return C.CFDictionaryCreateMutable(C.kCFAllocatorDefault, 0, &C.kCFTypeDictionaryKeyCallBacks, &C.kCFTypeDictionaryValueCallBacks)
}

// dictSet stores value under key, releasing the value after the dictionary
// retains it. Both key and value must be CF types.
func dictSet(d C.CFMutableDictionaryRef, key C.CFTypeRef, value C.CFTypeRef) {
	C.sec_dict_set(d, key, value)
}

// dictSetOwned stores value under key and releases value (the dictionary
// holds its own retain).
func dictSetOwned(d C.CFMutableDictionaryRef, key C.CFTypeRef, value C.CFTypeRef) {
	dictSet(d, key, value)
	release(value)
}

func dictSetString(d C.CFMutableDictionaryRef, key C.CFTypeRef, value string) {
	dictSetOwned(d, key, C.CFTypeRef(cfString(value)))
}

func dictSetData(d C.CFMutableDictionaryRef, key C.CFTypeRef, value []byte) {
	dictSetOwned(d, key, C.CFTypeRef(cfData(value)))
}

func dictSetBool(d C.CFMutableDictionaryRef, key C.CFTypeRef, value bool) {
	v := C.kCFBooleanFalse
	if value {
		v = C.kCFBooleanTrue
	}
	dictSet(d, key, C.CFTypeRef(v))
}

func dictSetInt32(d C.CFMutableDictionaryRef, key C.CFTypeRef, value int32) {
	v := C.int(value)
	n := C.CFNumberCreate(C.kCFAllocatorDefault, C.kCFNumberIntType, unsafe.Pointer(&v))
	dictSetOwned(d, key, C.CFTypeRef(n))
}

// dictGet returns the value for key, or nil if absent. The returned ref is
// borrowed from the dictionary.
func dictGet(d C.CFDictionaryRef, key C.CFTypeRef) C.CFTypeRef {
	return C.sec_dict_get(d, key)
}

func dictGetString(d C.CFDictionaryRef, key C.CFTypeRef) string {
	ref := dictGet(d, key)
	if ref == 0 {
		return ""
	}
	return goString(C.CFStringRef(ref))
}
