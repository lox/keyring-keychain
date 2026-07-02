//go:build darwin && cgo

package sec

/*
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
*/
import "C"

import (
	"unsafe"
)

// Keychain is a legacy file-based keychain (SecKeychainRef). The zero value
// is not usable; obtain one from OpenKeychain, CreateKeychain, or
// CreateKeychainWithPrompt, and Release it when done.
type Keychain struct {
	ref C.SecKeychainRef
}

// OpenKeychain opens a reference to the file-based keychain at path. Opening
// succeeds even if the file does not exist; use Status to check existence.
func OpenKeychain(path string) (*Keychain, error) {
	cpath := C.CString(path)
	defer C.free(unsafe.Pointer(cpath))

	var ref C.SecKeychainRef
	if err := checkStatus(C.SecKeychainOpen(cpath, &ref)); err != nil {
		return nil, err
	}
	return &Keychain{ref: ref}, nil
}

// Status returns nil if the keychain exists and is usable, or
// ErrNoSuchKeychain if the file does not exist.
func (k *Keychain) Status() error {
	var status C.SecKeychainStatus
	return checkStatus(C.SecKeychainGetStatus(k.ref, &status))
}

// CreateKeychain creates a new file-based keychain at path protected by
// password.
func CreateKeychain(path, password string) (*Keychain, error) {
	cpath := C.CString(path)
	defer C.free(unsafe.Pointer(cpath))
	cpassword := C.CString(password)
	defer C.free(unsafe.Pointer(cpassword))

	var ref C.SecKeychainRef
	err := checkStatus(C.SecKeychainCreate(cpath, C.UInt32(len(password)), unsafe.Pointer(cpassword), C.Boolean(0), 0, &ref))
	if err != nil {
		return nil, err
	}
	return &Keychain{ref: ref}, nil
}

// CreateKeychainWithPrompt creates a new file-based keychain at path,
// prompting the user for its password via the system dialog.
func CreateKeychainWithPrompt(path string) (*Keychain, error) {
	cpath := C.CString(path)
	defer C.free(unsafe.Pointer(cpath))

	var ref C.SecKeychainRef
	err := checkStatus(C.SecKeychainCreate(cpath, 0, nil, C.Boolean(1), 0, &ref))
	if err != nil {
		return nil, err
	}
	return &Keychain{ref: ref}, nil
}

// Release releases the underlying keychain reference.
func (k *Keychain) Release() {
	if k.ref != 0 {
		release(C.CFTypeRef(k.ref))
		k.ref = 0
	}
}

// Access describes a legacy file-based keychain ACL for a new item.
type Access struct {
	// Label is the ACL's descriptive label, shown in access prompts.
	Label string

	// TrustSelf, when true, trusts the calling application to access the
	// item without prompting. When false, every application (including the
	// creator) must be authorized by the user.
	TrustSelf bool
}

// create builds a SecAccessRef. The caller must release it.
func (a *Access) create() (C.SecAccessRef, error) {
	label := cfString(a.Label)
	defer release(C.CFTypeRef(label))

	// SecAccessCreate with a NULL trusted list trusts only the calling
	// application; an empty list trusts no applications.
	var trustedList C.CFArrayRef
	if !a.TrustSelf {
		trustedList = C.CFArrayCreate(C.kCFAllocatorDefault, nil, 0, &C.kCFTypeArrayCallBacks)
		defer release(C.CFTypeRef(trustedList))
	}

	var ref C.SecAccessRef
	if err := checkStatus(C.SecAccessCreate(label, trustedList, &ref)); err != nil {
		return 0, err
	}
	return ref, nil
}
