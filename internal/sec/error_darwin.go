//go:build darwin && cgo

package sec

/*
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
*/
import "C"

import (
	"fmt"
)

// Error is a Security framework OSStatus result code.
type Error int32

// Result codes from Security/SecBase.h.
const (
	ErrUserCanceled          Error = -128   // errSecUserCanceled
	ErrNoAccessForItem       Error = -25243 // errSecNoAccessForItem
	ErrInvalidOwnerEdit      Error = -25244 // errSecInvalidOwnerEdit
	ErrAuthFailed            Error = -25293 // errSecAuthFailed
	ErrNoSuchKeychain        Error = -25294 // errSecNoSuchKeychain
	ErrDuplicateItem         Error = -25299 // errSecDuplicateItem
	ErrItemNotFound          Error = -25300 // errSecItemNotFound
	ErrInteractionNotAllowed Error = -25308 // errSecInteractionNotAllowed
	ErrMissingEntitlement    Error = -34018 // errSecMissingEntitlement
)

func (e Error) Error() string {
	msg := C.SecCopyErrorMessageString(C.OSStatus(e), nil)
	if msg == 0 {
		return fmt.Sprintf("OSStatus %d", int32(e))
	}
	defer release(C.CFTypeRef(msg))
	return fmt.Sprintf("OSStatus %d: %s", int32(e), goString(msg))
}

func checkStatus(status C.OSStatus) error {
	if status == C.errSecSuccess {
		return nil
	}
	return Error(status)
}

// CFError describes a CFErrorRef returned by Security or LocalAuthentication
// framework calls that report errors out-of-band from OSStatus.
type CFError struct {
	Domain      string
	Code        int
	Description string
}

func (e *CFError) Error() string {
	return fmt.Sprintf("%s error %d: %s", e.Domain, e.Code, e.Description)
}

func goCFError(ref C.CFErrorRef) error {
	if ref == 0 {
		return nil
	}
	defer release(C.CFTypeRef(ref))
	e := &CFError{Code: int(C.CFErrorGetCode(ref))}
	if domain := C.CFErrorGetDomain(ref); domain != 0 {
		e.Domain = goString(domain)
	}
	if desc := C.CFErrorCopyDescription(ref); desc != 0 {
		e.Description = goString(desc)
		release(C.CFTypeRef(desc))
	}
	return e
}

// IsUserCanceled reports whether err represents the user dismissing an
// authentication prompt.
func IsUserCanceled(err error) bool {
	if cfErr, ok := err.(*CFError); ok {
		// LAErrorUserCancel in the LocalAuthentication error domain, or
		// errSecUserCanceled surfaced through the OSStatus error domain.
		if cfErr.Domain == "com.apple.LocalAuthentication" && cfErr.Code == -2 {
			return true
		}
		if cfErr.Domain == "NSOSStatusErrorDomain" && cfErr.Code == int(ErrUserCanceled) {
			return true
		}
	}
	return err == ErrUserCanceled
}

// IsAuthFailed reports whether err represents a failed (not canceled)
// authentication attempt: rejected biometry or biometry lockout.
// Environment errors such as biometry-not-enrolled or passcode-not-set are
// not authentication failures and are reported as-is.
func IsAuthFailed(err error) bool {
	if cfErr, ok := err.(*CFError); ok {
		if cfErr.Domain == "com.apple.LocalAuthentication" {
			// LAErrorAuthenticationFailed (-1), LAErrorBiometryLockout (-8).
			return cfErr.Code == -1 || cfErr.Code == -8
		}
		return cfErr.Domain == "NSOSStatusErrorDomain" && cfErr.Code == int(ErrAuthFailed)
	}
	return err == ErrAuthFailed
}
