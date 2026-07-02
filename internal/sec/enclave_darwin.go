//go:build darwin && cgo

package sec

/*
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>

static void *sec_new_lacontext(const char *reason) {
	LAContext *ctx = [[LAContext alloc] init];
	if (reason != NULL && reason[0] != '\0') {
		ctx.localizedReason = [NSString stringWithUTF8String:reason];
	}
	return ctx;
}

static void sec_release_lacontext(void *ctx) {
	[(LAContext *)ctx release];
}

static int sec_biometry_available(void) {
	LAContext *ctx = [[LAContext alloc] init];
	BOOL ok = [ctx canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:nil];
	[ctx release];
	return ok ? 1 : 0;
}
*/
import "C"

import (
	"errors"
	"unsafe"
)

// tokenOIDAttr is the kSecAttrTokenOID attribute key ("toid"): the opaque
// token object ID that identifies a Secure Enclave key. It is the same blob
// CryptoKit persists as a Secure Enclave key's dataRepresentation. The
// constant is not exposed in the public SDK headers, but is defined and
// stable in the open source Security framework (SecItemConstants.c).
const tokenOIDAttr = "toid"

// AccessControlPolicy selects the user authentication required to use a
// Secure Enclave key.
type AccessControlPolicy int

const (
	// PolicyUserPresence allows biometry or the account password.
	PolicyUserPresence AccessControlPolicy = iota
	// PolicyBiometryAny requires any enrolled biometry.
	PolicyBiometryAny
	// PolicyBiometryCurrentSet requires biometry as enrolled at key
	// creation time; re-enrolling invalidates the key.
	PolicyBiometryCurrentSet
)

// AuthContext wraps an LAContext used to authenticate Secure Enclave key
// operations. Reusing one context across operations lets the system cache a
// successful authentication instead of prompting for every operation.
type AuthContext struct {
	ptr unsafe.Pointer
}

// NewAuthContext creates an authentication context. The reason is shown in
// the system authentication prompt ("<app> is trying to <reason>").
func NewAuthContext(reason string) *AuthContext {
	creason := C.CString(reason)
	defer C.free(unsafe.Pointer(creason))
	return &AuthContext{ptr: C.sec_new_lacontext(creason)}
}

// Close releases the underlying LAContext.
func (c *AuthContext) Close() {
	if c.ptr != nil {
		C.sec_release_lacontext(c.ptr)
		c.ptr = nil
	}
}

// BiometryAvailable reports whether the device can authenticate with
// biometrics (e.g. Touch ID with an enrolled fingerprint).
func BiometryAvailable() bool {
	return C.sec_biometry_available() == 1
}

// tokenKeyAttrs builds the attribute dictionary shared by Secure Enclave key
// load operations. The caller must release the returned dictionary.
func tokenKeyAttrs() C.CFMutableDictionaryRef {
	d := newDict()
	dictSet(d, C.CFTypeRef(C.kSecAttrTokenID), C.CFTypeRef(C.kSecAttrTokenIDSecureEnclave))
	dictSet(d, C.CFTypeRef(C.kSecAttrKeyType), C.CFTypeRef(C.kSecAttrKeyTypeECSECPrimeRandom))
	return d
}

// CreateSecureEnclaveKeyBlob generates a new P-256 key inside the Secure
// Enclave, protected by the given policy, and returns its opaque encrypted
// representation. The key is not persisted anywhere: the blob is the only
// handle to it, and it is only usable by this device's Secure Enclave.
func CreateSecureEnclaveKeyBlob(policy AccessControlPolicy) ([]byte, error) {
	flags := C.SecAccessControlCreateFlags(C.kSecAccessControlPrivateKeyUsage)
	switch policy {
	case PolicyUserPresence:
		flags |= C.SecAccessControlCreateFlags(C.kSecAccessControlUserPresence)
	case PolicyBiometryAny:
		flags |= C.SecAccessControlCreateFlags(C.kSecAccessControlBiometryAny)
	case PolicyBiometryCurrentSet:
		flags |= C.SecAccessControlCreateFlags(C.kSecAccessControlBiometryCurrentSet)
	default:
		return nil, errors.New("sec: unknown access control policy")
	}

	var cfErr C.CFErrorRef
	accessControl := C.SecAccessControlCreateWithFlags(C.kCFAllocatorDefault,
		C.CFTypeRef(C.kSecAttrAccessibleWhenUnlockedThisDeviceOnly), flags, &cfErr)
	if accessControl == 0 {
		return nil, goCFError(cfErr)
	}
	defer release(C.CFTypeRef(accessControl))

	privAttrs := newDict()
	defer release(C.CFTypeRef(privAttrs))
	dictSetBool(privAttrs, C.CFTypeRef(C.kSecAttrIsPermanent), false)
	dictSet(privAttrs, C.CFTypeRef(C.kSecAttrAccessControl), C.CFTypeRef(accessControl))

	attrs := tokenKeyAttrs()
	defer release(C.CFTypeRef(attrs))
	dictSetInt32(attrs, C.CFTypeRef(C.kSecAttrKeySizeInBits), 256)
	dictSet(attrs, C.CFTypeRef(C.kSecPrivateKeyAttrs), C.CFTypeRef(privAttrs))

	key := C.SecKeyCreateRandomKey(C.CFDictionaryRef(attrs), &cfErr)
	if key == 0 {
		return nil, goCFError(cfErr)
	}
	defer release(C.CFTypeRef(key))

	// The key's opaque data representation is exposed as the token OID
	// attribute ("toid"), the same blob CryptoKit persists as a Secure
	// Enclave key's dataRepresentation.
	keyAttrs := C.SecKeyCopyAttributes(key)
	if keyAttrs == 0 {
		return nil, errors.New("sec: SecKeyCopyAttributes returned nil")
	}
	defer release(C.CFTypeRef(keyAttrs))

	tokenOID := cfString(tokenOIDAttr)
	defer release(C.CFTypeRef(tokenOID))
	blobRef := dictGet(keyAttrs, C.CFTypeRef(tokenOID))
	if blobRef == 0 {
		return nil, errors.New("sec: Secure Enclave key has no data representation")
	}
	return goData(C.CFDataRef(blobRef)), nil
}

// loadSecureEnclaveKey reconstitutes a Secure Enclave key from its opaque
// blob. The caller must release the returned key.
//
// The blob must be passed as the token object ID attribute
// (kSecAttrTokenOID, "toid"): when kSecAttrTokenID is present,
// SecKeyCreateWithData ignores its data parameter and looks up the token
// object by kSecAttrTokenOID; omitting it would silently generate a fresh
// key instead (see SecCTKKey initWithAttributes in apple-oss Security).
func loadSecureEnclaveKey(blob []byte, auth *AuthContext) (C.SecKeyRef, error) {
	attrs := tokenKeyAttrs()
	defer release(C.CFTypeRef(attrs))
	dictSet(attrs, C.CFTypeRef(C.kSecAttrKeyClass), C.CFTypeRef(C.kSecAttrKeyClassPrivate))
	oidKey := cfString(tokenOIDAttr)
	defer release(C.CFTypeRef(oidKey))
	dictSetData(attrs, C.CFTypeRef(oidKey), blob)
	if auth != nil && auth.ptr != nil {
		dictSet(attrs, C.CFTypeRef(C.kSecUseAuthenticationContext), C.CFTypeRef(auth.ptr))
	}

	data := cfData(blob)
	defer release(C.CFTypeRef(data))

	var cfErr C.CFErrorRef
	key := C.SecKeyCreateWithData(data, C.CFDictionaryRef(attrs), &cfErr)
	if key == 0 {
		return 0, goCFError(cfErr)
	}
	return key, nil
}

// SecureEnclavePublicKey returns the X9.63 representation of the public key
// for the Secure Enclave key identified by blob. Loading the same blob must
// always yield the same public key.
func SecureEnclavePublicKey(blob []byte) ([]byte, error) {
	key, err := loadSecureEnclaveKey(blob, nil)
	if err != nil {
		return nil, err
	}
	defer release(C.CFTypeRef(key))

	pub := C.SecKeyCopyPublicKey(key)
	if pub == 0 {
		return nil, errors.New("sec: SecKeyCopyPublicKey returned nil")
	}
	defer release(C.CFTypeRef(pub))

	var cfErr C.CFErrorRef
	data := C.SecKeyCopyExternalRepresentation(pub, &cfErr)
	if data == 0 {
		return nil, goCFError(cfErr)
	}
	defer release(C.CFTypeRef(data))
	return goData(data), nil
}

// SecureEnclaveEncrypt encrypts plaintext to the Secure Enclave key
// identified by blob using ECIES. Encryption uses the public key and
// requires no user authentication.
func SecureEnclaveEncrypt(blob, plaintext []byte) ([]byte, error) {
	key, err := loadSecureEnclaveKey(blob, nil)
	if err != nil {
		return nil, err
	}
	defer release(C.CFTypeRef(key))

	pub := C.SecKeyCopyPublicKey(key)
	if pub == 0 {
		return nil, errors.New("sec: SecKeyCopyPublicKey returned nil")
	}
	defer release(C.CFTypeRef(pub))

	data := cfData(plaintext)
	defer release(C.CFTypeRef(data))

	var cfErr C.CFErrorRef
	ciphertext := C.SecKeyCreateEncryptedData(pub, C.kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM, data, &cfErr)
	if ciphertext == 0 {
		return nil, goCFError(cfErr)
	}
	defer release(C.CFTypeRef(ciphertext))
	return goData(ciphertext), nil
}

// SecureEnclaveDecrypt decrypts ciphertext with the Secure Enclave key
// identified by blob. This triggers the system authentication prompt
// (Touch ID or password, per the key's policy). A nil auth context uses a
// fresh authentication for this operation.
func SecureEnclaveDecrypt(blob, ciphertext []byte, auth *AuthContext) ([]byte, error) {
	key, err := loadSecureEnclaveKey(blob, auth)
	if err != nil {
		return nil, err
	}
	defer release(C.CFTypeRef(key))

	data := cfData(ciphertext)
	defer release(C.CFTypeRef(data))

	var cfErr C.CFErrorRef
	plaintext := C.SecKeyCreateDecryptedData(key, C.kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM, data, &cfErr)
	if plaintext == 0 {
		return nil, goCFError(cfErr)
	}
	defer release(C.CFTypeRef(plaintext))
	return goData(plaintext), nil
}
