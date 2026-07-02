//go:build darwin && cgo

package keychain

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework CoreFoundation -framework Foundation -framework LocalAuthentication -framework Security

#include <CoreFoundation/CoreFoundation.h>
#include <Foundation/Foundation.h>
#include <LocalAuthentication/LocalAuthentication.h>
#include <Security/Security.h>

static void keychainDictSet(CFMutableDictionaryRef dict, CFTypeRef key, CFTypeRef value) {
	CFDictionarySetValue(dict, key, value);
}

static CFTypeRef keychainDictGet(CFDictionaryRef dict, CFTypeRef key) {
	return (CFTypeRef)CFDictionaryGetValue(dict, key);
}

static CFTypeRef keychainArrayGet(CFArrayRef array, CFIndex index) {
	return (CFTypeRef)CFArrayGetValueAtIndex(array, index);
}

typedef void* KeychainLAContextRef;

static KeychainLAContextRef keychainCreateLAContext(double reuseDuration) {
	LAContext *context = [[LAContext alloc] init];
	if (reuseDuration > 0) {
		context.touchIDAuthenticationAllowableReuseDuration = reuseDuration;
	}
	return (KeychainLAContextRef)context;
}

static void keychainReleaseLAContext(KeychainLAContextRef context) {
	[(LAContext *)context release];
}

static void keychainDictSetLAContext(CFMutableDictionaryRef dict, KeychainLAContextRef context) {
	CFDictionarySetValue(dict, kSecUseAuthenticationContext, (LAContext *)context);
}

static SecAccessControlRef keychainCreateAccessControl(CFTypeRef accessible, SecAccessControlCreateFlags flags, CFErrorRef *err) {
	return SecAccessControlCreateWithFlags(kCFAllocatorDefault, accessible, flags, err);
}
*/
import "C"

import (
	"errors"
	"fmt"
	"math"
	"sync"
	"time"
	"unicode/utf8"
	"unsafe"

	"github.com/lox/keyring/v2"
)

type dataProtectionKeychain struct {
	service                  string
	isAccessibleWhenUnlocked bool
	accessControl            dataProtectionAccessControl
	authContext              C.KeychainLAContextRef
	closeOnce                sync.Once
}

type keychainStatusError int32

const errSecMissingEntitlementStatus int32 = -34018

func openDataProtectionKeychain(cfg Config) (backendKeyring, error) {
	if err := validateDataProtectionConfig(cfg); err != nil {
		return nil, err
	}

	k := &dataProtectionKeychain{
		service:                  cfg.ServiceName,
		isAccessibleWhenUnlocked: cfg.KeychainAccessibleWhenUnlocked,
		accessControl:            cfg.keychainAccessControl,
	}
	if cfg.keychainAuthenticationReuse > 0 {
		k.authContext = C.keychainCreateLAContext(C.double(cfg.keychainAuthenticationReuse.Seconds()))
	}
	return k, nil
}

func (k *dataProtectionKeychain) Get(key string) (Item, error) {
	query, err := k.newAccountQuery(key)
	if err != nil {
		return Item{}, err
	}
	defer query.release()

	query.setMatchLimit(C.CFTypeRef(C.kSecMatchLimitOne))
	query.setBool(C.CFTypeRef(C.kSecReturnAttributes), true)
	query.setBool(C.CFTypeRef(C.kSecReturnData), true)
	k.setAuthenticationContext(query)

	debugf("Querying data protection keychain for service=%q, account=%q", k.service, key)
	result, err := secItemCopyMatching(query)
	if err != nil {
		return Item{}, err
	}
	defer cfRelease(result)

	return itemFromResult(result, key)
}

func (k *dataProtectionKeychain) GetMetadata(key string) (Metadata, error) {
	query, err := k.newAccountQuery(key)
	if err != nil {
		return Metadata{}, err
	}
	defer query.release()

	query.setMatchLimit(C.CFTypeRef(C.kSecMatchLimitOne))
	query.setBool(C.CFTypeRef(C.kSecReturnAttributes), true)

	debugf("Querying data protection keychain metadata for service=%q, account=%q", k.service, key)
	result, err := secItemCopyMatching(query)
	if err != nil {
		return Metadata{}, err
	}
	defer cfRelease(result)

	item, modified, err := metadataFromResult(result, key)
	if err != nil {
		return Metadata{}, err
	}
	return Metadata{Item: &item, ModificationTime: modified}, nil
}

func (k *dataProtectionKeychain) Set(item Item) error {
	add, err := k.newAccountQuery(item.Key)
	if err != nil {
		return err
	}
	defer add.release()

	if err := add.setOptionalString(C.CFTypeRef(C.kSecAttrLabel), item.Label); err != nil {
		return err
	}
	if err := add.setOptionalString(C.CFTypeRef(C.kSecAttrDescription), item.Description); err != nil {
		return err
	}
	if err := add.setData(C.CFTypeRef(C.kSecValueData), item.Data); err != nil {
		return err
	}
	if err := k.setProtection(add); err != nil {
		return err
	}

	debugf("Adding data protection keychain item service=%q, label=%q, account=%q", k.service, item.Label, item.Key)
	err = checkKeychainStatus(C.SecItemAdd(C.CFDictionaryRef(add.ref), nil))
	if errors.Is(err, ErrKeyNotFound) {
		return ErrKeyNotFound
	}
	if errors.Is(err, errKeychainDuplicateItem) {
		debugf("Item already exists, updating data protection keychain item service=%q, account=%q", k.service, item.Key)
		return k.updateItem(item)
	}
	return err
}

func (k *dataProtectionKeychain) Remove(key string) error {
	query, err := k.newAccountQuery(key)
	if err != nil {
		return err
	}
	defer query.release()
	k.setAuthenticationContext(query)

	debugf("Removing data protection keychain item service=%q, account=%q", k.service, key)
	return checkKeychainStatus(C.SecItemDelete(C.CFDictionaryRef(query.ref)))
}

func (k *dataProtectionKeychain) Keys() ([]string, error) {
	query, err := k.newQuery()
	if err != nil {
		return nil, err
	}
	defer query.release()

	query.setMatchLimit(C.CFTypeRef(C.kSecMatchLimitAll))
	query.setBool(C.CFTypeRef(C.kSecReturnAttributes), true)

	debugf("Querying data protection keychain keys for service=%q", k.service)
	result, err := secItemCopyMatching(query)
	if errors.Is(err, ErrKeyNotFound) {
		return []string{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer cfRelease(result)

	return accountsFromResult(result)
}

func (k *dataProtectionKeychain) Close() error {
	k.closeOnce.Do(func() {
		if k.authContext != nil {
			C.keychainReleaseLAContext(k.authContext)
			k.authContext = nil
		}
	})
	return nil
}

func (k *dataProtectionKeychain) updateItem(item Item) error {
	query, err := k.newAccountQuery(item.Key)
	if err != nil {
		return err
	}
	defer query.release()
	k.setAuthenticationContext(query)

	update, err := newSecDict()
	if err != nil {
		return err
	}
	defer update.release()

	if err := update.setData(C.CFTypeRef(C.kSecValueData), item.Data); err != nil {
		return err
	}
	if k.accessControl == dataProtectionAccessControlNone {
		if err := update.setOptionalString(C.CFTypeRef(C.kSecAttrLabel), item.Label); err != nil {
			return err
		}
		if err := update.setOptionalString(C.CFTypeRef(C.kSecAttrDescription), item.Description); err != nil {
			return err
		}
	}

	return checkKeychainStatus(C.SecItemUpdate(C.CFDictionaryRef(query.ref), C.CFDictionaryRef(update.ref)))
}

func (k *dataProtectionKeychain) newQuery() (secDict, error) {
	query, err := newSecDict()
	if err != nil {
		return secDict{}, err
	}
	query.setValue(C.CFTypeRef(C.kSecClass), C.CFTypeRef(C.kSecClassGenericPassword))
	if err := query.setString(C.CFTypeRef(C.kSecAttrService), k.service); err != nil {
		query.release()
		return secDict{}, err
	}
	query.setBool(C.CFTypeRef(C.kSecUseDataProtectionKeychain), true)
	return query, nil
}

func (k *dataProtectionKeychain) newAccountQuery(key string) (secDict, error) {
	query, err := k.newQuery()
	if err != nil {
		return secDict{}, err
	}
	if err := query.setString(C.CFTypeRef(C.kSecAttrAccount), key); err != nil {
		query.release()
		return secDict{}, err
	}
	return query, nil
}

func (k *dataProtectionKeychain) setProtection(item secDict) error {
	if k.accessControl != dataProtectionAccessControlNone {
		return item.setAccessControl(k.accessControl)
	}
	if k.isAccessibleWhenUnlocked {
		item.setValue(C.CFTypeRef(C.kSecAttrAccessible), C.CFTypeRef(C.kSecAttrAccessibleWhenUnlocked))
	}
	return nil
}

func (k *dataProtectionKeychain) setAuthenticationContext(query secDict) {
	if k.authContext != nil {
		C.keychainDictSetLAContext(query.ref, k.authContext)
	}
}

type secDict struct {
	ref C.CFMutableDictionaryRef
}

func newSecDict() (secDict, error) {
	ref := C.CFDictionaryCreateMutable(
		C.kCFAllocatorDefault,
		0,
		&C.kCFTypeDictionaryKeyCallBacks,
		&C.kCFTypeDictionaryValueCallBacks, //nolint:gocritic
	)
	if ref == 0 {
		return secDict{}, errors.New("create keychain query")
	}
	return secDict{ref: ref}, nil
}

func (d secDict) release() {
	cfRelease(C.CFTypeRef(d.ref))
}

func (d secDict) setValue(key C.CFTypeRef, value C.CFTypeRef) {
	C.keychainDictSet(d.ref, key, value)
}

func (d secDict) setBool(key C.CFTypeRef, value bool) {
	if value {
		d.setValue(key, C.CFTypeRef(C.kCFBooleanTrue))
		return
	}
	d.setValue(key, C.CFTypeRef(C.kCFBooleanFalse))
}

func (d secDict) setMatchLimit(limit C.CFTypeRef) {
	d.setValue(C.CFTypeRef(C.kSecMatchLimit), limit)
}

func (d secDict) setString(key C.CFTypeRef, value string) error {
	ref, err := cfString(value)
	if err != nil {
		return err
	}
	defer cfRelease(C.CFTypeRef(ref))
	d.setValue(key, C.CFTypeRef(ref))
	return nil
}

func (d secDict) setOptionalString(key C.CFTypeRef, value string) error {
	if value == "" {
		return nil
	}
	return d.setString(key, value)
}

func (d secDict) setData(key C.CFTypeRef, value []byte) error {
	ref, err := cfData(value)
	if err != nil {
		return err
	}
	defer cfRelease(C.CFTypeRef(ref))
	d.setValue(key, C.CFTypeRef(ref))
	return nil
}

func (d secDict) setAccessControl(accessControl dataProtectionAccessControl) error {
	var cfErr C.CFErrorRef
	ref := C.keychainCreateAccessControl(
		C.CFTypeRef(C.kSecAttrAccessibleWhenUnlockedThisDeviceOnly),
		accessControl.secAccessControlFlags(),
		&cfErr, //nolint:gocritic
	)
	if ref == 0 {
		message := cfErrorString(cfErr)
		cfRelease(C.CFTypeRef(cfErr))
		return fmt.Errorf("%w: create access control: %v", keyring.ErrInvalidOption, message)
	}
	defer cfRelease(C.CFTypeRef(ref))

	d.setValue(C.CFTypeRef(C.kSecAttrAccessControl), C.CFTypeRef(ref))
	return nil
}

func (a dataProtectionAccessControl) secAccessControlFlags() C.SecAccessControlCreateFlags {
	switch a {
	case dataProtectionAccessControlNone:
		return 0
	case dataProtectionAccessControlUserPresence:
		return C.kSecAccessControlUserPresence
	case dataProtectionAccessControlBiometryCurrentSet:
		return C.kSecAccessControlBiometryCurrentSet
	default:
		return 0
	}
}

func secItemCopyMatching(query secDict) (C.CFTypeRef, error) {
	var result C.CFTypeRef
	status := C.SecItemCopyMatching(C.CFDictionaryRef(query.ref), &result) //nolint:gocritic
	if err := checkKeychainStatus(status); err != nil {
		return 0, err
	}
	return result, nil
}

var errKeychainDuplicateItem = errors.New("keychain duplicate item")

func checkKeychainStatus(status C.OSStatus) error {
	switch int32(status) {
	case int32(C.errSecSuccess):
		return nil
	case int32(C.errSecItemNotFound):
		return ErrKeyNotFound
	case int32(C.errSecDuplicateItem):
		return errKeychainDuplicateItem
	case errSecMissingEntitlementStatus:
		return fmt.Errorf("%w: data protection keychain requires a signed app with keychain-access-groups entitlement", ErrAccessDenied)
	}

	err := keychainStatusError(status)
	if isAccessDeniedStatus(status) {
		return fmt.Errorf("%w: %w", ErrAccessDenied, err)
	}
	return err
}

func isAccessDeniedStatus(status C.OSStatus) bool {
	switch int32(status) {
	case -128, -25244, errSecMissingEntitlementStatus, int32(C.errSecAuthFailed), int32(C.errSecInteractionNotAllowed), int32(C.errSecNoAccessForItem):
		return true
	default:
		return false
	}
}

func (s keychainStatusError) Error() string {
	return fmt.Sprintf("keychain status %d", int32(s))
}

func itemFromResult(result C.CFTypeRef, key string) (Item, error) {
	if C.CFGetTypeID(result) != C.CFDictionaryGetTypeID() {
		return Item{}, fmt.Errorf("unexpected keychain result type: %s", cfTypeDescription(result))
	}

	item, _, err := itemFromDict(C.CFDictionaryRef(result), key)
	return item, err
}

func metadataFromResult(result C.CFTypeRef, key string) (Item, time.Time, error) {
	if C.CFGetTypeID(result) != C.CFDictionaryGetTypeID() {
		return Item{}, time.Time{}, fmt.Errorf("unexpected keychain result type: %s", cfTypeDescription(result))
	}
	return itemFromDict(C.CFDictionaryRef(result), key)
}

func itemFromDict(dict C.CFDictionaryRef, key string) (Item, time.Time, error) {
	item := Item{Key: key}
	if account, ok := dictString(dict, C.CFTypeRef(C.kSecAttrAccount)); ok && key == "" {
		item.Key = account
	}
	if label, ok := dictString(dict, C.CFTypeRef(C.kSecAttrLabel)); ok {
		item.Label = label
	}
	if description, ok := dictString(dict, C.CFTypeRef(C.kSecAttrDescription)); ok {
		item.Description = description
	}
	if data, ok, err := dictData(dict, C.CFTypeRef(C.kSecValueData)); ok || err != nil {
		if err != nil {
			return Item{}, time.Time{}, err
		}
		item.Data = data
	}
	modified := time.Time{}
	if ref := C.keychainDictGet(dict, C.CFTypeRef(C.kSecAttrModificationDate)); ref != 0 {
		modified = cfDateToTime(ref)
	}
	return item, modified, nil
}

func accountsFromResult(result C.CFTypeRef) ([]string, error) {
	seen := map[string]struct{}{}
	accounts := []string{}

	switch C.CFGetTypeID(result) {
	case C.CFArrayGetTypeID():
		array := C.CFArrayRef(result)
		count := C.CFArrayGetCount(array)
		for i := C.CFIndex(0); i < count; i++ {
			if err := appendAccount(&accounts, seen, C.keychainArrayGet(array, i)); err != nil {
				return nil, err
			}
		}
	case C.CFDictionaryGetTypeID():
		if err := appendAccount(&accounts, seen, result); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unexpected keychain result type: %s", cfTypeDescription(result))
	}

	return accounts, nil
}

func appendAccount(accounts *[]string, seen map[string]struct{}, result C.CFTypeRef) error {
	if C.CFGetTypeID(result) != C.CFDictionaryGetTypeID() {
		return fmt.Errorf("unexpected keychain result type: %s", cfTypeDescription(result))
	}

	account, ok := dictString(C.CFDictionaryRef(result), C.CFTypeRef(C.kSecAttrAccount))
	if !ok {
		return nil
	}
	if _, ok := seen[account]; ok {
		return nil
	}
	seen[account] = struct{}{}
	*accounts = append(*accounts, account)
	return nil
}

func dictString(dict C.CFDictionaryRef, key C.CFTypeRef) (string, bool) {
	ref := C.keychainDictGet(dict, key)
	if ref == 0 {
		return "", false
	}
	return cfStringToString(C.CFStringRef(ref)), true
}

func dictData(dict C.CFDictionaryRef, key C.CFTypeRef) ([]byte, bool, error) {
	ref := C.keychainDictGet(dict, key)
	if ref == 0 {
		return nil, false, nil
	}
	if C.CFGetTypeID(ref) != C.CFDataGetTypeID() {
		return nil, false, fmt.Errorf("unexpected keychain data type: %s", cfTypeDescription(ref))
	}
	return cfDataToBytes(C.CFDataRef(ref)), true, nil
}

func cfString(value string) (C.CFStringRef, error) {
	if !utf8.ValidString(value) {
		return 0, errors.New("invalid UTF-8 string")
	}
	bytes := []byte(value)
	var ptr *C.UInt8
	if len(bytes) > 0 {
		ptr = (*C.UInt8)(unsafe.Pointer(&bytes[0]))
	}
	ref := C.CFStringCreateWithBytes(C.kCFAllocatorDefault, ptr, C.CFIndex(len(bytes)), C.kCFStringEncodingUTF8, C.false)
	if ref == 0 {
		return 0, errors.New("create CFString")
	}
	return ref, nil
}

func cfStringToString(ref C.CFStringRef) string {
	if ref == 0 {
		return ""
	}
	ptr := C.CFStringGetCStringPtr(ref, C.kCFStringEncodingUTF8)
	if ptr != nil {
		return C.GoString(ptr)
	}

	length := C.CFStringGetLength(ref)
	if length == 0 {
		return ""
	}
	maxLength := C.CFStringGetMaximumSizeForEncoding(length, C.kCFStringEncodingUTF8) + 1
	buffer := make([]byte, int(maxLength))
	ok := C.CFStringGetCString(ref, (*C.char)(unsafe.Pointer(&buffer[0])), maxLength, C.kCFStringEncodingUTF8)
	if ok == C.false {
		return ""
	}
	return C.GoString((*C.char)(unsafe.Pointer(&buffer[0])))
}

func cfData(value []byte) (C.CFDataRef, error) {
	var ptr *C.UInt8
	if len(value) > 0 {
		ptr = (*C.UInt8)(unsafe.Pointer(&value[0]))
	}
	ref := C.CFDataCreate(C.kCFAllocatorDefault, ptr, C.CFIndex(len(value)))
	if ref == 0 {
		return 0, errors.New("create CFData")
	}
	return ref, nil
}

func cfDataToBytes(ref C.CFDataRef) []byte {
	length := C.CFDataGetLength(ref)
	return C.GoBytes(unsafe.Pointer(C.CFDataGetBytePtr(ref)), C.int(length))
}

func cfDateToTime(ref C.CFTypeRef) time.Time {
	seconds := float64(C.CFDateGetAbsoluteTime(C.CFDateRef(ref))) + 978307200
	whole, fraction := math.Modf(seconds)
	return time.Unix(int64(whole), int64(fraction*1e9))
}

func cfTypeDescription(ref C.CFTypeRef) string {
	typeID := C.CFGetTypeID(ref)
	description := C.CFCopyTypeIDDescription(typeID)
	if description == 0 {
		return "unknown"
	}
	defer cfRelease(C.CFTypeRef(description))
	return cfStringToString(description)
}

func cfErrorString(ref C.CFErrorRef) string {
	if ref == 0 {
		return "unknown error"
	}
	description := C.CFErrorCopyDescription(ref)
	if description == 0 {
		return "unknown error"
	}
	defer cfRelease(C.CFTypeRef(description))
	return cfStringToString(description)
}

func cfRelease(ref C.CFTypeRef) {
	if ref != 0 {
		C.CFRelease(ref)
	}
}
