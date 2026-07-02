//go:build darwin && cgo

package sec

/*
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
*/
import "C"

import (
	"time"
	"unsafe"
)

// Synchronizable controls the kSecAttrSynchronizable attribute. Default
// leaves the attribute unset, which macOS treats as "not synchronizable"
// for both storage and matching.
type Synchronizable int

const (
	SynchronizableDefault Synchronizable = iota
	SynchronizableYes
	SynchronizableNo
)

// Accessible controls the kSecAttrAccessible attribute. Default leaves the
// attribute unset.
type Accessible int

const (
	AccessibleDefault Accessible = iota
	AccessibleWhenUnlocked
)

// MatchLimit controls how many results a query returns.
type MatchLimit int

const (
	MatchLimitOne MatchLimit = iota
	MatchLimitAll
)

// Item describes a generic password item to add or the replacement
// attributes for an update.
type Item struct {
	Service     string
	Account     string
	Label       string
	Description string
	Data        []byte

	Accessible     Accessible
	Synchronizable Synchronizable

	// Access, when set, applies a legacy file-based keychain ACL to the item
	// on add. Ignored on update.
	Access *Access

	// Keychain, when set, targets a specific file-based keychain on add.
	Keychain *Keychain
}

// Query describes a search for generic password items.
type Query struct {
	Service        string
	Account        string
	Synchronizable Synchronizable

	// Keychain, when set, restricts matching to a specific file-based keychain.
	Keychain *Keychain

	Limit            MatchLimit
	ReturnData       bool
	ReturnAttributes bool
}

// Result is a single item returned by QueryItems.
type Result struct {
	Account          string
	Label            string
	Description      string
	Data             []byte
	ModificationDate time.Time
}

func setSynchronizable(d C.CFMutableDictionaryRef, s Synchronizable) {
	switch s {
	case SynchronizableYes:
		dictSetBool(d, C.CFTypeRef(C.kSecAttrSynchronizable), true)
	case SynchronizableNo:
		dictSetBool(d, C.CFTypeRef(C.kSecAttrSynchronizable), false)
	case SynchronizableDefault:
	}
}

func setAccessible(d C.CFMutableDictionaryRef, a Accessible) {
	switch a {
	case AccessibleWhenUnlocked:
		dictSet(d, C.CFTypeRef(C.kSecAttrAccessible), C.CFTypeRef(C.kSecAttrAccessibleWhenUnlocked))
	case AccessibleDefault:
	}
}

// attrDict builds the add/update attribute dictionary for an item. The
// caller must release the returned dictionary.
func (item Item) attrDict() (C.CFMutableDictionaryRef, error) {
	d := newDict()
	dictSetString(d, C.CFTypeRef(C.kSecAttrService), item.Service)
	dictSetString(d, C.CFTypeRef(C.kSecAttrAccount), item.Account)
	dictSetString(d, C.CFTypeRef(C.kSecAttrLabel), item.Label)
	dictSetString(d, C.CFTypeRef(C.kSecAttrDescription), item.Description)
	dictSetData(d, C.CFTypeRef(C.kSecValueData), item.Data)
	setAccessible(d, item.Accessible)
	setSynchronizable(d, item.Synchronizable)
	if item.Access != nil {
		accessRef, err := item.Access.create()
		if err != nil {
			release(C.CFTypeRef(d))
			return 0, err
		}
		dictSetOwned(d, C.CFTypeRef(C.kSecAttrAccess), C.CFTypeRef(accessRef))
	}
	return d, nil
}

// AddItem adds a generic password item to the keychain.
func AddItem(item Item) error {
	d, err := item.attrDict()
	if err != nil {
		return err
	}
	defer release(C.CFTypeRef(d))
	dictSet(d, C.CFTypeRef(C.kSecClass), C.CFTypeRef(C.kSecClassGenericPassword))
	if item.Keychain != nil {
		dictSet(d, C.CFTypeRef(C.kSecUseKeychain), C.CFTypeRef(item.Keychain.ref))
	}
	return checkStatus(C.SecItemAdd(C.CFDictionaryRef(d), nil))
}

// dict builds the query dictionary. The caller must release it.
func (q Query) dict() C.CFMutableDictionaryRef {
	d := newDict()
	dictSet(d, C.CFTypeRef(C.kSecClass), C.CFTypeRef(C.kSecClassGenericPassword))
	if q.Service != "" {
		dictSetString(d, C.CFTypeRef(C.kSecAttrService), q.Service)
	}
	if q.Account != "" {
		dictSetString(d, C.CFTypeRef(C.kSecAttrAccount), q.Account)
	}
	setSynchronizable(d, q.Synchronizable)
	if q.Keychain != nil {
		searchList := C.CFArrayCreate(C.kCFAllocatorDefault,
			(*unsafe.Pointer)(unsafe.Pointer(&q.Keychain.ref)), 1, &C.kCFTypeArrayCallBacks)
		dictSetOwned(d, C.CFTypeRef(C.kSecMatchSearchList), C.CFTypeRef(searchList))
	}
	return d
}

// QueryItems searches for generic password items matching the query.
// Returns ErrItemNotFound if nothing matches.
func QueryItems(q Query) ([]Result, error) {
	d := q.dict()
	defer release(C.CFTypeRef(d))

	switch q.Limit {
	case MatchLimitAll:
		dictSet(d, C.CFTypeRef(C.kSecMatchLimit), C.CFTypeRef(C.kSecMatchLimitAll))
	case MatchLimitOne:
		dictSet(d, C.CFTypeRef(C.kSecMatchLimit), C.CFTypeRef(C.kSecMatchLimitOne))
	}
	if q.ReturnData {
		dictSetBool(d, C.CFTypeRef(C.kSecReturnData), true)
	}
	if q.ReturnAttributes {
		dictSetBool(d, C.CFTypeRef(C.kSecReturnAttributes), true)
	}

	var result C.CFTypeRef
	if err := checkStatus(C.SecItemCopyMatching(C.CFDictionaryRef(d), &result)); err != nil {
		return nil, err
	}
	if result == 0 {
		return nil, ErrItemNotFound
	}
	defer release(result)

	typeID := C.CFGetTypeID(result)
	switch typeID {
	case C.CFArrayGetTypeID():
		arr := C.CFArrayRef(result)
		count := int(C.CFArrayGetCount(arr))
		results := make([]Result, 0, count)
		for i := 0; i < count; i++ {
			ref := C.CFTypeRef(C.CFArrayGetValueAtIndex(arr, C.CFIndex(i)))
			results = append(results, parseResult(ref))
		}
		return results, nil
	default:
		return []Result{parseResult(result)}, nil
	}
}

func parseResult(ref C.CFTypeRef) Result {
	if C.CFGetTypeID(ref) == C.CFDataGetTypeID() {
		// kSecReturnData without kSecReturnAttributes yields a bare CFData.
		return Result{Data: goData(C.CFDataRef(ref))}
	}
	d := C.CFDictionaryRef(ref)
	r := Result{
		Account:     dictGetString(d, C.CFTypeRef(C.kSecAttrAccount)),
		Label:       dictGetString(d, C.CFTypeRef(C.kSecAttrLabel)),
		Description: dictGetString(d, C.CFTypeRef(C.kSecAttrDescription)),
	}
	if data := dictGet(d, C.CFTypeRef(C.kSecValueData)); data != 0 {
		r.Data = goData(C.CFDataRef(data))
	}
	if date := dictGet(d, C.CFTypeRef(C.kSecAttrModificationDate)); date != 0 {
		r.ModificationDate = goTime(C.CFDateRef(date))
	}
	return r
}

// UpdateItem updates items matching the query with the item's attributes.
// The item's Access and Keychain fields are ignored.
func UpdateItem(q Query, item Item) error {
	item.Access = nil
	update, err := item.attrDict()
	if err != nil {
		return err
	}
	defer release(C.CFTypeRef(update))

	d := q.dict()
	defer release(C.CFTypeRef(d))

	return checkStatus(C.SecItemUpdate(C.CFDictionaryRef(d), C.CFDictionaryRef(update)))
}

// DeleteItem deletes all items matching the query.
func DeleteItem(q Query) error {
	d := q.dict()
	defer release(C.CFTypeRef(d))
	return checkStatus(C.SecItemDelete(C.CFDictionaryRef(d)))
}
