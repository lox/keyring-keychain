//go:build darwin && cgo

package keychain

import (
	"errors"
	"fmt"
	"sync"

	"github.com/lox/keyring-keychain/internal/sec"
)

var errKeychainUpdateItemNotFound = errors.New("keychain item not found")

var errKeychainSynchronizableWithCustomKeychain = errors.New("keychain synchronizable is not supported with custom keychains")

var errKeychainTouchIDWithSynchronizable = errors.New("keychain touch id is not supported with synchronizable items")

type keychain struct {
	path    string
	service string

	passwordFunc PromptFunc

	isSynchronizable         bool
	isAccessibleWhenUnlocked bool
	isTrusted                bool

	touchID *TouchIDConfig

	authMu  sync.Mutex
	authCtx *sec.AuthContext
}

func init() {
	supportedBackends[KeychainBackend] = opener(func(cfg Config) (backendKeyring, error) {
		if cfg.KeychainName != "" && cfg.KeychainSynchronizable {
			return nil, errKeychainSynchronizableWithCustomKeychain
		}
		if cfg.TouchID != nil && cfg.KeychainSynchronizable {
			return nil, errKeychainTouchIDWithSynchronizable
		}

		kc := &keychain{
			service:          cfg.ServiceName,
			passwordFunc:     cfg.KeychainPasswordFunc,
			isSynchronizable: cfg.KeychainSynchronizable,

			// Set the isAccessibleWhenUnlocked to the boolean value of
			// KeychainAccessibleWhenUnlocked is a shorthand for setting the accessibility value.
			// See: https://developer.apple.com/documentation/security/ksecattraccessiblewhenunlocked
			isAccessibleWhenUnlocked: cfg.KeychainAccessibleWhenUnlocked,

			touchID: cfg.TouchID,
		}
		if cfg.KeychainName != "" {
			kc.path = cfg.KeychainName + ".keychain"
		}
		if cfg.KeychainTrustApplication {
			kc.isTrusted = true
		}
		return kc, nil
	})
}

func (k *keychain) synchronizableItemMode(item Item) sec.Synchronizable {
	if !k.isSynchronizable {
		return sec.SynchronizableDefault
	}
	if item.KeychainNotSynchronizable {
		return sec.SynchronizableNo
	}

	return sec.SynchronizableYes
}

func (k *keychain) synchronizableQueryModes() []sec.Synchronizable {
	if !k.isSynchronizable {
		return []sec.Synchronizable{sec.SynchronizableDefault}
	}

	return []sec.Synchronizable{
		sec.SynchronizableYes,
		sec.SynchronizableNo,
	}
}

func (k *keychain) updateSynchronizableModes(synchronizable sec.Synchronizable) []sec.Synchronizable {
	if !k.isSynchronizable {
		return []sec.Synchronizable{sec.SynchronizableDefault}
	}

	modes := []sec.Synchronizable{synchronizable}
	for _, fallback := range k.synchronizableQueryModes() {
		if fallback == synchronizable {
			continue
		}
		modes = append(modes, fallback)
	}

	return modes
}

func isKeychainNotFound(err error) bool {
	return errors.Is(err, sec.ErrItemNotFound) || errors.Is(err, sec.ErrNoSuchKeychain)
}

func isMissingSynchronizableEntitlement(err error) bool {
	return errors.Is(err, sec.ErrMissingEntitlement)
}

func isKeychainAccessDenied(err error) bool {
	return errors.Is(err, sec.ErrUserCanceled) ||
		errors.Is(err, sec.ErrInvalidOwnerEdit) ||
		errors.Is(err, sec.ErrMissingEntitlement) ||
		errors.Is(err, sec.ErrAuthFailed) ||
		errors.Is(err, sec.ErrInteractionNotAllowed) ||
		errors.Is(err, sec.ErrNoAccessForItem)
}

func normalizeKeychainError(err error) error {
	if err == nil || errors.Is(err, ErrAccessDenied) {
		return err
	}
	if isKeychainAccessDenied(err) {
		return fmt.Errorf("%w: %w", ErrAccessDenied, err)
	}
	return err
}

// openSearchKeychain opens the custom keychain for search operations, or
// returns nil when the default keychain search list should be used. The
// caller must release a non-nil keychain.
func (k *keychain) openSearchKeychain() (*sec.Keychain, error) {
	if k.path == "" {
		return nil, nil //nolint:nilnil // nil keychain means the default search list
	}
	return sec.OpenKeychain(k.path)
}

func releaseKeychain(kc *sec.Keychain) {
	if kc != nil {
		kc.Release()
	}
}

func (k *keychain) queryAccount(key string, returnData bool) ([]sec.Result, error) {
	kc, err := k.openSearchKeychain()
	if err != nil {
		return nil, normalizeKeychainError(err)
	}
	defer releaseKeychain(kc)

	var firstErr error
	for _, synchronizable := range k.synchronizableQueryModes() {
		results, err := sec.QueryItems(sec.Query{
			Service:          k.service,
			Account:          key,
			Synchronizable:   synchronizable,
			Keychain:         kc,
			Limit:            sec.MatchLimitOne,
			ReturnAttributes: true,
			ReturnData:       returnData,
		})
		if isKeychainNotFound(err) {
			continue
		}
		if k.isSynchronizable && isMissingSynchronizableEntitlement(err) {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if err != nil {
			return nil, normalizeKeychainError(err)
		}
		if len(results) == 0 {
			continue
		}

		return results, nil
	}

	if firstErr != nil {
		return nil, normalizeKeychainError(firstErr)
	}

	return nil, ErrKeyNotFound
}

func (k *keychain) Get(key string) (Item, error) {
	debugf("Querying keychain for service=%q, account=%q, keychain=%q", k.service, key, k.path)
	results, err := k.queryAccount(key, true)
	if err == ErrKeyNotFound {
		debugf("No results found")
		return Item{}, ErrKeyNotFound
	}
	if err != nil {
		debugf("Error: %#v", err)
		return Item{}, err
	}

	data, err := k.maybeDecrypt(results[0].Data)
	if err != nil {
		debugf("Error decrypting item: %v", err)
		return Item{}, err
	}

	item := Item{
		Key:         key,
		Data:        data,
		Label:       results[0].Label,
		Description: results[0].Description,
	}

	debugf("Found item %q", results[0].Label)
	return item, nil
}

func (k *keychain) GetMetadata(key string) (Metadata, error) {
	debugf("Querying keychain for metadata of service=%q, account=%q, keychain=%q", k.service, key, k.path)
	results, err := k.queryAccount(key, false)
	if err == ErrKeyNotFound {
		debugf("No results found")
		return Metadata{}, ErrKeyNotFound
	}
	if err != nil {
		debugf("Error: %#v", err)
		return Metadata{}, err
	}

	md := Metadata{
		Item: &Item{
			Key:         key,
			Label:       results[0].Label,
			Description: results[0].Description,
		},
		ModificationTime: results[0].ModificationDate,
	}

	debugf("Found metadata for %q", md.Label)

	return md, nil
}

func (k *keychain) updateItemInMode(kc *sec.Keychain, item sec.Item, synchronizable sec.Synchronizable) error {
	query := sec.Query{
		Service:          k.service,
		Account:          item.Account,
		Synchronizable:   synchronizable,
		Keychain:         kc,
		Limit:            sec.MatchLimitOne,
		ReturnAttributes: true,
	}

	results, err := sec.QueryItems(query)
	if isKeychainNotFound(err) {
		return errKeychainUpdateItemNotFound
	}
	if err != nil {
		return fmt.Errorf("failed to query keychain: %w", normalizeKeychainError(err))
	}
	if len(results) == 0 {
		return errKeychainUpdateItemNotFound
	}

	updateQuery := sec.Query{
		Service:        k.service,
		Account:        item.Account,
		Synchronizable: synchronizable,
		Keychain:       kc,
	}
	if err := sec.UpdateItem(updateQuery, item); err != nil {
		return fmt.Errorf("failed to update item in keychain: %w", normalizeKeychainError(err))
	}

	return nil
}

func (k *keychain) updateItem(kc *sec.Keychain, item sec.Item, synchronizable sec.Synchronizable) error {
	var firstErr error
	for _, mode := range k.updateSynchronizableModes(synchronizable) {
		err := k.updateItemInMode(kc, item, mode)
		if err == nil {
			if firstErr != nil {
				return firstErr
			}
			return nil
		}
		if errors.Is(err, errKeychainUpdateItemNotFound) {
			continue
		}
		if k.isSynchronizable && isMissingSynchronizableEntitlement(err) {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}

		return err
	}

	if firstErr != nil {
		return normalizeKeychainError(firstErr)
	}

	return errKeychainUpdateItemNotFound
}

func (k *keychain) removeOtherSynchronizableItems(kc *sec.Keychain, account string, keepSynchronizable sec.Synchronizable) error {
	if !k.isSynchronizable {
		return nil
	}

	var firstErr error
	for _, synchronizable := range k.synchronizableQueryModes() {
		if synchronizable == keepSynchronizable {
			continue
		}

		err := sec.DeleteItem(sec.Query{
			Service:        k.service,
			Account:        account,
			Synchronizable: synchronizable,
			Keychain:       kc,
		})
		if err == nil || isKeychainNotFound(err) {
			continue
		}
		if isMissingSynchronizableEntitlement(err) {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}

		return normalizeKeychainError(err)
	}

	if firstErr != nil {
		return normalizeKeychainError(firstErr)
	}

	return nil
}

func (k *keychain) Set(item Item) error {
	var kc *sec.Keychain

	// when we are setting a value, we create or open
	if k.path != "" {
		var err error
		kc, err = k.createOrOpen()
		if err != nil {
			return err
		}
		defer kc.Release()
	}

	data := item.Data
	if k.touchID != nil {
		var err error
		data, err = k.sealTouchID(data)
		if err != nil {
			return err
		}
	}

	synchronizable := k.synchronizableItemMode(item)
	usesSynchronizableAttr := synchronizable != sec.SynchronizableDefault

	secItem := sec.Item{
		Service:        k.service,
		Account:        item.Key,
		Label:          item.Label,
		Description:    item.Description,
		Data:           data,
		Synchronizable: synchronizable,
		Keychain:       kc,
	}

	if k.isAccessibleWhenUnlocked {
		secItem.Accessible = sec.AccessibleWhenUnlocked
	}

	isTrusted := k.isTrusted && !item.KeychainNotTrustApplication

	switch {
	case usesSynchronizableAttr:
		debugf("Keychain item has a synchronizable attribute and doesn't use legacy access ACLs")
	case isTrusted:
		debugf("Keychain item trusts keyring")
		secItem.Access = &sec.Access{Label: item.Label, TrustSelf: true}
	default:
		debugf("Keychain item doesn't trust keyring")
		secItem.Access = &sec.Access{Label: item.Label, TrustSelf: false}
	}

	debugf("Adding service=%q, label=%q, account=%q, trusted=%v to osx keychain %q", k.service, item.Label, item.Key, isTrusted, k.path)

	err := sec.AddItem(secItem)

	if errors.Is(err, sec.ErrDuplicateItem) {
		debugf("Item already exists, updating")
		err = k.updateItem(kc, secItem, synchronizable)
	}

	if err != nil {
		return normalizeKeychainError(err)
	}

	return k.removeOtherSynchronizableItems(kc, item.Key, synchronizable)
}

func (k *keychain) Remove(key string) error {
	var kc *sec.Keychain

	if k.path != "" {
		var err error
		kc, err = sec.OpenKeychain(k.path)
		if err != nil {
			return normalizeKeychainError(err)
		}
		defer kc.Release()

		if err := kc.Status(); err != nil {
			if errors.Is(err, sec.ErrNoSuchKeychain) {
				return ErrKeyNotFound
			}
			return normalizeKeychainError(err)
		}
	}

	debugf("Removing keychain item service=%q, account=%q, keychain %q", k.service, key, k.path)
	removed := false
	var firstErr error
	for _, synchronizable := range k.synchronizableQueryModes() {
		err := sec.DeleteItem(sec.Query{
			Service:        k.service,
			Account:        key,
			Synchronizable: synchronizable,
			Keychain:       kc,
		})
		if err == nil {
			removed = true
			continue
		}
		if isKeychainNotFound(err) {
			continue
		}
		if k.isSynchronizable && isMissingSynchronizableEntitlement(err) {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}

		return normalizeKeychainError(err)
	}
	if firstErr != nil {
		return normalizeKeychainError(firstErr)
	}
	if removed {
		return nil
	}

	return ErrKeyNotFound
}

func (k *keychain) Keys() ([]string, error) {
	var kc *sec.Keychain

	if k.path != "" {
		var err error
		kc, err = sec.OpenKeychain(k.path)
		if err != nil {
			return nil, normalizeKeychainError(err)
		}
		defer kc.Release()

		if err := kc.Status(); err != nil {
			if errors.Is(err, sec.ErrNoSuchKeychain) {
				return []string{}, nil
			}
			return nil, normalizeKeychainError(err)
		}
	}

	debugf("Querying keychain for service=%q, keychain=%q", k.service, k.path)
	accountNames := []string{}
	seen := map[string]struct{}{}
	var firstErr error
	for _, synchronizable := range k.synchronizableQueryModes() {
		results, err := sec.QueryItems(sec.Query{
			Service:          k.service,
			Synchronizable:   synchronizable,
			Keychain:         kc,
			Limit:            sec.MatchLimitAll,
			ReturnAttributes: true,
		})
		if isKeychainNotFound(err) {
			continue
		}
		if k.isSynchronizable && isMissingSynchronizableEntitlement(err) {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if err != nil {
			return nil, normalizeKeychainError(err)
		}

		debugf("Found %d results", len(results))
		for _, r := range results {
			if _, ok := seen[r.Account]; ok {
				continue
			}
			seen[r.Account] = struct{}{}
			accountNames = append(accountNames, r.Account)
		}
	}

	if firstErr != nil {
		return nil, normalizeKeychainError(firstErr)
	}

	return accountNames, nil
}

func (k *keychain) createOrOpen() (*sec.Keychain, error) {
	kc, err := sec.OpenKeychain(k.path)
	if err != nil {
		return nil, normalizeKeychainError(err)
	}

	debugf("Checking keychain status")
	statusErr := kc.Status()
	if statusErr == nil {
		debugf("Keychain status returned nil, keychain exists")
		return kc, nil
	}
	kc.Release()

	debugf("Keychain status returned error: %v", statusErr)

	if !errors.Is(statusErr, sec.ErrNoSuchKeychain) {
		return nil, normalizeKeychainError(statusErr)
	}

	if k.passwordFunc == nil {
		debugf("Creating keychain %s with prompt", k.path)
		created, err := sec.CreateKeychainWithPrompt(k.path)
		if err != nil {
			return nil, normalizeKeychainError(err)
		}
		return created, nil
	}

	passphrase, err := k.passwordFunc("Enter passphrase for keychain")
	if err != nil {
		return nil, err
	}

	debugf("Creating keychain %s with provided password", k.path)
	created, err := sec.CreateKeychain(k.path, passphrase)
	if err != nil {
		return nil, normalizeKeychainError(err)
	}
	return created, nil
}

func (k *keychain) touchIDPolicy() sec.AccessControlPolicy {
	if k.touchID == nil {
		return sec.PolicyUserPresence
	}
	switch k.touchID.Policy {
	case TouchIDPolicyBiometryAny:
		return sec.PolicyBiometryAny
	case TouchIDPolicyBiometryCurrentSet:
		return sec.PolicyBiometryCurrentSet
	case TouchIDPolicyUserPresence:
		return sec.PolicyUserPresence
	default:
		return sec.PolicyUserPresence
	}
}

// sealTouchID encrypts data to a freshly generated Secure Enclave key and
// packs the key blob and ciphertext into a self-contained envelope.
func (k *keychain) sealTouchID(data []byte) ([]byte, error) {
	debugf("Encrypting item with Secure Enclave key")
	blob, err := sec.CreateSecureEnclaveKeyBlob(k.touchIDPolicy())
	if err != nil {
		return nil, fmt.Errorf("creating Secure Enclave key: %w", err)
	}
	ciphertext, err := sec.SecureEnclaveEncrypt(blob, data)
	if err != nil {
		return nil, fmt.Errorf("encrypting with Secure Enclave key: %w", err)
	}
	return encodeEnvelope(blob, ciphertext)
}

// maybeDecrypt decrypts envelope-encrypted item data, triggering the system
// authentication prompt. Non-envelope data is returned unchanged, so items
// written without the TouchID option read normally.
func (k *keychain) maybeDecrypt(data []byte) ([]byte, error) {
	blob, ciphertext, ok := decodeEnvelope(data)
	if !ok {
		return data, nil
	}

	debugf("Decrypting Secure Enclave protected item")
	plaintext, err := k.decryptWithAuth(blob, ciphertext)
	if err != nil {
		if sec.IsUserCanceled(err) || sec.IsAuthFailed(err) {
			return nil, fmt.Errorf("%w: %w", ErrAccessDenied, err)
		}
		return nil, fmt.Errorf("decrypting with Secure Enclave key: %w", err)
	}
	return plaintext, nil
}

// decryptWithAuth decrypts under the shared authentication context, which is
// created on first use. Reusing one context lets the system cache a
// successful authentication across multiple reads instead of prompting for
// each item. The lock is held for the whole operation so a concurrent Close
// cannot release the context mid-decrypt; this also serializes decrypts,
// which is harmless since authentication prompts are modal anyway.
func (k *keychain) decryptWithAuth(blob, ciphertext []byte) ([]byte, error) {
	k.authMu.Lock()
	defer k.authMu.Unlock()
	if k.authCtx == nil {
		reason := fmt.Sprintf("access %q", k.service)
		if k.touchID != nil && k.touchID.Reason != "" {
			reason = k.touchID.Reason
		}
		k.authCtx = sec.NewAuthContext(reason)
	}
	return sec.SecureEnclaveDecrypt(blob, ciphertext, k.authCtx)
}

// Close releases the authentication context, if any. The keyring remains
// usable; a new context is created on the next Touch ID protected read.
func (k *keychain) Close() error {
	k.authMu.Lock()
	defer k.authMu.Unlock()
	if k.authCtx != nil {
		k.authCtx.Close()
		k.authCtx = nil
	}
	return nil
}
