//go:build darwin && cgo

package keychain

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/lox/keyring-keychain/internal/sec"
	"github.com/lox/keyring/v2"
)

const testService = "keyring-keychain-test"

func newTestKeyring(t *testing.T, opts ...Option) keyring.Keyring {
	t.Helper()

	base := []Option{
		Name(filepath.Join(t.TempDir(), "test")),
		TrustApplication(true),
		Prompt(keyring.FixedStringPrompt("test-password")),
	}

	ring, err := keyring.Open(context.Background(),
		keyring.WithServiceName(testService),
		keyring.WithProvider(Provider(append(base, opts...)...)),
	)
	if err != nil {
		t.Fatalf("keyring.Open: %v", err)
	}
	return ring
}

func TestKeychainCRUD(t *testing.T) {
	ctx := context.Background()
	ring := newTestKeyring(t)

	item := Item{
		Key:         "llamas",
		Data:        []byte("llamas are great"),
		Label:       "keyring-keychain-test.llamas",
		Description: "application password",
	}
	if err := ring.Set(ctx, item); err != nil {
		t.Fatalf("Set: %v", err)
	}

	got, err := ring.Get(ctx, "llamas")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got.Data, item.Data) {
		t.Errorf("Get data = %q, want %q", got.Data, item.Data)
	}
	if got.Label != item.Label {
		t.Errorf("Get label = %q, want %q", got.Label, item.Label)
	}
	if got.Description != item.Description {
		t.Errorf("Get description = %q, want %q", got.Description, item.Description)
	}

	keys, err := ring.Keys(ctx)
	if err != nil {
		t.Fatalf("Keys: %v", err)
	}
	if len(keys) != 1 || keys[0] != "llamas" {
		t.Errorf("Keys = %v, want [llamas]", keys)
	}

	mr, ok := ring.(keyring.MetadataReader)
	if !ok {
		t.Fatal("ring does not implement keyring.MetadataReader")
	}
	md, err := mr.Metadata(ctx, "llamas")
	if err != nil {
		t.Fatalf("Metadata: %v", err)
	}
	if md.ModificationTime.IsZero() {
		t.Error("Metadata modification time is zero")
	}
	if md.Label != item.Label {
		t.Errorf("Metadata label = %q, want %q", md.Label, item.Label)
	}

	if err := ring.Remove(ctx, "llamas"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := ring.Get(ctx, "llamas"); !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("Get after Remove = %v, want ErrKeyNotFound", err)
	}
}

func TestKeychainUpdate(t *testing.T) {
	ctx := context.Background()
	ring := newTestKeyring(t)

	for _, data := range []string{"first", "second"} {
		err := ring.Set(ctx, Item{Key: "alpacas", Data: []byte(data), Label: "alpacas"})
		if err != nil {
			t.Fatalf("Set %q: %v", data, err)
		}
	}

	got, err := ring.Get(ctx, "alpacas")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got.Data) != "second" {
		t.Errorf("Get data = %q, want %q", got.Data, "second")
	}
}

func TestKeychainMissingKey(t *testing.T) {
	ctx := context.Background()
	ring := newTestKeyring(t)

	if _, err := ring.Get(ctx, "no-such-key"); !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("Get = %v, want ErrKeyNotFound", err)
	}
	if err := ring.Remove(ctx, "no-such-key"); !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("Remove = %v, want ErrKeyNotFound", err)
	}
}

func TestKeychainKeysWithoutKeychainFile(t *testing.T) {
	ctx := context.Background()
	ring := newTestKeyring(t)

	keys, err := ring.Keys(ctx)
	if err != nil {
		t.Fatalf("Keys: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("Keys = %v, want empty", keys)
	}
}

func TestTouchIDWithSynchronizableFails(t *testing.T) {
	_, err := keyring.Open(context.Background(),
		keyring.WithServiceName(testService),
		keyring.WithProvider(Provider(
			Synchronizable(true),
			TouchID(TouchIDConfig{}),
		)),
	)
	if err == nil {
		t.Fatal("expected error opening TouchID keyring with Synchronizable")
	}
}

// requireSecureEnclave skips the test on machines without a usable Secure
// Enclave (e.g. CI virtual machines and pre-T2 Intel Macs).
func requireSecureEnclave(t *testing.T) {
	t.Helper()
	if _, err := sec.CreateSecureEnclaveKeyBlob(sec.PolicyUserPresence); err != nil {
		t.Skipf("Secure Enclave unavailable: %v", err)
	}
}

// TestSecureEnclaveKeyBlobIsStable guards against the token OID bug where
// loading a key blob silently generated a fresh key: reloading the same blob
// must always resolve to the same key (same public key).
func TestSecureEnclaveKeyBlobIsStable(t *testing.T) {
	requireSecureEnclave(t)

	blob, err := sec.CreateSecureEnclaveKeyBlob(sec.PolicyUserPresence)
	if err != nil {
		t.Fatalf("CreateSecureEnclaveKeyBlob: %v", err)
	}

	pub1, err := sec.SecureEnclavePublicKey(blob)
	if err != nil {
		t.Fatalf("SecureEnclavePublicKey: %v", err)
	}
	pub2, err := sec.SecureEnclavePublicKey(blob)
	if err != nil {
		t.Fatalf("SecureEnclavePublicKey (reload): %v", err)
	}
	if len(pub1) == 0 || !bytes.Equal(pub1, pub2) {
		t.Errorf("public key differs across loads of the same blob:\n%x\n%x", pub1, pub2)
	}
}

func TestSecureEnclaveEncrypt(t *testing.T) {
	requireSecureEnclave(t)

	blob, err := sec.CreateSecureEnclaveKeyBlob(sec.PolicyUserPresence)
	if err != nil {
		t.Fatalf("CreateSecureEnclaveKeyBlob: %v", err)
	}
	if len(blob) == 0 {
		t.Fatal("empty key blob")
	}

	ciphertext, err := sec.SecureEnclaveEncrypt(blob, []byte("hello"))
	if err != nil {
		t.Fatalf("SecureEnclaveEncrypt: %v", err)
	}
	if bytes.Contains(ciphertext, []byte("hello")) {
		t.Error("ciphertext contains plaintext")
	}
}

// TestTouchIDSetStoresEnvelope verifies that Set with the TouchID option
// stores an encrypted envelope rather than the plaintext, without needing
// user interaction (only decryption prompts).
func TestTouchIDSetStoresEnvelope(t *testing.T) {
	requireSecureEnclave(t)

	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "test")
	ring := newTestKeyring(t, Name(path), TouchID(TouchIDConfig{}))

	secret := []byte("touch id protected secret")
	if err := ring.Set(ctx, Item{Key: "protected", Data: secret, Label: "protected"}); err != nil {
		t.Fatalf("Set: %v", err)
	}

	// Read the raw stored bytes without triggering decryption.
	kc, err := sec.OpenKeychain(path + ".keychain")
	if err != nil {
		t.Fatalf("OpenKeychain: %v", err)
	}
	defer kc.Release()

	results, err := sec.QueryItems(sec.Query{
		Service:          testService,
		Account:          "protected",
		Keychain:         kc,
		Limit:            sec.MatchLimitOne,
		ReturnAttributes: true,
		ReturnData:       true,
	})
	if err != nil {
		t.Fatalf("QueryItems: %v", err)
	}

	raw := results[0].Data
	if bytes.Contains(raw, secret) {
		t.Error("stored data contains plaintext secret")
	}
	if _, _, ok := decodeEnvelope(raw); !ok {
		t.Error("stored data is not a Secure Enclave envelope")
	}
}

// TestTouchIDGetInteractive exercises the full encrypt/decrypt round trip,
// including the system authentication prompt. Run manually with:
//
//	KEYRING_KEYCHAIN_INTERACTIVE=1 go test -run TestTouchIDGetInteractive -v
func TestTouchIDGetInteractive(t *testing.T) {
	if os.Getenv("KEYRING_KEYCHAIN_INTERACTIVE") == "" {
		t.Skip("set KEYRING_KEYCHAIN_INTERACTIVE=1 to run interactive Touch ID tests")
	}
	requireSecureEnclave(t)

	ctx := context.Background()
	ring := newTestKeyring(t, TouchID(TouchIDConfig{
		Reason: "run the keyring-keychain interactive test",
	}))

	secret := []byte("touch id protected secret")
	if err := ring.Set(ctx, Item{Key: "protected", Data: secret, Label: "protected"}); err != nil {
		t.Fatalf("Set: %v", err)
	}

	got, err := ring.Get(ctx, "protected")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got.Data, secret) {
		t.Errorf("Get data = %q, want %q", got.Data, secret)
	}
}
