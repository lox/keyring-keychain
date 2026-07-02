package keychain

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/lox/keyring/v2"
)

func TestProviderUsesLegacyBackendByDefault(t *testing.T) {
	oldOpener, hadOpener := supportedBackends[Backend]
	defer func() {
		if hadOpener {
			supportedBackends[Backend] = oldOpener
			return
		}
		delete(supportedBackends, Backend)
	}()

	called := false
	supportedBackends[Backend] = opener(func(cfg Config) (backendKeyring, error) {
		called = true
		if cfg.keychainDataProtection {
			t.Fatal("default provider unexpectedly used data protection")
		}
		if cfg.ServiceName != "test-service" {
			t.Fatalf("unexpected service name: %q", cfg.ServiceName)
		}
		return &testClosingBackend{}, nil
	})

	ring, err := Provider().Open(context.Background(), keyring.OpenOptions{ServiceName: "test-service"})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if ring == nil || !called {
		t.Fatal("expected legacy opener to be called")
	}
}

func TestDataProtectionOptionsConfigureProvider(t *testing.T) {
	cfg := newConfig(
		DataProtection(),
		RequireUserPresence(),
		AuthenticationReuse(30*time.Second),
		AccessibleWhenUnlocked(true),
	)

	if !cfg.keychainDataProtection {
		t.Fatal("expected data protection keychain")
	}
	if cfg.keychainAccessControl != dataProtectionAccessControlUserPresence {
		t.Fatalf("unexpected access control: %v", cfg.keychainAccessControl)
	}
	if cfg.keychainAuthenticationReuse != 30*time.Second {
		t.Fatalf("unexpected authentication reuse: %v", cfg.keychainAuthenticationReuse)
	}
	if !cfg.KeychainAccessibleWhenUnlocked {
		t.Fatal("expected accessible-when-unlocked option")
	}
}

func TestRequireBiometryCurrentSetOverridesUserPresence(t *testing.T) {
	cfg := newConfig(RequireUserPresence(), RequireBiometryCurrentSet())

	if cfg.keychainAccessControl != dataProtectionAccessControlBiometryCurrentSet {
		t.Fatalf("unexpected access control: %v", cfg.keychainAccessControl)
	}
}

func TestValidateDataProtectionConfig(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
		want bool
	}{
		{
			name: "plain data protection",
			cfg:  Config{keychainDataProtection: true},
		},
		{
			name: "user presence with reuse",
			cfg: Config{
				keychainDataProtection:      true,
				keychainAccessControl:       dataProtectionAccessControlUserPresence,
				keychainAuthenticationReuse: time.Minute,
			},
		},
		{
			name: "custom keychain",
			cfg: Config{
				keychainDataProtection: true,
				KeychainName:           "login",
			},
			want: true,
		},
		{
			name: "trusted application",
			cfg: Config{
				keychainDataProtection:   true,
				KeychainTrustApplication: true,
			},
			want: true,
		},
		{
			name: "synchronizable",
			cfg: Config{
				keychainDataProtection: true,
				KeychainSynchronizable: true,
			},
			want: true,
		},
		{
			name: "negative reuse",
			cfg: Config{
				keychainDataProtection:      true,
				keychainAuthenticationReuse: -time.Second,
			},
			want: true,
		},
		{
			name: "reuse without access control",
			cfg: Config{
				keychainDataProtection:      true,
				keychainAuthenticationReuse: time.Second,
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateDataProtectionConfig(tt.cfg)
			if tt.want && !errors.Is(err, keyring.ErrInvalidOption) {
				t.Fatalf("expected invalid option, got %v", err)
			}
			if !tt.want && err != nil {
				t.Fatalf("expected valid config, got %v", err)
			}
		})
	}
}

func TestAdapterCloseClosesBackend(t *testing.T) {
	backend := &testClosingBackend{}
	if err := (adapter{ring: backend}).Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !backend.closed {
		t.Fatal("expected backend to close")
	}
}

type testClosingBackend struct {
	closed bool
}

func (b *testClosingBackend) Get(string) (keyring.Item, error) {
	return keyring.Item{}, keyring.ErrKeyNotFound
}

func (b *testClosingBackend) GetMetadata(string) (keyring.Metadata, error) {
	return keyring.Metadata{}, keyring.ErrMetadataNotSupported
}

func (b *testClosingBackend) Set(keyring.Item) error {
	return nil
}

func (b *testClosingBackend) Remove(string) error {
	return nil
}

func (b *testClosingBackend) Keys() ([]string, error) {
	return nil, nil
}

func (b *testClosingBackend) Close() error {
	b.closed = true
	return nil
}
