package keychain

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/lox/keyring/v2"
)

const Backend = keyring.KeychainBackend

type Option func(*Config)

type Config struct {
	ServiceName                    string
	KeychainName                   string
	KeychainTrustApplication       bool
	KeychainSynchronizable         bool
	KeychainAccessibleWhenUnlocked bool
	KeychainPasswordFunc           keyring.PromptFunc

	keychainDataProtection      bool
	keychainAccessControl       dataProtectionAccessControl
	keychainAuthenticationReuse time.Duration
}

type dataProtectionAccessControl int

const (
	dataProtectionAccessControlNone dataProtectionAccessControl = iota
	dataProtectionAccessControlUserPresence
	dataProtectionAccessControlBiometryCurrentSet
)

func Name(name string) Option {
	return func(cfg *Config) { cfg.KeychainName = name }
}

func TrustApplication(enabled bool) Option {
	return func(cfg *Config) { cfg.KeychainTrustApplication = enabled }
}

func Synchronizable(enabled bool) Option {
	return func(cfg *Config) { cfg.KeychainSynchronizable = enabled }
}

func AccessibleWhenUnlocked(enabled bool) Option {
	return func(cfg *Config) { cfg.KeychainAccessibleWhenUnlocked = enabled }
}

func Prompt(prompt keyring.PromptFunc) Option {
	return func(cfg *Config) { cfg.KeychainPasswordFunc = prompt }
}

// DataProtection stores items in the macOS data-protection keychain.
func DataProtection() Option {
	return func(cfg *Config) { cfg.keychainDataProtection = true }
}

// RequireUserPresence requires Touch ID or device password authentication before
// reading protected item data.
func RequireUserPresence() Option {
	return func(cfg *Config) { cfg.keychainAccessControl = dataProtectionAccessControlUserPresence }
}

// RequireBiometryCurrentSet requires the current Touch ID enrollment before
// reading protected item data.
func RequireBiometryCurrentSet() Option {
	return func(cfg *Config) { cfg.keychainAccessControl = dataProtectionAccessControlBiometryCurrentSet }
}

// AuthenticationReuse allows recent authentication to be reused for protected
// reads.
func AuthenticationReuse(duration time.Duration) Option {
	return func(cfg *Config) { cfg.keychainAuthenticationReuse = duration }
}

func newConfig(opts ...Option) Config {
	cfg := Config{}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	return cfg
}

func Provider(opts ...Option) keyring.Provider {
	cfg := newConfig(opts...)
	return keyring.Provider{
		Backend: Backend,
		Open: func(ctx context.Context, open keyring.OpenOptions) (keyring.Keyring, error) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			openCfg := cfg
			openCfg.ServiceName = open.ServiceName
			if openCfg.keychainDataProtection {
				ring, err := openDataProtectionKeychain(openCfg)
				if err != nil {
					return nil, err
				}
				return adapter{ring: ring}, nil
			}
			opener, ok := supportedBackends[Backend]
			if !ok {
				return nil, keyring.ErrUnavailable
			}
			ring, err := opener(openCfg)
			if err != nil {
				return nil, err
			}
			return adapter{ring: ring}, nil
		},
	}
}

func validateDataProtectionConfig(cfg Config) error {
	if cfg.KeychainName != "" {
		return fmt.Errorf("%w: data protection keychain does not support custom keychains", keyring.ErrInvalidOption)
	}
	if cfg.KeychainTrustApplication {
		return fmt.Errorf("%w: data protection keychain does not support legacy trusted-application ACLs", keyring.ErrInvalidOption)
	}
	if cfg.KeychainSynchronizable {
		return fmt.Errorf("%w: data protection keychain does not support synchronizable items", keyring.ErrInvalidOption)
	}
	if cfg.keychainAuthenticationReuse < 0 {
		return fmt.Errorf("%w: authentication reuse duration must not be negative", keyring.ErrInvalidOption)
	}
	if cfg.keychainAuthenticationReuse > 0 && cfg.keychainAccessControl == dataProtectionAccessControlNone {
		return fmt.Errorf("%w: authentication reuse requires access control", keyring.ErrInvalidOption)
	}
	return nil
}

type opener func(Config) (backendKeyring, error)

var supportedBackends = map[keyring.Backend]opener{}

type backendKeyring interface {
	Get(string) (keyring.Item, error)
	GetMetadata(string) (keyring.Metadata, error)
	Set(keyring.Item) error
	Remove(string) error
	Keys() ([]string, error)
}

type adapter struct {
	ring backendKeyring
}

func (a adapter) Get(ctx context.Context, key string) (keyring.Item, error) {
	if err := ctx.Err(); err != nil {
		return keyring.Item{}, err
	}
	return a.ring.Get(key)
}

func (a adapter) Set(ctx context.Context, item keyring.Item) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return a.ring.Set(item)
}

func (a adapter) Remove(ctx context.Context, key string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return a.ring.Remove(key)
}

func (a adapter) Keys(ctx context.Context) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return a.ring.Keys()
}

func (a adapter) Metadata(ctx context.Context, key string) (keyring.Metadata, error) {
	if err := ctx.Err(); err != nil {
		return keyring.Metadata{}, err
	}
	return a.ring.GetMetadata(key)
}

func (a adapter) Close() error {
	closer, ok := a.ring.(io.Closer)
	if !ok {
		return nil
	}
	return closer.Close()
}
