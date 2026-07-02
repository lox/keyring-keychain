package keychain

import (
	"context"
	"io"

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
	TouchID                        *TouchIDConfig
}

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

func Provider(opts ...Option) keyring.Provider {
	cfg := Config{}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	return keyring.Provider{
		Backend: Backend,
		Open: func(ctx context.Context, open keyring.OpenOptions) (keyring.Keyring, error) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			openCfg := cfg
			openCfg.ServiceName = open.ServiceName
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

// Close releases any resources held by the underlying keyring, such as the
// authentication context used for Touch ID protected items.
func (a adapter) Close() error {
	if closer, ok := a.ring.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}
