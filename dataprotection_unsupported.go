//go:build !darwin || !cgo

package keychain

import "github.com/lox/keyring/v2"

func openDataProtectionKeychain(cfg Config) (backendKeyring, error) {
	if err := validateDataProtectionConfig(cfg); err != nil {
		return nil, err
	}
	return nil, keyring.ErrUnavailable
}
