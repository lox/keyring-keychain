//go:build !darwin || !cgo

package keychain

import (
	"context"
	"errors"
	"testing"

	"github.com/lox/keyring/v2"
)

func TestDataProtectionProviderUnavailableOnUnsupportedPlatforms(t *testing.T) {
	_, err := Provider(DataProtection()).Open(context.Background(), keyring.OpenOptions{})
	if !errors.Is(err, keyring.ErrUnavailable) {
		t.Fatalf("expected unavailable, got %v", err)
	}
}
