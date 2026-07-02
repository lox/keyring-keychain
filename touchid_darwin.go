//go:build darwin && cgo

package keychain

import "github.com/lox/keyring-keychain/internal/sec"

// TouchIDAvailable reports whether the device can authenticate with
// biometrics (Touch ID with at least one enrolled fingerprint). The
// TouchID option's default UserPresence policy may still be usable without
// biometrics on Secure Enclave equipped Macs via the account password.
func TouchIDAvailable() bool {
	return sec.BiometryAvailable()
}
