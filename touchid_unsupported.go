//go:build !darwin || !cgo

package keychain

// TouchIDAvailable reports whether the device can authenticate with
// biometrics. Always false on non-macOS platforms and cgo-less builds.
func TouchIDAvailable() bool {
	return false
}
