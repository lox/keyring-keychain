package keychain

// TouchIDPolicy selects the user authentication required to read items
// protected by the TouchID option.
type TouchIDPolicy int

const (
	// TouchIDPolicyUserPresence allows Touch ID or the user's account
	// password. This is the default and works on Macs without biometrics.
	TouchIDPolicyUserPresence TouchIDPolicy = iota

	// TouchIDPolicyBiometryAny requires any enrolled fingerprint, with no
	// password fallback.
	TouchIDPolicyBiometryAny

	// TouchIDPolicyBiometryCurrentSet requires a fingerprint from the set
	// enrolled when the item was written; enrolling new fingerprints
	// invalidates access.
	TouchIDPolicyBiometryCurrentSet
)

// TouchIDConfig configures Touch ID protection for items written through
// this provider.
type TouchIDConfig struct {
	// Reason is shown in the authentication prompt as
	// "<app> is trying to <reason>". Defaults to `access "<service>"`.
	Reason string

	// Policy selects the required authentication. Defaults to
	// TouchIDPolicyUserPresence.
	Policy TouchIDPolicy
}

// TouchID protects item data with a per-item Secure Enclave key so that
// reading it back requires user authentication (Touch ID, or the account
// password under the default policy). The encrypted payload is stored as a
// regular keychain item; the wrapping key never leaves the Secure Enclave,
// so protected items are only readable on the device that wrote them.
//
// Requires a Mac with a Secure Enclave (Apple silicon or T2). Set returns
// an error on machines without one. Not compatible with Synchronizable.
func TouchID(cfg TouchIDConfig) Option {
	return func(c *Config) { c.TouchID = &cfg }
}
