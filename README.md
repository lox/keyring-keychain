keyring-keychain
================
[![CI](https://github.com/lox/keyring-keychain/actions/workflows/test.yml/badge.svg?branch=master)](https://github.com/lox/keyring-keychain/actions/workflows/test.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/lox/keyring-keychain.svg)](https://pkg.go.dev/github.com/lox/keyring-keychain)

macOS Keychain provider for [`github.com/lox/keyring/v2`](https://github.com/lox/keyring),
with optional Touch ID protection backed by the Secure Enclave. Binds directly
to the Security and LocalAuthentication frameworks with no third-party
dependencies.

## Usage

```bash
go get github.com/lox/keyring-keychain
```

```go
import (
	"context"

	"github.com/lox/keyring/v2"
	keychain "github.com/lox/keyring-keychain"
)

ctx := context.Background()

ring, err := keyring.Open(ctx,
	keyring.WithServiceName("example"),
	keyring.WithProvider(keychain.Provider()),
)
```

`keychain.Provider` accepts `Name`, `TrustApplication`, `Synchronizable`,
`AccessibleWhenUnlocked`, `Prompt`, and `TouchID` options. On non-macOS
platforms, or when macOS cgo support is disabled, it returns
`keyring.ErrUnavailable` during open.

## Touch ID

The `TouchID` option encrypts item data to a per-item key held in the Secure
Enclave, so reading an item back requires user authentication:

```go
ring, err := keyring.Open(ctx,
	keyring.WithServiceName("example"),
	keyring.WithProvider(keychain.Provider(
		keychain.TouchID(keychain.TouchIDConfig{
			Reason: "unlock example credentials",
		}),
	)),
)
```

Reads trigger the system prompt ("&lt;app&gt; is trying to &lt;reason&gt;").
The default `TouchIDPolicyUserPresence` policy accepts Touch ID or the user's
account password; `TouchIDPolicyBiometryAny` and
`TouchIDPolicyBiometryCurrentSet` require a fingerprint. Repeated reads
through one open keyring reuse a single authentication context, so the user
is not prompted per item.

Unlike keychain-level biometry (`kSecAttrAccessControl` on the data
protection keychain), this works in unsigned or ad-hoc signed binaries —
plain `go build` output included — because the enforcement is done by the
Secure Enclave rather than by keychain entitlements. It requires a Mac with
a Secure Enclave (Apple silicon or T2); `Set` returns an error on other
machines. `keychain.TouchIDAvailable()` reports whether biometric
authentication is currently possible.

Notes:

- Protected items are device-bound: the wrapping key never leaves the Secure
  Enclave, so items cannot be read on another machine (and `TouchID` cannot
  be combined with `Synchronizable`).
- The encrypted payload is stored as a regular keychain item, so `Keys`,
  `Metadata`, and `Remove` work without authentication; only item data is
  protected.
- Items written with `TouchID` are readable by rings opened without it (the
  envelope is detected on read); items written without it are returned
  as-is.

## Design

### Why not the data protection keychain?

The supported way to gate keychain items behind Touch ID is
`kSecAttrAccessControl` on the data protection keychain
(`kSecUseDataProtectionKeychain`). macOS builds a process's data protection
keychain access from its code signing entitlements, which must be authorised
by a provisioning profile embedded in an app-like bundle
([TN3137](https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains)).
A plain Go binary — even fully ad-hoc re-signed — gets
`errSecMissingEntitlement (-34018)` for every data protection keychain
operation, so that route is unavailable to typical Go CLIs. (Vendors who ship
signed, provisioned bundles, like Teleport's `tsh.app`, can use it; that mode
could be added here as an option later.)

An `LAContext.evaluatePolicy` check before reading an ordinary item — what
most "Touch ID for the keychain" CLI tools do — was rejected: the check runs
in the calling process and nothing cryptographic depends on it, so the data
remains readable without authentication.

### Secure Enclave envelope encryption

What does work without entitlements is creating **non-permanent** Secure
Enclave keys (`SecKeyCreateRandomKey` with `kSecAttrTokenIDSecureEnclave`
and `kSecAttrIsPermanent: false`). Such a key is never stored in any
keychain: its only handle is an opaque encrypted blob (the key's
`kSecAttrTokenOID` attribute — the same blob CryptoKit persists as a Secure
Enclave key's `dataRepresentation`) that only this device's Secure Enclave
can use. The key's `kSecAccessControlUserPresence` (or biometry) flag is
enforced by the Secure Enclave itself at operation time, not by keychain
entitlements. This is the same mechanism
[age-plugin-se](https://github.com/remko/age-plugin-se) uses.

On `Set`, the provider:

1. generates a fresh Secure Enclave P-256 key with the configured access
   control policy,
2. encrypts the item data to its public key with ECIES
   (`kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM`,
   a hybrid scheme, so data of any length),
3. stores key blob and ciphertext together as a self-contained envelope in a
   regular generic password item:

```
┌────────────────┬──────────────────┬──────────┬────────────┐
│ magic \x00krse1│ blob len (u16 BE)│ key blob │ ciphertext │
└────────────────┴──────────────────┴──────────┴────────────┘
```

On `Get`, the envelope is detected by its magic, the key is reconstituted
from the blob, and `SecKeyCreateDecryptedData` performs ECDH inside the
Secure Enclave — which is the point where the system shows the
authentication prompt.

Each item has its own key and the envelope is self-contained: there is no
key registry to manage or orphan, `Remove` needs no special handling, and
deleting the item destroys the only handle to its key. Because reads are
driven by item content rather than ring configuration, mixed rings work
naturally. A shared `LAContext` per open ring lets the system cache a
successful authentication across reads.

One implementation subtlety: when reconstituting a token key,
`SecKeyCreateWithData` ignores its data parameter — the blob must be passed
as the `kSecAttrTokenOID` attribute. Omitting it silently generates a brand
new key (see `SecCTKKey initWithAttributes` in the open source
[Security framework](https://github.com/apple-oss-distributions/Security)).
`kSecAttrTokenOID` ("toid") is not in the public SDK headers but is defined
and stable in the open source framework, and Apple's own regression tests
use this reconstruction pattern.

### Security model

The Secure Enclave enforces user presence for the ECDH operation, so item
data is not recoverable without authentication even by code that can read
the raw keychain item. The usual caveats for same-user local security still
apply: a process running as the user could phish a prompt (the prompt names
the calling binary and reason), and under `TouchIDPolicyUserPresence` the
account password is an accepted fallback. `TouchIDPolicyBiometryCurrentSet`
additionally binds keys to the fingerprint set enrolled at write time.

## Demo CLI

A small CLI in [`cmd/keychain-demo`](cmd/keychain-demo/main.go) exercises the
provider:

```bash
# Regular keychain items
echo -n hunter2 | go run ./cmd/keychain-demo set llamas
go run ./cmd/keychain-demo get llamas
go run ./cmd/keychain-demo ls
go run ./cmd/keychain-demo rm llamas

# Touch ID protected items (get prompts for authentication)
echo -n hunter2 | go run ./cmd/keychain-demo -touchid set llamas
go run ./cmd/keychain-demo -touchid -reason "read the demo secret" get llamas

go run ./cmd/keychain-demo available
```

See `go run ./cmd/keychain-demo -h` for service, custom keychain, and policy
flags.

## Development

```bash
go test ./...

# Exercise the Touch ID prompt end to end (requires interaction):
KEYRING_KEYCHAIN_INTERACTIVE=1 go test -run TestTouchIDGetInteractive -v
```
