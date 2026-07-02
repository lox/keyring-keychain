keyring-keychain
================
[![CI](https://github.com/lox/keyring-keychain/actions/workflows/test.yml/badge.svg?branch=master)](https://github.com/lox/keyring-keychain/actions/workflows/test.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/lox/keyring-keychain.svg)](https://pkg.go.dev/github.com/lox/keyring-keychain)

macOS Keychain provider for [`github.com/lox/keyring/v2`](https://github.com/lox/keyring).

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
`AccessibleWhenUnlocked`, and `Prompt` options. On non-macOS platforms, or when
macOS cgo support is disabled, it returns `keyring.ErrUnavailable` during open.

Use `DataProtection` to opt in to the macOS data-protection keychain. Add
`RequireUserPresence` for Touch ID or device password authentication before
secret reads:

```go
ring, err := keyring.Open(ctx,
	keyring.WithServiceName("example"),
	keyring.WithProvider(keychain.Provider(
		keychain.DataProtection(),
		keychain.RequireUserPresence(),
	)),
)
```

`RequireBiometryCurrentSet` is also available when Touch ID enrollment changes
should invalidate stored items. `AuthenticationReuse` can reuse recent
authentication for protected reads. Data-protection mode does not support custom
keychain files, synchronizable items, or legacy trusted-application ACLs.

For local testing, use the tiny example CLI:

```bash
mise run smoke:cli
```

`-data-protection` and the Touch ID flags require the example to run as a signed
macOS app with a `keychain-access-groups` entitlement. `go run` builds an
unsigned temporary command, so macOS returns `errSecMissingEntitlement`.

To smoke test the data-protection path, point `KEYCHAIN_CLI_PROFILE` at a macOS
provisioning profile with Keychain Sharing enabled:

```bash
KEYCHAIN_CLI_PROFILE=/path/to/profile.provisionprofile mise run smoke:data-protection
```

Set `KEYCHAIN_CLI_SIGN_IDENTITY` if the default codesigning identity is not the
one that matches the profile.
