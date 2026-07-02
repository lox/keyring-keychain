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
