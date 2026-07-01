package keychain

import "github.com/lox/keyring/v2"

type Item = keyring.Item
type Metadata = keyring.Metadata
type PromptFunc = keyring.PromptFunc

const KeychainBackend = keyring.KeychainBackend

var (
	ErrAccessDenied             = keyring.ErrAccessDenied
	ErrKeyNotFound              = keyring.ErrKeyNotFound
	ErrMetadataNeedsCredentials = keyring.ErrMetadataNeedsCredentials
)
