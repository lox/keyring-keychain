package keychain

import (
	"log"

	"github.com/lox/keyring/v2"
)

func debugf(pattern string, args ...any) {
	if keyring.Debug {
		log.Printf("[keyring] "+pattern, args...)
	}
}
