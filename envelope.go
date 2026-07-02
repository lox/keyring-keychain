package keychain

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
)

// envelopeMagic marks item data that is envelope-encrypted to a Secure
// Enclave key. The leading NUL keeps the marker out of the printable-text
// space to make collisions with real secrets vanishingly unlikely.
var envelopeMagic = []byte{0x00, 'k', 'r', 's', 'e', '1'}

// encodeEnvelope packs a Secure Enclave key blob and the ciphertext it
// decrypts into a single self-contained payload:
//
//	magic (6 bytes) | key blob length (uint16 BE) | key blob | ciphertext
func encodeEnvelope(keyBlob, ciphertext []byte) ([]byte, error) {
	if len(keyBlob) > math.MaxUint16 {
		return nil, fmt.Errorf("keychain: Secure Enclave key blob too large: %d bytes", len(keyBlob))
	}
	out := make([]byte, 0, len(envelopeMagic)+2+len(keyBlob)+len(ciphertext))
	out = append(out, envelopeMagic...)
	out = binary.BigEndian.AppendUint16(out, uint16(len(keyBlob)))
	out = append(out, keyBlob...)
	out = append(out, ciphertext...)
	return out, nil
}

// decodeEnvelope unpacks a payload produced by encodeEnvelope. It reports
// ok=false if data is not an envelope.
func decodeEnvelope(data []byte) (keyBlob, ciphertext []byte, ok bool) {
	if !bytes.HasPrefix(data, envelopeMagic) {
		return nil, nil, false
	}
	rest := data[len(envelopeMagic):]
	if len(rest) < 2 {
		return nil, nil, false
	}
	n := int(binary.BigEndian.Uint16(rest))
	rest = rest[2:]
	if len(rest) < n {
		return nil, nil, false
	}
	return rest[:n], rest[n:], true
}
