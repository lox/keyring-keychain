package keychain

import (
	"bytes"
	"testing"
)

func TestEnvelopeRoundTrip(t *testing.T) {
	t.Parallel()

	keyBlob := bytes.Repeat([]byte{0xAB}, 427)
	ciphertext := []byte("ciphertext bytes")

	data, err := encodeEnvelope(keyBlob, ciphertext)
	if err != nil {
		t.Fatalf("encodeEnvelope: %v", err)
	}

	gotBlob, gotCiphertext, ok := decodeEnvelope(data)
	if !ok {
		t.Fatal("decodeEnvelope: expected ok")
	}
	if !bytes.Equal(gotBlob, keyBlob) {
		t.Errorf("key blob mismatch: got %d bytes, want %d", len(gotBlob), len(keyBlob))
	}
	if !bytes.Equal(gotCiphertext, ciphertext) {
		t.Errorf("ciphertext mismatch: got %q, want %q", gotCiphertext, ciphertext)
	}
}

func TestEnvelopeEmptyCiphertext(t *testing.T) {
	t.Parallel()

	data, err := encodeEnvelope([]byte{0x01}, nil)
	if err != nil {
		t.Fatalf("encodeEnvelope: %v", err)
	}
	blob, ciphertext, ok := decodeEnvelope(data)
	if !ok {
		t.Fatal("decodeEnvelope: expected ok")
	}
	if !bytes.Equal(blob, []byte{0x01}) {
		t.Errorf("key blob mismatch: got %v", blob)
	}
	if len(ciphertext) != 0 {
		t.Errorf("expected empty ciphertext, got %v", ciphertext)
	}
}

func TestEnvelopeKeyBlobTooLarge(t *testing.T) {
	t.Parallel()

	if _, err := encodeEnvelope(make([]byte, 1<<16), nil); err == nil {
		t.Fatal("expected error for oversized key blob")
	}
}

func TestDecodeEnvelopeRejectsNonEnvelopes(t *testing.T) {
	t.Parallel()

	cases := map[string][]byte{
		"nil":            nil,
		"empty":          {},
		"plain text":     []byte("hunter2"),
		"magic only":     envelopeMagic,
		"truncated len":  append(append([]byte{}, envelopeMagic...), 0x00),
		"truncated blob": append(append([]byte{}, envelopeMagic...), 0x00, 0x10, 0x01),
		"almost magic":   {0x00, 'k', 'r', 's', 'e', '2'},
		"leading nul":    {0x00, 0x01, 0x02},
	}
	for name, data := range cases {
		if _, _, ok := decodeEnvelope(data); ok {
			t.Errorf("%s: expected not ok", name)
		}
	}
}
