package vcipher

import (
	"bytes"
	"testing"
)

func TestCBCPaddingOracle_HasPadding(t *testing.T) {
	e := RandomEncrypter{}
	e.SetEncryptionMode(CBC_ENCODE)
	e.IV = bytes.Repeat([]byte("A"), e.GetBlockSize())
	e.Key = []byte("YELLOW SUBMARINE")

	ciphertext := e.Encrypt([]byte("This is it. Please let me know."))

	want := true

	if got := CBCPaddingOracle(ciphertext, e.Key, e.IV); got != want {
		t.Errorf("CBCPaddingOracle() = %v, want %v", got, want)
	}

}

func TestCBCPaddingOracle_InvalidPadding(t *testing.T) {
	e := RandomEncrypter{}
	e.SetEncryptionMode(CBC_ENCODE)
	e.IV = bytes.Repeat([]byte("A"), e.GetBlockSize())
	e.Key = []byte("YELLOW SUBMARINE")
	e.SetIgnorePadding(true)
	ciphertext := e.Encrypt([]byte("This is it. Please let me know.\x02"))

	want := false

	if got := CBCPaddingOracle(ciphertext, e.Key, e.IV); got != want {
		t.Errorf("CBCPaddingOracle() = %v, want %v", got, want)
	}

}
