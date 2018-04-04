package vcipher

import (
	"bytes"
	"testing"
)

func TestHasValidPadding_true(t *testing.T) {
	e := RandomEncrypter{}
	e.SetEncryptionMode(CBC_ENCODE)
	e.IV = bytes.Repeat([]byte("A"), e.GetBlockSize())
	e.Key = []byte("YELLOW SUBMARINE")

	ciphertext := e.Encrypt([]byte("This is it. Please let me know."))

	e.SetEncryptionMode(CBC_DECODE)
	oracle := NewCBCOracle(e)

	want := true

	if got := oracle.HasValidPadding(ciphertext); got != want {
		t.Errorf("HasValidPadding() = %v, want %v", got, want)
	}

}

func TestHasValidPadding_false(t *testing.T) {
	e := RandomEncrypter{}
	e.SetEncryptionMode(CBC_ENCODE)
	e.IV = bytes.Repeat([]byte("A"), e.GetBlockSize())
	e.Key = []byte("YELLOW SUBMARINE")
	e.SetIgnorePadding(true)
	ciphertext := e.Encrypt([]byte("This is it. Please let me know.\x02"))

	e.SetEncryptionMode(CBC_DECODE)
	oracle := NewCBCOracle(e)

	want := false

	if got := oracle.HasValidPadding(ciphertext); got != want {
		t.Errorf("HasValidPadding() = %v, want %v", got, want)
	}

}
