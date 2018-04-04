package vcipher

import (
	"github.com/valakuzhyk/cryptopals/utils"
)

// CBCPaddingOracle returns true if a given ciphertext has appropriate padding.
// This can be used to mount an attack on CBC.
func CBCPaddingOracle(ciphertext, key, iv []byte) bool {
	e := RandomEncrypter{}
	e.Key = key
	e.IV = iv
	e.SetEncryptionMode(CBC_DECODE)
	e.SetIgnorePadding(true)
	decrypted := e.Encrypt(ciphertext)

	validPadding, _ := utils.RemovePKCS7Padding(string(decrypted), e.GetBlockSize())
	return validPadding
}
