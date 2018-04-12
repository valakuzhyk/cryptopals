package vcipher

import (
	"bytes"
	"crypto/cipher"

	"github.com/valakuzhyk/cryptopals/xor"
)

// CrackCTRPlaintextWithEdit allows an aes ctr cipher to be cracked through the used of the
// EditCiphertext function.
func CrackCTRPlaintextWithEdit(ctrCipher cipher.Stream, ciphertext []byte) []byte {
	cipherTextToRewrite := make([]byte, len(ciphertext))
	newText := bytes.Repeat([]byte("A"), len(ciphertext))
	copy(cipherTextToRewrite, ciphertext)
	newCipherText := EditCiphertext(cipherTextToRewrite, ctrCipher, 0, newText)

	// The new ciphertext will be encrypted with the same keystream. It has to in order for it
	// to be decrypted correctly. If we know the entire plaintext, we can then find out what the original
	// keystream was, and using that we can easily find the plaintext.
	keyStream := xor.Xor(newCipherText, newText)
	plainText := xor.Xor(keyStream, ciphertext)

	return plainText
}
