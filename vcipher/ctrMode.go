package vcipher

import (
	"crypto/cipher"
	"encoding/binary"
	"log"

	"github.com/valakuzhyk/cryptopals/xor"
)

type ctrEncrypter struct {
	blockCipher cipher.Block
	nonce       []byte
	counter     uint64
}

// NewCTREncrypter returns a CTR encrypter which uses the given blockcipher
// algorithm.
func NewCTREncrypter(block cipher.Block, nonce []byte) (cipher.Stream, error) {
	if len(nonce) != 8 {
		log.Fatal("This CTR encrypter only accepts nonce of 8 bytes")
	}

	return ctrEncrypter{blockCipher: block, nonce: nonce}, nil
}

func (e ctrEncrypter) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic("your source is larger than your destination. Doesn't work for XORKeyStream")
	}

	// Create the keystream, enough to cover the plaintext.
	fullKeyStream := []byte{}
	for i := 0; i < len(src); i += 16 {
		blockCount := make([]byte, 8)
		binary.LittleEndian.PutUint64(blockCount, e.counter)

		toEncrypt := append(e.nonce, blockCount...)

		keyStream := make([]byte, 16)
		e.blockCipher.Encrypt(keyStream, toEncrypt)
		fullKeyStream = append(fullKeyStream, keyStream...)
		e.counter++
	}

	appropriateKeyStream := fullKeyStream[:len(src)]

	output := xor.Xor(appropriateKeyStream, src)
	for i, b := range output {
		dst[i] = b
	}
}
