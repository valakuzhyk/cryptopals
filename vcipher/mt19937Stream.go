package vcipher

import (
	"crypto/cipher"
	"encoding/binary"
	"log"

	"github.com/valakuzhyk/cryptopals/vcipher/vrandom"

	"github.com/valakuzhyk/cryptopals/xor"
)

type mt19937Encrypter struct {
	mt vrandom.MersenneTwister
}

// NewMT19937Encrypter returns an encrypter which uses the MT19937 pseudo-random
// number generation algorithm to generate a keystream which can be used in a stream
// cipher.
func NewMT19937Encrypter(seed []byte) (cipher.Stream, error) {
	if len(seed) != 2 {
		log.Fatal("This MT19937 encrypter only accepts a seed of 16 bytes")
	}
	seedAsInt := binary.LittleEndian.Uint16(seed)

	return mt19937Encrypter{vrandom.NewMersenneTwister(uint32(seedAsInt))}, nil
}

func (e mt19937Encrypter) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic("your source is larger than your destination. Doesn't work for XORKeyStream")
	}

	// Create the keystream, enough to cover the plaintext.
	fullKeyStream := []byte{}
	for i := 0; i < len(src); i += 4 {
		nextKeyStreamData := e.mt.Rand()

		nextKeyStreamBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(nextKeyStreamBytes, nextKeyStreamData)
		fullKeyStream = append(fullKeyStream, nextKeyStreamBytes...)
	}

	appropriateKeyStream := fullKeyStream[:len(src)]

	output := xor.Xor(appropriateKeyStream, src)
	for i, b := range output {
		dst[i] = b
	}
}
