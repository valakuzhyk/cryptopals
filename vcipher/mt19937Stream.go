package vcipher

import (
	"crypto/cipher"
	"encoding/binary"
	"log"
	"math"

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

	return &mt19937Encrypter{vrandom.NewMersenneTwister(uint32(seedAsInt))}, nil
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

// We assume that the key is less than 16 bits, and that we have some controlled
// plaintext that was appended before being encrypted.
func BruteForceMT19937(ciphertext []byte, controlledPlaintextLen int) []byte {
	if controlledPlaintextLen < 8 {
		log.Fatal("Just tryina make my life a little easier for this silly challenge.")
	}

	// Find how many bytes were used on the unknown portion
	lastControlledDwordIndex := (len(ciphertext) / 4) - 1
	lastControlledDword := ciphertext[lastControlledDwordIndex*4 : (lastControlledDwordIndex+1)*4]

	// We are just assuming here that the controlledPlaintext is all "A"
	expectedBytes := xor.RepeatingXor(lastControlledDword, []byte("A"))
	expectedNumber := binary.LittleEndian.Uint32(expectedBytes)
	expectedIndex := lastControlledDwordIndex

	for i := 0; i < math.MaxUint16; i++ {
		mt := vrandom.NewMersenneTwister(uint32(i))
		for i := 0; i < expectedIndex; i++ {
			mt.Rand()
		}
		gotNumber := mt.Rand()

		if gotNumber == expectedNumber {
			seed := make([]byte, 2)
			binary.LittleEndian.PutUint16(seed, uint16(i))
			return seed
		}
	}
	return []byte{}
}
