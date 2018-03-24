package vcipher

import (
	"crypto/rand"
	"log"
	"math/big"
)

// RandomEncrypter randomly pads information given and encodes in either
// ECB or CBC mode.
func RandomEncrypter(input []byte) {
	frontBytes := GetRandomBytes(5, 10)
	input = append(frontBytes, input...)

	endBytes := GetRandomBytes(5, 10)
	input = append(input, endBytes...)
}

// GetRandomBytes returns a number of random bytes between min and max
func GetRandomBytes(min, max int) []byte {
	maxIntSize := big.NewInt(int64(max - min))
	numByteOffset, err := rand.Int(rand.Reader, maxIntSize)
	if err != nil {
		log.Fatal("Issue computing random int: ", err)
	}
	numBytes := uint64(min) + numByteOffset.Uint64()

	randBytes := make([]byte, numBytes)
	_, err = rand.Read(randBytes)
	if err != nil {
		log.Fatal("Issue computing random bytes: ", err)
	}
	return randBytes
}
