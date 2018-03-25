package vcipher

import (
	"crypto/cipher"
	"crypto/rand"
	"log"
	"math/big"
	"strings"

	"github.com/valakuzhyk/cryptopals/utils"

	"github.com/valakuzhyk/cryptopals/aes"
)

type EncryptionMode int

const (
	RANDOM EncryptionMode = iota
	ECB_MODE
	CBC_MODE
)

// ECBvsCBCOracle identifies whether or not the function passed in
// encrypts using ECB or CBC
func ECBvsCBCOracle(encrypterFunction func(input []byte) []byte) EncryptionMode {
	// If we send a bunch of the same character, if this is encrypting in ECB,
	// the middle blocks would be the same.
	bytesToInput := []byte(strings.Repeat("A", 100))
	encryptedBytes := encrypterFunction(bytesToInput)
	repeats := CountRepeats(string(encryptedBytes), 16)
	if repeats > 0 {
		return ECB_MODE
	}
	return CBC_MODE
}

type RandomEncrypter struct {
	Mode EncryptionMode
}

// SetEncryptionMode sets what kind of encryption the Encrypt function does.
func (e *RandomEncrypter) SetEncryptionMode(newMode EncryptionMode) EncryptionMode {
	if newMode == RANDOM {
		randByte := GetRandomBytes(1)
		if randByte[0] > 127 {
			newMode = ECB_MODE
		} else {
			newMode = CBC_MODE
		}
	}
	e.Mode = newMode
	return e.Mode
}

// RandomEncrypter randomly pads information given and encodes in either
// ECB or CBC mode.
func (e RandomEncrypter) Encrypt(input []byte) []byte {
	frontBytes := GetRandomBytesBetween(5, 10)
	input = append(frontBytes, input...)

	endBytes := GetRandomBytesBetween(5, 10)
	input = append(input, endBytes...)

	key := GetRandomBytes(16)
	aesCipher, err := aes.NewBlockCipher(key)
	if err != nil {
		log.Println("Couldn't get block cipher to work", err)
	}

	var encrypter cipher.BlockMode
	if e.Mode == ECB_MODE {
		encrypter = NewECBEncrypter(aesCipher)
	} else if e.Mode == CBC_MODE {
		encrypter, err = NewCBCEncrypter(aesCipher, GetRandomBytes(16))
		if err != nil {
			log.Fatal("CBC encrypter failed ", err)
		}
	} else {
		log.Fatal("invalid mode ", e.Mode)
	}
	paddedInput := utils.AddPKCS7Padding(string(input), encrypter.BlockSize())
	output := make([]byte, len(paddedInput))
	encrypter.CryptBlocks(output, []byte(paddedInput))
	return output
}

// GetRandomBytes returns a number of random bytes between min and max
func GetRandomBytesBetween(min, max int) []byte {
	maxIntSize := big.NewInt(int64(max - min))
	numByteOffset, err := rand.Int(rand.Reader, maxIntSize)
	if err != nil {
		log.Fatal("Issue computing random int: ", err)
	}
	numBytes := min + int(numByteOffset.Uint64())

	return GetRandomBytes(numBytes)
}

func GetRandomBytes(numBytes int) []byte {
	randBytes := make([]byte, numBytes)
	_, err := rand.Read(randBytes)
	if err != nil {
		log.Fatal("Issue computing random bytes: ", err)
	}
	return randBytes
}
