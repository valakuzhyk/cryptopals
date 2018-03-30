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
	RANDOM_ENCODE EncryptionMode = iota
	ECB_ENCODE
	ECB_DECODE
	CBC_ENCODE
	CBC_DECODE
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
		return ECB_ENCODE
	}
	return CBC_ENCODE
}

type RandomEncrypter struct {
	Mode EncryptionMode
	Key  []byte
}

// SetEncryptionMode sets what kind of encryption the Encrypt function does.
func (e *RandomEncrypter) SetEncryptionMode(newMode EncryptionMode) EncryptionMode {
	if newMode == RANDOM_ENCODE {
		randByte := GetRandomBytes(1)
		if randByte[0] > 127 {
			newMode = ECB_ENCODE
		} else {
			newMode = CBC_ENCODE
		}
	}
	e.Mode = newMode
	return e.Mode
}

// RandomizeKey randomly sets the key
func (e *RandomEncrypter) RandomizeKey() {
	e.Key = GetRandomBytes(16)
}

func (e RandomEncrypter) Encrypt(input []byte) []byte {
	aesCipher, err := aes.NewBlockCipher(e.Key)
	if err != nil {
		log.Fatal("Couldn't get block cipher to work", err)
	}

	var encrypter cipher.BlockMode
	if e.Mode == ECB_ENCODE {
		encrypter = NewECBEncrypter(aesCipher)
	} else if e.Mode == ECB_DECODE {
		encrypter = NewECBDecrypter(aesCipher)
	} else if e.Mode == CBC_ENCODE {
		encrypter, err = NewCBCEncrypter(aesCipher, GetRandomBytes(16))
		if err != nil {
			log.Fatal("CBC encrypter failed ", err)
		}
	} else if e.Mode == CBC_DECODE {
		encrypter, err = NewCBCDecrypter(aesCipher, GetRandomBytes(16))
		if err != nil {
			log.Fatal("CBC Decrypter failed ", err)
		}
	} else {
		log.Fatal("invalid mode ", e.Mode)
	}
	if e.Mode == ECB_ENCODE || e.Mode == CBC_ENCODE {
		input = []byte(utils.AddPKCS7Padding(string(input), encrypter.BlockSize()))
	}
	output := make([]byte, len(input))
	encrypter.CryptBlocks(output, input)

	if e.Mode == ECB_DECODE || e.Mode == CBC_DECODE {
		_, outputString := utils.RemovePKCS7Padding(string(output), encrypter.BlockSize())
		output = []byte(outputString)
	}
	return output
}

// RandomEncrypter randomly pads information given and encodes in either
// ECB or CBC mode.
func (e RandomEncrypter) EncryptwithRandomKey(input []byte) []byte {
	frontBytes := GetRandomBytesBetween(5, 10)
	input = append(frontBytes, input...)

	endBytes := GetRandomBytesBetween(5, 10)
	input = append(input, endBytes...)
	e.RandomizeKey()

	return e.Encrypt(input)
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
