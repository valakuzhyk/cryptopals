package vcipher

import (
	"crypto/cipher"
	"log"
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
	IV   []byte
}

// SetEncryptionMode sets what kind of encryption the Encrypt function does.
func (e *RandomEncrypter) SetEncryptionMode(newMode EncryptionMode) EncryptionMode {
	if newMode == RANDOM_ENCODE {
		randByte := utils.GetRandomBytes(1)
		e.RandomizeKey()

		if randByte[0] > 127 {
			newMode = ECB_ENCODE
		} else {
			newMode = CBC_ENCODE
			e.RandomizeIV()
		}
	}
	e.Mode = newMode
	return e.Mode
}

// RandomizeKey randomly sets the key
func (e *RandomEncrypter) RandomizeKey() {
	e.Key = utils.GetRandomBytes(16)

}

// RandomizeIV randomly sets the iv
func (e *RandomEncrypter) RandomizeIV() {
	e.IV = utils.GetRandomBytes(16)
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
		encrypter, err = NewCBCEncrypter(aesCipher, e.IV)
		if err != nil {
			log.Fatal("CBC encrypter failed ", err)
		}
	} else if e.Mode == CBC_DECODE {
		encrypter, err = NewCBCDecrypter(aesCipher, e.IV)
		if err != nil {
			log.Fatal("CBC Decrypter failed ", e.IV)
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
func (e AppendEncrypter) EncryptwithRandomPaddingAndKey(input []byte) []byte {
	e.SetBeginBytes(utils.GetRandomBytesBetween(5, 10))
	e.SetEndBytes(utils.GetRandomBytesBetween(5, 10))
	e.RandomizeKey()

	return e.RandomEncrypter.Encrypt(input)
}
