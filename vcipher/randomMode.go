package vcipher

import (
	"bytes"
	"crypto/cipher"
	"log"

	"github.com/valakuzhyk/cryptopals/utils"

	"github.com/valakuzhyk/cryptopals/aes"
)

// EncryptionMode decides what mode will be used when Encrypt is called.
type EncryptionMode int

const (
	RANDOM_ENCODE EncryptionMode = iota
	ECB_ENCODE
	ECB_DECODE
	CBC_ENCODE
	CBC_DECODE
	CTR
)

// RandomEncrypter is a utility class to quickly create and use AES encrypters in different
// modes.
type RandomEncrypter struct {
	Mode          EncryptionMode
	Key           []byte
	IV            []byte
	ignorePadding bool
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
	e.Key = utils.GetRandomBytes(e.GetBlockSize())
}

// RandomizeIV randomly sets the iv
func (e *RandomEncrypter) RandomizeIV() {
	e.IV = utils.GetRandomBytes(e.GetBlockSize())
}

// GetBlockSize returns the block size used in the encrypter.
func (e *RandomEncrypter) GetBlockSize() int {
	return 16
}

// SetIgnorePadding sets whether or not padding should be ignored.
func (e *RandomEncrypter) SetIgnorePadding(setting bool) {
	e.ignorePadding = setting
}

// Encrypt encrypts the input under the given settings.
func (e RandomEncrypter) Encrypt(input []byte) []byte {
	aesCipher, err := aes.NewBlockCipher(e.Key)
	if err != nil {
		log.Fatal("Couldn't get block cipher to work", err)
	}

	var encrypter cipher.BlockMode
	switch e.Mode {
	case ECB_ENCODE:
		encrypter = NewECBEncrypter(aesCipher)
	case ECB_DECODE:
		encrypter = NewECBDecrypter(aesCipher)
	case CBC_ENCODE:
		encrypter, err = NewCBCEncrypter(aesCipher, e.IV)
		if err != nil {
			log.Fatal("CBC encrypter failed ", err)
		}
	case CBC_DECODE:
		encrypter, err = NewCBCDecrypter(aesCipher, e.IV)
		if err != nil {
			log.Fatal("CBC Decrypter failed ", err)
		}
	case CTR:
		streamCipher, err := NewCTREncrypter(aesCipher, e.IV)
		if err != nil {
			log.Fatal("CTR mode failed ", err)
		}
		output := make([]byte, len(input))
		streamCipher.XORKeyStream(output, input)
		return output
	default:
		log.Fatal("invalid mode ", e.Mode)
	}

	if e.isEncoding() && !e.ignorePadding {
		input = []byte(utils.AddPKCS7Padding(string(input), encrypter.BlockSize()))
	}
	output := make([]byte, len(input))
	encrypter.CryptBlocks(output, input)

	if e.isDecoding() && !e.ignorePadding {
		_, outputString := utils.RemovePKCS7Padding(string(output), encrypter.BlockSize())
		output = []byte(outputString)
	}
	return output
}

func (e RandomEncrypter) isEncoding() bool {
	return e.Mode == CBC_ENCODE || e.Mode == ECB_ENCODE
}

func (e RandomEncrypter) isDecoding() bool {
	return e.Mode == CBC_DECODE || e.Mode == ECB_DECODE
}

// EncryptwithRandomPaddingAndKey randomly pads information given and encodes in either
// ECB or CBC mode.
func (e AppendEncrypter) EncryptwithRandomPaddingAndKey(input []byte) []byte {
	e.SetBeginBytes(utils.GetRandomBytesBetween(5, 10))
	e.SetEndBytes(utils.GetRandomBytesBetween(5, 10))
	e.RandomizeKey()

	return e.RandomEncrypter.Encrypt(input)
}

// ECBvsCBCOracle identifies whether or not the function passed in
// encrypts using ECB or CBC
func ECBvsCBCOracle(encrypterFunction func(input []byte) []byte) EncryptionMode {
	// If we send a bunch of the same character, if this is encrypting in ECB,
	// the middle blocks would be the same.
	bytesToInput := bytes.Repeat([]byte("A"), 100)
	encryptedBytes := encrypterFunction(bytesToInput)
	repeats := CountRepeats(string(encryptedBytes), 16)
	if repeats > 0 {
		return ECB_ENCODE
	}
	return CBC_ENCODE
}
