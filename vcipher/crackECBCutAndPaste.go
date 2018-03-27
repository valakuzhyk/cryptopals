package vcipher

import (
	"log"

	"github.com/valakuzhyk/cryptopals/utils"
)

// AccountEncoder (used in challenge 13) is a tool used to encode a string
// for a user. Ultimately, there is some flaw that allows us to use this
// to construct an account that has admin powers.
type AccountEncoder struct {
	RandomEncrypter
}

// NewAccountEncoder returns an initialized AccountEncoder
func NewAccountEncoder() AccountEncoder {
	e := RandomEncrypter{}
	e.RandomizeKey()
	return AccountEncoder{e}
}

// Encrypt returns the bytes after encrypting the given string
func (e AccountEncoder) Encrypt(email string) []byte {
	input := utils.ProfileFor(email)
	e.SetEncryptionMode(ECB_ENCODE)
	return e.RandomEncrypter.Encrypt([]byte(input))
}

// Decrypt returns the key value map that is encoded.
func (e AccountEncoder) Decrypt(input []byte) map[string]string {
	e.SetEncryptionMode(ECB_DECODE)
	decodedString := e.RandomEncrypter.Encrypt(input)
	kvPairs, err := utils.ParseKeyValuePairs(string(decodedString))
	if err != nil {
		log.Println("Couldn't parse: ", err)
	}
	return kvPairs
}
