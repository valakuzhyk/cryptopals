package vcipher

import (
	"log"
	"strings"

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

// ECBCutAndPaste does a cut and paste attack that take a string and
// append the desired string?
func ECBCutAndPaste(encrypter AccountEncoder) []byte {
	blockSize := encrypter.GetBlockSize()
	// First, we need to get a block that can be used to set the admin field
	firstBlock := strings.Repeat("A", blockSize-len("email="))
	secondBlock := utils.AddPKCS7Padding("admin", blockSize)
	constructedLastBlock := encrypter.Encrypt(firstBlock + secondBlock)
	lastBlock := utils.GetNthBlock(constructedLastBlock, 1, blockSize)

	// Now, we get the encrypted string that we want, with the last block containing
	// the string that we want to control.
	beginningRemainingString := "email=A"
	endRemainingString := "@fake.com&uid=10&role="
	lengthOfRemainingString := len(beginningRemainingString) + len(endRemainingString)

	neededChars := blockSize - (lengthOfRemainingString % blockSize)
	// We want to get the offset to be a multiple of this number
	fakeUsername := "A" + strings.Repeat("A", neededChars) + "@fake.com"
	encryptedBlocks := encrypter.Encrypt(fakeUsername)

	// Put the block we computed in the first step at the end of this set of
	desiredBytes := append(
		encryptedBlocks[:len(encryptedBlocks)-blockSize],
		lastBlock...)
	return desiredBytes
}
