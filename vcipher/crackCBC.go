package vcipher

import (
	"log"

	"github.com/valakuzhyk/cryptopals/utils"
)

// Oracle is a struct that is a source of groundtruth about something relating
// to a encryption scheme. Oftentimes, the information that is leaked out of
// an oracle can be used to gain greater understanding of ciphertext, or to
// manipulate ciphertext for your own gain.
type Oracle struct {
	encrypter RandomEncrypter
}

// NewCBCOracle returns an oracle that returns properties of a CBC
// cipher.
func NewCBCOracle(encrypter RandomEncrypter) Oracle {
	if encrypter.Mode != CBC_DECODE {
		log.Fatal("Hey now. Hey now... wrong mode.")
	}
	encrypter.SetIgnorePadding(true)
	return Oracle{encrypter}
}

// HasValidPadding returns true if a given ciphertext has appropriate padding.
// This can be used to mount an attack on CBC.
func (o Oracle) HasValidPadding(ciphertext []byte) bool {
	decrypted := o.encrypter.Encrypt(ciphertext)
	validPadding, _ := utils.RemovePKCS7Padding(string(decrypted), o.encrypter.GetBlockSize())
	return validPadding
}

// DecodeCBCWithPaddingOracle returns the plaintext from ciphertext given that you have an oracle
// that tells you whether the padding on a given message is valid.
func DecodeCBCWithPaddingOracle(ciphertext []byte, oracle Oracle) []byte {
	log.Println("Not implemented yet! But will be soon :)")
	return []byte{}
}
