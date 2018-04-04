package main

import (
	"crypto/rand"
	"log"
	"math/big"
	"testing"

	"github.com/valakuzhyk/cryptopals/vcipher"
)

func TestSet3Challenge17(t *testing.T) {
	possibleStrings := []string{
		"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
		"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
		"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
		"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
		"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
		"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
		"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
		"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
		"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
		"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
	}

	numByteOffset, err := rand.Int(rand.Reader, big.NewInt(10))
	if err != nil {
		log.Fatal("Issue computing random int: ", err)
	}
	stringToUse := possibleStrings[int(numByteOffset.Uint64())]

	e := vcipher.RandomEncrypter{}
	e.RandomizeIV()
	e.RandomizeKey()
	e.SetEncryptionMode(vcipher.CBC_ENCODE)
	encryptedString := e.Encrypt([]byte(stringToUse))

	// Now, time to create the CBC oracle
	e.SetEncryptionMode(vcipher.CBC_DECODE)
	oracle := vcipher.NewCBCOracle(e)

	plaintext := vcipher.DecodeCBCWithPaddingOracle(ciphertext, oracle)

}
