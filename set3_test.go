package main

import (
	"log"
	"testing"

	"github.com/valakuzhyk/cryptopals/utils"

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

	for _, stringToUse := range possibleStrings {

		e := vcipher.RandomEncrypter{}
		e.RandomizeIV()
		e.RandomizeKey()
		e.SetEncryptionMode(vcipher.CBC_ENCODE)
		stringBytes, err := utils.Base64ToBytes(stringToUse)
		if err != nil {
			log.Fatal("Couldn't base64 decode string: ", err)
		}
		ciphertext := e.Encrypt(stringBytes)

		// Now, time to create the CBC oracle
		e.SetEncryptionMode(vcipher.CBC_DECODE)
		oracle := vcipher.NewCBCOracle(e)

		// Will recieve the plaintext here.
		decryptedText := vcipher.DecodeCBCWithPaddingOracle(e.IV, ciphertext, oracle)
		if string(decryptedText) != string(stringBytes) {
			log.Fatalf("Couldn't decode, got %s, want %s", string(decryptedText), string(stringBytes))
		}
	}

}
