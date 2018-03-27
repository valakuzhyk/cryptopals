package main

import (
	"io/ioutil"
	"log"
	"path/filepath"
	"strings"
	"testing"

	"github.com/valakuzhyk/cryptopals/aes"
	"github.com/valakuzhyk/cryptopals/data"
	"github.com/valakuzhyk/cryptopals/utils"
	"github.com/valakuzhyk/cryptopals/vcipher"
)

func TestSet2Challenge13(t *testing.T) {
	accountEncoder := vcipher.NewAccountEncoder()
	output := accountEncoder.Encrypt("myemail@gmail.com")
	decodedOutput := accountEncoder.Decrypt(output)
	if decodedOutput["role"] != "admin" {
		log.Println(decodedOutput)
		t.Fatal("Unable to convert account to admin")
	}
}

func TestSet2Challenge12(t *testing.T) {
	unknownString := "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
	unknownBytes, err := utils.Base64ToBytes(unknownString)
	if err != nil {
		log.Fatal("Couldn't decode base64: ", err)
	}
	e := vcipher.AppendEncrypter{}
	e.SetEndBytes(unknownBytes)
	e.RandomizeKey()
	e.SetEncryptionMode(vcipher.ECB_ENCODE)
	bytes := vcipher.IdentifyHiddenAppendedBytes(e)
	if string(bytes) != string(unknownBytes) {
		t.Fatal("unable to find the appended bytes by iterative decoding")
	}
}

func TestSet2Challenge11(t *testing.T) {
	// Implement ECB/CBC oracle
	randomEncrypter := vcipher.RandomEncrypter{}
	wantMode := randomEncrypter.SetEncryptionMode(vcipher.RANDOM_ENCODE)
	getMode := vcipher.ECBvsCBCOracle(randomEncrypter.EncryptwithRandomKey)
	if wantMode != getMode {
		t.Fatalf("Wanted %d, got %d", wantMode, getMode)
	}
}

func TestSet2Challenge10(t *testing.T) {
	// Implement CBC
	absPath, _ := filepath.Abs("../cryptopals/data/Set2Challenge10.txt")
	base64Str, err := ioutil.ReadFile(absPath)
	if err != nil {
		t.Fatal("Unable to open data file")
	}
	fileData, err := utils.Base64ToBytes(string(base64Str))
	if err != nil {
		t.Fatal("Failed to decode string", err)
	}

	key := []byte("YELLOW SUBMARINE")

	blockCipher, err := aes.NewBlockCipher(key)
	if err != nil {
		t.Fatal("Unable to create aes block cipher")
	}

	iv := strings.Repeat("\x00", blockCipher.BlockSize())
	ecbDecrypter, err := vcipher.NewCBCDecrypter(blockCipher, []byte(iv))
	if err != nil {
		t.Fatal("unable to create CBC decrypter: ", err)
	}

	output := make([]byte, len(fileData))
	ecbDecrypter.CryptBlocks(output, fileData)
	if !strings.HasPrefix(string(output), data.SongLyrics) {
		log.Println(len(output), string(output))
		t.Fatal("Answer is not correct")
	}
}
func TestSet2Challenge9(t *testing.T) {
	// Implement PKCS Padding
	paddedString := utils.AddPKCS7Padding("YELLOW SUBMARINE", 20)
	if paddedString != "YELLOW SUBMARINE\x04\x04\x04\x04" {
		t.Fatal("The padding is all wrong... all wrong.")
	}
}
