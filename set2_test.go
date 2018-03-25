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

func TestSet2Challenge11(t *testing.T) {
	// Implement ECB/CBC oracle
	randomEncrypter := vcipher.RandomEncrypter{}
	wantMode := randomEncrypter.SetEncryptionMode(vcipher.RANDOM)
	getMode := vcipher.ECBvsCBCOracle(randomEncrypter.Encrypt)
	if wantMode == getMode {
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
