package main

import (
	"bytes"
	"io/ioutil"
	"log"
	"path/filepath"
	"testing"

	"github.com/valakuzhyk/cryptopals/data"

	"github.com/valakuzhyk/cryptopals/aes"
	"github.com/valakuzhyk/cryptopals/utils"
	"github.com/valakuzhyk/cryptopals/vcipher"
)

func TestSet4Challenge25(t *testing.T) {
	absPath, err := filepath.Abs("../cryptopals/data/Set2Challenge10.txt")
	if err != nil {
		t.Fatal("Couldn't get file path", err)
	}
	base64Str, err := ioutil.ReadFile(absPath)
	if err != nil {
		t.Fatal("Unable to open data file", err)
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

	iv := bytes.Repeat([]byte{0x00}, blockCipher.BlockSize())
	ecbDecrypter, err := vcipher.NewCBCDecrypter(blockCipher, iv)
	if err != nil {
		t.Fatal("unable to create CBC decrypter: ", err)
	}

	output := make([]byte, len(fileData))
	ecbDecrypter.CryptBlocks(output, fileData)
	success, depaddedOutput := utils.RemovePKCS7Padding(string(output), 16)
	if !success {
		t.Fatal("Pretty sure there was padding there ")
	}
	output = []byte(depaddedOutput)

	key = utils.GetRandomBytes(16)
	blockCipher, err = aes.NewBlockCipher(key)
	if err != nil {
		t.Fatal("Unable to create aes block cipher", err)
	}

	nonce := bytes.Repeat([]byte("\x00"), 8)
	ctrEncrypter, err := vcipher.NewCTREncrypter(blockCipher, nonce)
	if err != nil {
		t.Fatal("Unable to create a CTR encrypter", err)
	}

	encryptedData := make([]byte, len(output))
	ctrEncrypter.XORKeyStream(encryptedData, output)

	plainText := vcipher.CrackCTRPlaintextWithEdit(ctrEncrypter, encryptedData)
	if string(plainText) != data.SongLyrics {
		log.Fatal("Couldn't get the lyrics")
	}
}
