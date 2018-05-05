package main

import (
	"bytes"
	"io/ioutil"
	"log"
	"path/filepath"
	"strings"
	"testing"

	"github.com/valakuzhyk/cryptopals/data"
	"github.com/valakuzhyk/cryptopals/xor"

	"github.com/valakuzhyk/cryptopals/aes"
	"github.com/valakuzhyk/cryptopals/utils"
	"github.com/valakuzhyk/cryptopals/vcipher"
)

func TestSet4Challenge27(t *testing.T) {
	// CBC Key as IV
	e := vcipher.AppendEncrypter{}
	e.Key = []byte("ASDFGHJKLQWERTYU")
	e.IV = e.Key
	e.SetEncryptionMode(vcipher.CBC_ENCODE)

	blockSize := vcipher.CalculateBlockSize(e.Encrypt)

	// This is our scratch space. We will scramble the first block that we write,
	// by modifying it with our desired message. This will insert our message into the next block.
	input := []byte(strings.Repeat("A", blockSize*3))

	encryptedInput := e.Encrypt(input)

	block := utils.GetNthBlock(encryptedInput, 1, blockSize)
	zeroBlock := bytes.Repeat([]byte{0}, blockSize)
	constructedCiphertext := append(
		block,
		append(zeroBlock, block...)...)

	e.SetEncryptionMode(vcipher.CBC_DECODE)
	e.SetBeginBytes([]byte{})
	e.SetEndBytes([]byte{})
	unencryptedData := e.Encrypt(constructedCiphertext)
	log.Println(string(unencryptedData))
	if utils.IsValidASCII(unencryptedData) {
		t.Fatal("Didn't cause an error, so it did not disclose the key")
	}
	firstDecodedBlock := utils.GetNthBlock(unencryptedData, 0, blockSize)
	lastDecodedBlock := utils.GetNthBlock(unencryptedData, 2, blockSize)
	calculatedKey := xor.Xor(firstDecodedBlock, lastDecodedBlock)
	log.Println(string(calculatedKey))

	if string(e.Key) != string(calculatedKey) {
		t.Fatal("Unfortunate. You had so much potential.")
	}
}

func TestSet4Challenge26(t *testing.T) {
	// CBC Bitflipping
	e := vcipher.AppendEncrypter{}
	e.Key = []byte("ASDFGHJKLQWERTYU")
	e.IV = []byte("12345678")
	startBytes := []byte("comment1=cooking%20MCs;userdata=")
	e.SetBeginBytes(startBytes)
	e.SetEndBytes([]byte(";comment2=%20like%20a%20pound%20of%20bacon"))
	e.SetEncryptionMode(vcipher.CTR)

	// This is our scratch space. We will scramble the first block that we write,
	// by modifying it with our desired message. This will insert our message into the next block.
	desiredInput := "v;admin=true"
	input := strings.Repeat("\x00", len(desiredInput))

	// This is the step that prevents you from just specifying you are admin.
	input = strings.Replace(input, ";", "", -1)
	input = strings.Replace(input, "=", "", -1)
	encryptedInput := e.Encrypt([]byte(input))

	// Time to simply xor our message in... seems way too easy.
	offset := len(startBytes)
	for i := 0; i < len(input); i++ {
		encryptedInput[i+offset] ^= desiredInput[i]
	}

	e.SetBeginBytes([]byte{})
	e.SetEndBytes([]byte{})
	unencryptedData := e.Encrypt(encryptedInput)
	log.Println(string(unencryptedData))

	propertyMap := map[string]string{}
	tuples := strings.Split(string(unencryptedData), ";")
	for _, tuple := range tuples {
		log.Println(tuple)
		keyValue := strings.Split(tuple, "=")
		if len(keyValue) != 2 {
			t.Fatalf("Invalid format %s", tuple)
		}
		propertyMap[keyValue[0]] = keyValue[1]
	}
	log.Println(propertyMap)
	if propertyMap["admin"] != "true" {
		t.Fatal("Unfortunate. You had so much potential.")
	}
}

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
