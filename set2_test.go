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

// This test is flaky, I wrote the solution to this without handling the case where
// you happen to decrypt and get a special character ("=;"). So far, the only way I have thought
// to handle this is to try a new string.
func TestSet2Challenge16(t *testing.T) {
	// CBC Bitflipping
	e := vcipher.AppendEncrypter{}
	e.RandomizeKey()
	e.RandomizeIV()
	e.SetBeginBytes([]byte("comment1=cooking%20MCs;userdata="))
	e.SetEndBytes([]byte(";comment2=%20like%20a%20pound%20of%20bacon"))
	e.SetEncryptionMode(vcipher.CBC_ENCODE)

	blockSize := vcipher.CalculateBlockSize(e.Encrypt)

	// This is our scratch space. We will scramble the first block that we write,
	// by modifying it with our desired message. This will insert our message into the next block.
	input := strings.Repeat("\x00", blockSize*2)

	// This is the step that prevents you from just specifying you are admin.
	input = strings.Replace(input, ";", "", -1)
	input = strings.Replace(input, "=", "", -1)
	encryptedInput := e.Encrypt([]byte(input))

	block := utils.GetNthBlock(encryptedInput, 2, blockSize)
	desiredString := "aaaaa;admin=true"
	for i := range block {
		block[i] ^= byte(desiredString[i])
	}

	e.SetEncryptionMode(vcipher.CBC_DECODE)
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

func TestSet2Challenge15(t *testing.T) {
	// Validate PKCS #7 padding
	hasPadding, depadded := utils.RemovePKCS7Padding("ICE ICE BABY\x04\x04\x04\x04", 16)
	wantHasPadding := true
	wantDepadded := "ICE ICE BABY"
	if hasPadding != wantHasPadding || depadded != wantDepadded {
		log.Fatal("Unable to depad input correctly")
	}

	hasPadding, _ = utils.RemovePKCS7Padding("ICE ICE BABY\x05\x05\x05\x05", 16)
	wantHasPadding = false
	if hasPadding != wantHasPadding {
		log.Fatal("Thought there was padding, but there isn't")
	}

	hasPadding, _ = utils.RemovePKCS7Padding("ICE ICE BABY\x01\x02\x03\x04", 16)
	wantHasPadding = false
	if hasPadding != wantHasPadding {
		log.Fatal("andddd still no padding")
	}

}

func TestSet2Challenge14(t *testing.T) {
	unknownString := "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
	unknownBytes, err := utils.Base64ToBytes(unknownString)
	if err != nil {
		log.Fatal("Couldn't decode base64: ", err)
	}
	e := vcipher.AppendEncrypter{}
	startBytes := utils.GetRandomBytesBetween(0, 32)
	e.SetBeginBytes(startBytes)
	log.Printf("Start byte Length: %d", len(startBytes))

	e.SetEndBytes(unknownBytes)
	e.RandomizeKey()
	e.SetEncryptionMode(vcipher.ECB_ENCODE)
	bytes := vcipher.IdentifyHiddenAppendedBytes(e)
	if string(bytes) != string(unknownBytes) {
		t.Fatal("unable to find the appended bytes by iterative decoding")
	}
}

func TestSet2Challenge13(t *testing.T) {
	accountEncoder := vcipher.NewAccountEncoder()
	desiredBytes := vcipher.ECBCutAndPaste(accountEncoder)
	decodedOutput := accountEncoder.Decrypt(desiredBytes)
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
	e := vcipher.AppendEncrypter{}
	wantMode := e.SetEncryptionMode(vcipher.RANDOM_ENCODE)
	getMode := vcipher.ECBvsCBCOracle(e.EncryptwithRandomPaddingAndKey)
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
