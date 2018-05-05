package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/valakuzhyk/cryptopals/vcipher/vrandom"
	"github.com/valakuzhyk/cryptopals/xor"

	"github.com/valakuzhyk/cryptopals/aes"
	"github.com/valakuzhyk/cryptopals/utils"

	"github.com/valakuzhyk/cryptopals/vcipher"
)

func TestSet3Challenge24(t *testing.T) {
	startingBytes := utils.GetRandomBytesBetween(1, 50)
	controlledBytes := strings.Repeat("A", 14)

	plaintext := append(startingBytes, controlledBytes...)

	seed := utils.GetRandomBytes(2)
	e, err := vcipher.NewMT19937Encrypter(seed)
	if err != nil {
		t.Fatal("Unable to create encrypter", err)
	}

	encrypted := make([]byte, len(plaintext))
	e.XORKeyStream(encrypted, plaintext)
	key := vcipher.BruteForceMT19937(encrypted, 14)
	if string(key) != string(seed) {
		t.Fatal("Couldn't brute force it :/")
	}
}

func TestSet3Challenge23(t *testing.T) {
	mt := vrandom.NewMersenneTwister(1000)
	copiedMT := vrandom.RecreateMTFromOutput(mt)
	for i := 0; i < 624; i++ {
		got := mt.Rand()
		want := copiedMT.Rand()
		if got != want {
			log.Fatalf("Got %d, want %d", got, want)
		}
	}
}

func TestSet3Challenge22(t *testing.T) {
	max := 1000
	min := 40
	maxIntSize := big.NewInt(int64(max - min))
	randNum, err := rand.Int(rand.Reader, maxIntSize)
	if err != nil {
		log.Fatal("Couldn't generate random number", err)
	}

	seed := time.Now().Unix() - randNum.Int64()
	mt := vrandom.NewMersenneTwister(uint32(seed))

	randomNumber := mt.Rand()
	gotSeed, err := vrandom.CrackMTSeededByRecentTime(vrandom.NewMersenneTwister, randomNumber, 10000)
	if err != nil {
		log.Fatal("Got error trying to find seed", err)
	}
	if uint32(seed) != gotSeed {
		log.Fatalf("Wanted %d, got %d", seed, gotSeed)
	}
}

func TestSet3Challenge21(t *testing.T) {
	mt := vrandom.NewMersenneTwister(1)

	// Received from http://create.stephan-brumme.com/mersenne-twister/
	wantFirst10 := []uint32{
		0x6AC1F425,
		0xFF4780EB,
		0xB8672F8C,
		0xEEBC1448,
		0x00077EFF,
		0x20CCC389,
		0x4D65AACB,
		0xFFC11E85,
		0x2591CB4F,
		0x3C7053C0,
	}
	for i, want := range wantFirst10 {
		got := mt.Rand()
		if want != got {
			log.Fatalf("%d iteration, want %x, got %x", i, want, got)
		}
	}
}

func TestSet3Challenge20(t *testing.T) {
	absPath, _ := filepath.Abs("../cryptopals/data/Set3Challenge20.txt")
	file, err := os.Open(absPath)
	if err != nil {
		t.Fatal("Unable to open data file")
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	blockCipher, err := aes.NewBlockCipher(utils.GetRandomBytes(16))
	if err != nil {
		t.Fatal("Unable to create aes block cipher")
	}

	minStringSize := 0
	var originalStrings []string
	var encryptedStrings []string
	for scanner.Scan() {
		str := scanner.Text()
		strBytes, err := utils.Base64ToBytes(str)
		if err != nil {
			log.Fatal(err)
		}
		originalStrings = append(originalStrings, strings.TrimSpace(string(strBytes)))
		ctrEncrypter, err := vcipher.NewCTREncrypter(blockCipher, bytes.Repeat([]byte("\x00"), 8))

		encrypted := make([]byte, len(strBytes))
		ctrEncrypter.XORKeyStream(encrypted, strBytes)
		if len(encrypted) < minStringSize {
			minStringSize = len(encrypted)
		}
		encryptedStrings = append(encryptedStrings, string(encrypted))
	}

	guessedKey := xor.GuessKey(encryptedStrings)
	encryptedFirstString := encryptedStrings[0]
	decryptedStringBytes := xor.RepeatingXor([]byte(encryptedFirstString), guessedKey)
	decryptedString := string(decryptedStringBytes[:len(encryptedFirstString)])
	// Check the first string
	if !strings.EqualFold(decryptedString, originalStrings[0]) {
		t.Fatalf("Unable to decode first string. Got: \n%s\nWant: \n%s\n", decryptedString, originalStrings[0])
	}
}

func TestSet3Challenge19(t *testing.T) {
	absPath, _ := filepath.Abs("../cryptopals/data/Set3Challenge19.txt")
	file, err := os.Open(absPath)
	if err != nil {
		t.Fatal("Unable to open data file")
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	blockCipher, err := aes.NewBlockCipher(utils.GetRandomBytes(16))
	if err != nil {
		t.Fatal("Unable to create aes block cipher")
	}

	var originalStrings []string
	var encryptedStrings []string
	for scanner.Scan() {
		str := scanner.Text()
		strBytes, err := utils.Base64ToBytes(str)
		if err != nil {
			log.Fatal(err)
		}
		originalStrings = append(originalStrings, strings.TrimSpace(string(strBytes)))
		ctrEncrypter, err := vcipher.NewCTREncrypter(blockCipher, bytes.Repeat([]byte("\x00"), 8))

		encrypted := make([]byte, len(strBytes))
		ctrEncrypter.XORKeyStream(encrypted, strBytes)
		encryptedStrings = append(encryptedStrings, string(encrypted))
	}
	guessedKey := xor.GuessKey(encryptedStrings)
	encryptedFirstString := encryptedStrings[0]
	decryptedStringBytes := xor.RepeatingXor([]byte(encryptedFirstString), guessedKey)
	decryptedString := string(decryptedStringBytes[:len(encryptedFirstString)])
	// Check the first string
	if !strings.EqualFold(decryptedString, originalStrings[0]) {
		t.Fatalf("Unable to decode first string. Got: \n%s\nWant: \n%s\n", decryptedString, originalStrings[0])
	}
}

func TestSet3Challenge18(t *testing.T) {
	toDecode := "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
	stringBytes, err := utils.Base64ToBytes(toDecode)
	if err != nil {
		log.Fatal("Couldn't base64 decode string: ", err)
	}
	cipher, err := aes.NewBlockCipher([]byte("YELLOW SUBMARINE"))
	if err != nil {
		log.Fatal("Unable to create AES block cipher: ", err)
	}
	encrypter, err := vcipher.NewCTREncrypter(cipher, bytes.Repeat([]byte{0x00}, 8))
	if err != nil {
		log.Fatal("Unable to create CTR Encrypter: ", err)
	}

	output := make([]byte, len(stringBytes))
	encrypter.XORKeyStream(output, stringBytes)
	want := "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby "
	if string(output) != want {
		log.Fatalf("Failed challenge 18, got \n%s\nwanted\n%s\n", string(output), want)
	}

}

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
