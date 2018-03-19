package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/valakuzhyk/cryptopals/aes"
	"github.com/valakuzhyk/cryptopals/utils"
	"github.com/valakuzhyk/cryptopals/xor"
)

func TestSet1Challenge7(t *testing.T) {
	absPath, _ := filepath.Abs("../cryptopals/data/Set1Challenge7.txt")
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

	ecbEncrypter := utils.NewECBDecrypter(blockCipher)

	output := make([]byte, len(fileData))
	ecbEncrypter.CryptBlocks(output, fileData)
	if !strings.HasPrefix(string(output), SongLyrics) {
		t.Fatal("Answer is not correct")
	}
}

func TestECBModeAES(t *testing.T) {
	input := []byte("THIS IS HOW WE D")
	key := []byte("YELLOW SUBMARINE")

	// Encrypt
	blockCipher, err := aes.NewBlockCipher(key)
	if err != nil {
		t.Fatal("Unable to create aes block cipher")
	}

	ecbEncrypter := utils.NewECBEncrypter(blockCipher)

	encrypted := make([]byte, len(input))
	ecbEncrypter.CryptBlocks(encrypted, input)

	// DEcrypt
	blockCipher2, err := aes.NewBlockCipher(key)
	if err != nil {
		t.Fatal("Unable to create aes block cipher")
	}

	ecbDecrypter := utils.NewECBDecrypter(blockCipher2)

	output := make([]byte, len(encrypted))
	ecbDecrypter.CryptBlocks(output, encrypted)

	if string(output) != string(input) {
		t.Fatal("Instead, got ", string(output))
	}
}

func TestSet1Challenge6(t *testing.T) {
	absPath, _ := filepath.Abs("../cryptopals/data/Set1Challenge6.txt")
	base64Str, err := ioutil.ReadFile(absPath)
	if err != nil {
		t.Fatal("Unable to open data file")
	}
	ciphertext, err := utils.Base64ToBytes(string(base64Str))
	if err != nil {
		t.Fatal("Failed to decode string", err)
	}
	solutions := xor.Decrypt(ciphertext)

	if solutions.Plaintext != SongLyrics {
		t.Log("Plaintext does not match the desired output\n")
		lines1 := strings.Split(solutions.Plaintext, "\n")
		lines2 := strings.Split(SongLyrics, "\n")
		if len(lines1) != len(lines2) {
			t.Fatal("They don't even have the same number of lines...")
		}
		for i := range lines1 {
			if lines1[i] != lines2[i] {
				t.Errorf("Line1: %s\nLine2: %s\n", lines1[i], lines2[i])
			}
		}
	}
}

func TestSet1Challenge5(t *testing.T) {
	input := "Burning 'em, if you ain't quick and nimble\n" +
		"I go crazy when I hear a cymbal"

	encrypted := xor.RepeatingXor([]byte(input), []byte("ICE"))
	got := hex.EncodeToString(encrypted)
	want := "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
	if got != want {
		if len(got) != len(want) {
			t.Fatal("len(got):", len(got), "len(want): ", len(want))
		}
		t.Fatal("Got: ", got)
	}
}

func TestSet1Challenge4(t *testing.T) {
	absPath, _ := filepath.Abs("../cryptopals/data/Set1Challenge4.txt")
	file, err := os.Open(absPath)
	if err != nil {
		t.Fatal("Unable to open data file")
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var decodedStrings []string
	for scanner.Scan() {
		str := scanner.Text()
		bytes, err := hex.DecodeString(str)
		if err != nil {
			t.Fatal("For some reason, there was a failure decoding the string.")
		}
		soln := xor.DecodeEnglishFrom1ByteXor(bytes)
		decodedStrings = append(decodedStrings, string(soln.Plaintext))
	}

	sort.Slice(decodedStrings, func(i, j int) bool {
		return utils.EnglishScore(decodedStrings[i]) < utils.EnglishScore(decodedStrings[j])
	})
	fmt.Println("The Final answer?: ")
	if decodedStrings[0] != "Now that the party is jumping\n" {
		t.Fatal("The final string found was : ", decodedStrings[0], " instead of ", "Now that the party is jumping")
	}
}

func TestSet1Challenge3(t *testing.T) {
	bytes1, err := hex.DecodeString("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
	if err != nil {
		fmt.Println("Error decoding hex", err)
	}
	soln := xor.DecodeEnglishFrom1ByteXor(bytes1)
	if string(soln.Plaintext) != "Cooking MC's like a pound of bacon" {
		t.Fatal("Got this string instead: ", string(soln.Plaintext))
	}
}

func TestSet1Challenge2(t *testing.T) {
	bytes1, err := hex.DecodeString("1c0111001f010100061a024b53535009181c")
	if err != nil {
		fmt.Println("Error decoding hex", err)
	}
	bytes2, err := hex.DecodeString("686974207468652062756c6c277320657965")
	if err != nil {
		fmt.Println("Error decoding hex", err)
	}
	output := hex.EncodeToString(xor.Xor(bytes1, bytes2))
	if output != "746865206b696420646f6e277420706c6179" {
		t.FailNow()
	}
}

func TestSet1Challenge1(t *testing.T) {
	bytes, err := hex.DecodeString("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
	if err != nil {
		fmt.Println("Error decoding hex", err)
	}
	output := utils.BytesToBase64(bytes)
	if output != "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t" {
		t.FailNow()
	}
}
