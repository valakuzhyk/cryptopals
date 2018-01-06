package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/valakuzhyk/cryptopals/utils"
)

func TestSet1Challenge6(t *testing.T) {
	absPath, _ := filepath.Abs("../cryptopals/data/Set1Challenge6.txt")
	base64Str, err := ioutil.ReadFile(absPath)
	if err != nil {
		t.Fatal("Unable to open data file")
	}
	log.Println(base64Str)

}

func TestSet1Challenge5(t *testing.T) {
	input := "Burning 'em, if you ain't quick and nimble\n" +
		"I go crazy when I hear a cymbal"

	encrypted := utils.RepeatingXor([]byte(input), []byte("ICE"))
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
		_, decoded := utils.DecodeEnglishFrom1ByteXor(bytes)
		decodedStrings = append(decodedStrings, decoded)
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
	_, decoded := utils.DecodeEnglishFrom1ByteXor(bytes1)
	if decoded != "Cooking MC's like a pound of bacon" {
		t.Fatal("Got this string instead: ", decoded)
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
	output := hex.EncodeToString(utils.Xor(bytes1, bytes2))
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
