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
	"strings"
	"testing"

	"github.com/valakuzhyk/cryptopals/utils"
	"github.com/valakuzhyk/cryptopals/xor"
)

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
	want :=
		`I'm back and I'm ringin' the bell 
A rockin' on the mike while the fly girls yell 
In ecstasy in the back of me 
Well that's my DJ Deshay cuttin' all them Z's 
Hittin' hard and the girlies goin' crazy 
Vanilla's on the mike, man I'm not lazy. 

I'm lettin' my drug kick in 
It controls my mouth and I begin 
To just let it flow, let my concepts go 
My posse's to the side yellin', Go Vanilla Go! 

Smooth 'cause that's the way I will be 
And if you don't give a damn, then 
Why you starin' at me 
So get off 'cause I control the stage 
There's no dissin' allowed 
I'm in my own phase 
The girlies sa y they love me and that is ok 
And I can dance better than any kid n' play 

Stage 2 -- Yea the one ya' wanna listen to 
It's off my head so let the beat play through 
So I can funk it up and make it sound good 
1-2-3 Yo -- Knock on some wood 
For good luck, I like my rhymes atrocious 
Supercalafragilisticexpialidocious 
I'm an effect and that you can bet 
I can take a fly girl and make her wet. 

I'm like Samson -- Samson to Delilah 
There's no denyin', You can try to hang 
But you'll keep tryin' to get my style 
Over and over, practice makes perfect 
But not if you're a loafer. 

You'll get nowhere, no place, no time, no girls 
Soon -- Oh my God, homebody, you probably eat 
Spaghetti with a spoon! Come on and say it! 

VIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino 
Intoxicating so you stagger like a wino 
So punks stop trying and girl stop cryin' 
Vanilla Ice is sellin' and you people are buyin' 
'Cause why the freaks are jockin' like Crazy Glue 
Movin' and groovin' trying to sing along 
All through the ghetto groovin' this here song 
Now you're amazed by the VIP posse. 

Steppin' so hard like a German Nazi 
Startled by the bases hittin' ground 
There's no trippin' on mine, I'm just gettin' down 
Sparkamatic, I'm hangin' tight like a fanatic 
You trapped me once and I thought that 
You might have it 
So step down and lend me your ear 
'89 in my time! You, '90 is my year. 

You're weakenin' fast, YO! and I can tell it 
Your body's gettin' hot, so, so I can smell it 
So don't be mad and don't be sad 
'Cause the lyrics belong to ICE, You can call me Dad 
You're pitchin' a fit, so step back and endure 
Let the witch doctor, Ice, do the dance to cure 
So come up close and don't be square 
You wanna battle me -- Anytime, anywhere 

You thought that I was weak, Boy, you're dead wrong 
So come on, everybody and sing this song 

Say -- Play that funky music Say, go white boy, go white boy go 
play that funky music Go white boy, go white boy, go 
Lay down and boogie and play that funky music till you die. 

Play that funky music Come on, Come on, let me hear 
Play that funky music white boy you say it, say it 
Play that funky music A little louder now 
Play that funky music, white boy Come on, Come on, Come on 
Play that funky music 
`
	if solutions.Plaintext != want {
		t.Log("Plaintext does not match the desired output\n")
		lines1 := strings.Split(solutions.Plaintext, "\n")
		lines2 := strings.Split(want, "\n")
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

func TestSet1Challenge5Reverse(t *testing.T) {
	ciphertext := "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
	bytes, err := hex.DecodeString(ciphertext)
	if err != nil {
		log.Fatal("Unable to parse hex string.")
	}
	soln := xor.Decrypt(bytes)
	got := soln.Plaintext
	want := "Burning 'em, if you ain't quick and nimble\n" +
		"I go crazy when I hear a cymbal"
	if got != want {
		t.Fatal("Incorrect key and plaintext", soln.Key, got)
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
