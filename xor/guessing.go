package xor

import (
	"log"
	"unicode"

	"github.com/valakuzhyk/cryptopals/utils"
)

// GuessKey tries to guess a key for a bunch of samples that have been xored
// against the same key.
func GuessKey(samples []string) []byte {
	guessedKey := []byte{}
	for i := 0; i < 38; i++ {
		letter := GuessLetter(samples, i)
		guessedKey = append(guessedKey, letter)
	}

	log.Println("Guesses: ")
	for _, sample := range samples {
		decryptGuess := RepeatingXor([]byte(sample), guessedKey)
		log.Printf("  %s", decryptGuess)
	}
	return guessedKey
}

// GuessLetter attempts to guess the byte that was xored in the nth position
// of each sample, relying on the distribution of english letters.
func GuessLetter(samples []string, n int) byte {
	char0 := CollectNthByteFromSamples(samples, n)
	guesses := ValidGuesses(char0)

	bestGuess := byte(0)
	bestScore := 1000.0

	for _, guess := range guesses {
		xoredBytes := RepeatingXor(char0, []byte{guess})
		score := utils.EnglishScore(string(xoredBytes))
		if score < bestScore {
			bestGuess = guess
			bestScore = score
		}
	}
	return bestGuess
}

// ValidGuesses returns all the bytes that would result in the input characters all being mapped to valid
// ascii characters.
func ValidGuesses(inputBytes []byte) []byte {
	possibleGuess := []byte{}
	for i := 0; i < 256; i++ {
		if allBytesAreText(inputBytes, byte(i)) {
			possibleGuess = append(possibleGuess, byte(i))
		}
	}
	return possibleGuess
}

func CollectNthByteFromSamples(samples []string, n int) []byte {
	output := []byte{}
	for _, s := range samples {
		if len(s) <= n {
			continue
		}
		output = append(output, s[n])
	}
	return output
}

func FindCommonPrefixes(strings []string) []string {
	prefixes := make(map[string]int)
	for _, s1 := range strings {
		for _, s2 := range strings {
			if s1 == s2 {
				continue
			}
			commonPrefix := ""
			for i := 0; s1[:i] == s2[:i]; i++ {
				commonPrefix = s1[:i]
			}
			if commonPrefix != "" {
				prefixes[commonPrefix]++
			}
		}
	}
	output := []string{}
	for prefix, _ := range prefixes {
		output = append(output, prefix)
	}
	return output
}

func allBytesAreText(inputBytes []byte, key byte) bool {
	for _, b := range inputBytes {
		newRune := rune(b ^ byte(key))
		if !(unicode.IsLetter(newRune) || unicode.IsSpace(newRune) || unicode.IsPunct(newRune)) {
			return false
		}
	}
	return true
}
