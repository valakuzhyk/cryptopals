package xor

import (
	"fmt"
	"math"
	"sort"

	"github.com/valakuzhyk/cryptopals/utils"
)

var MIN_KEYSIZE = 2
var MAX_KEYSIZE = 40

type Solution struct {
	Plaintext    string
	Key          []byte
	EnglishScore float64
	KeyScore     float64
}

// Decrypt attempts to identify identify the plaintext for a ciphertext that has been
// xored with an arbitrary length byte string.
func Decrypt(ciphertext []byte) Solution {
	topSolutions := []Solution{}
	keyScores := identifyKeysize(ciphertext)
	for i := MIN_KEYSIZE; i < MAX_KEYSIZE; i++ {
		solution := DecryptWithKeysize(ciphertext, i)
		keyScore := keyScores[len(solution.Key)]
		solution.KeyScore = keyScore
		topSolutions = append(topSolutions, solution)
	}

	// Rank the solutions for each key size.
	sort.Slice(topSolutions, func(i, j int) bool {
		return topSolutions[i].KeyScore < topSolutions[j].KeyScore
	})

	return topSolutions[0]
}

// DecryptWithKeysize takes a ciphertext and the keysize and tries to identify the
// key bytes and plaintext assuming the plaintext is in English.
func DecryptWithKeysize(ciphertext []byte, likelyKeysize int) Solution {
	guessedKey := make([]byte, likelyKeysize)
	plaintextPieces := make([]string, likelyKeysize)
	avgScore := float64(0)
	for keyIdx := 0; keyIdx < likelyKeysize; keyIdx++ {
		nthChars := utils.CollectEveryNthRune(string(ciphertext[keyIdx:]), likelyKeysize)
		soln := DecodeEnglishFrom1ByteXor([]byte(nthChars))
		guessedKey[keyIdx] = soln.Key[0]
		plaintextPieces[keyIdx] = string(soln.Plaintext)
		avgScore += soln.EnglishScore / float64(likelyKeysize)
	}

	return Solution{
		Key:          guessedKey,
		Plaintext:    reconstructPlaintextFromPieces(plaintextPieces),
		EnglishScore: avgScore,
	}
}

// Reconstructs the plaintext given n slices that contain every nth character.
func reconstructPlaintextFromPieces(pieces []string) string {
	output := []byte{}
	for i := 0; ; i++ {
		for _, piece := range pieces {
			if i == len(piece) {
				return string(output)
			}
			output = append(output, piece[i])
		}
	}
}

// DecodeEnglishFrom1ByteXor identifies the byte that gives the most english like string
// from the bytes given.
func DecodeEnglishFrom1ByteXor(bytes []byte) Solution {
	decodedStrings := make(map[uint8]string)
	for key := uint8(0); key < math.MaxUint8; key++ {
		if !utils.IsPossibleKeyVal(rune(key)) {
			continue
		}
		decodedStrings[key] = string(RepeatingXor(bytes, []byte{byte(key)}))
	}

	minScore := float64(math.MaxFloat64)
	minString := ""
	minKey := uint8(0)
	for key, s := range decodedStrings {
		score := utils.EnglishScore(s)
		if score < minScore {
			minScore = score
			minKey = key
			minString = s
		}
	}

	return Solution{
		Key:          []byte{byte(minKey)},
		Plaintext:    minString,
		EnglishScore: minScore,
	}
}

func identifyKeysize(ciphertext []byte) map[int]float64 {
	// Take chunks of the guessed key size, and find the normalized hamming distance between them.
	editDistMap := make(map[int]float64)
	for keySize := MIN_KEYSIZE; keySize < MAX_KEYSIZE; keySize++ {
		// record the normalized edit distance
		totalNormalizedEditDist := float64(0)
		numSamples := 0
		for i := 0; i+2*keySize < len(ciphertext); i++ {
			chunk1 := ciphertext[i : i+keySize]
			chunk2 := ciphertext[i+keySize : i+2*keySize]
			normalizedDist := float64(utils.HammingDistance(chunk1, chunk2)) / float64(keySize)
			totalNormalizedEditDist += normalizedDist
			numSamples++
		}
		editDistMap[keySize] = float64(totalNormalizedEditDist) / float64(numSamples)
	}
	fmt.Println("Printing keysize Scores")
	printSortedScores(editDistMap)

	return editDistMap
}

func printSortedScores(scores map[int]float64) {
	keys := []int{}
	for k := range scores {
		keys = append(keys, k)
	}

	sort.Slice(keys, func(i, j int) bool {
		return scores[keys[i]] < scores[keys[j]]
	})
	for _, k := range keys {
		fmt.Printf(" %d: %f\n", k, scores[k])
	}
	fmt.Println()
}
