package repeatxor

import (
	"math"
	"unicode"

	"github.com/valakuzhyk/cryptopals/utils"
)

var MIN_KEYSIZE = 2
var MAX_KEYSIZE = 25

func isPossibleKeyVal(keyVal rune) bool {
	return unicode.IsLetter(keyVal) ||
		unicode.IsDigit(keyVal) ||
		unicode.IsSpace(keyVal)
}

func Decrypt(ciphertext []byte) {
	likelyKeysize := identifyKeysize(ciphertext)
	for keyIdx := 0; keyIdx < likelyKeysize; keyIdx++ {
		nthChars := utils.CollectEveryNthRune(string(ciphertext[keyIdx:]), likelyKeysize)
		utils.DecodeEnglishFrom1ByteXor([]byte(nthChars))
	}

}

func identifyKeysize(ciphertext []byte) int {
	// Take chunks of the guessed key size
	editDistMap := make(map[int]float64)
	for keySize := MIN_KEYSIZE; keySize < MAX_KEYSIZE; keySize++ {
		// record the normalized edit distance
		totalEditDist := 0
		numChunks := 0
		for i := 0; i+2*keySize < len(ciphertext); i += keySize {
			chunk1 := ciphertext[i : i+keySize]
			chunk2 := ciphertext[i+keySize : i+2*keySize]
			totalEditDist += utils.HammingDistance(chunk1, chunk2)
		}
		editDistMap[keySize] = float64(totalEditDist) / float64(numChunks)
	}

	// the smallest normalized edit distance is the key
	minKeySize := -1
	minEditDist := math.MaxFloat64
	for keySize, editDist := range editDistMap {
		if minEditDist > editDist {
			minEditDist = editDist
			minKeySize = keySize
		}
	}
	return minKeySize
}
