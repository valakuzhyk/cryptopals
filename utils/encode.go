package utils

import (
	"encoding/base64"
	"math"
)

func DecodeEnglishFrom1ByteXor(bytes []byte) (uint8, string) {
	decodedStrings := make(map[uint8]string)
	for key := uint8(0); key < math.MaxUint8; key++ {
		decodedStrings[key] = string(RepeatingXor(bytes, []byte{byte(key)}))
	}

	maxScore := float32(0)
	maxString := ""
	maxKey := uint8(0)
	for key, s := range decodedStrings {
		score := EnglishScore(s)
		if score > maxScore {
			maxScore = score
			maxKey = key
			maxString = s
		}
	}

	return maxKey, maxString
}

func BytesToBase64(bytes []byte) string {
	return base64.StdEncoding.EncodeToString(bytes)
}
