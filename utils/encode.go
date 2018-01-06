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

	minScore := float32(math.MaxFloat32)
	minString := ""
	minKey := uint8(0)
	for key, s := range decodedStrings {
		score := EnglishScore(s)
		if score < minScore {
			minScore = score
			minKey = key
			minString = s
		}
	}

	return minKey, minString
}

func BytesToBase64(bytes []byte) string {
	return base64.StdEncoding.EncodeToString(bytes)
}
