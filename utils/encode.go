package utils

import (
	"encoding/base64"
)

func IsPossibleKeyVal(keyVal rune) bool {
	return true
	// return unicode.IsLetter(keyVal) ||
	// 	unicode.IsDigit(keyVal) ||
	// 	unicode.IsSpace(keyVal)
}

func BytesToBase64(bytes []byte) string {
	return base64.StdEncoding.EncodeToString(bytes)
}

func Base64ToBytes(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}
