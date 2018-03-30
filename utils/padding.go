package utils

import (
	"log"
	"strings"
)

// AddPKCS7Padding adds padding according to https://tools.ietf.org/html/rfc5652#section-6.3
func AddPKCS7Padding(s string, blockSize int) string {
	if blockSize >= 256 {
		log.Fatalf("You can't use PKCS7 padding with a blocksize greater than 256. You chose %d", blockSize)
	}
	paddingSize := byte(blockSize - (len(s) % blockSize))
	padding := strings.Repeat(string(paddingSize), int(paddingSize))
	return s + padding
}

// RemovePKCS7Padding removes padding if it exists, returning true if it identified
// and removed the padding. It can have false positives (of course)
func RemovePKCS7Padding(s string, blockSize int) (bool, string) {
	if blockSize >= 256 {
		log.Fatalf("You can't use PKCS7 padding with a blocksize greater than 256. You chose %d", blockSize)
	}

	bytes := []byte(s)
	if len(bytes) == 0 {
		return false, s
	} else if len(bytes)%blockSize != 0 {
		return false, s
	}
	lastByte := bytes[len(bytes)-1]
	if len(bytes) < int(lastByte) {
		return false, s
	}
	potentialPadding := bytes[len(bytes)-int(lastByte) : len(bytes)]
	for _, b := range potentialPadding {
		if b != lastByte {
			return false, s
		}
	}
	unpaddedBytes := bytes[0 : len(bytes)-int(lastByte)]
	return true, string(unpaddedBytes)
}
