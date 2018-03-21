package utils

import (
	"log"
	"strings"
)

// AddPKCS7Padding adds padding to the
func AddPKCS7Padding(s string, blockSize int) string {
	if blockSize >= 256 {
		log.Fatalf("You can't use PKCS7 padding with a blocksize greater than 256. You chose %d", blockSize)
	}
	paddingSize := byte(blockSize - (len(s) % blockSize))
	padding := strings.Repeat(string(paddingSize), int(paddingSize))
	return s + padding
}
