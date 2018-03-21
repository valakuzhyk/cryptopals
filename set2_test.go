package main

import (
	"testing"

	"github.com/valakuzhyk/cryptopals/utils"
)

func TestSet2Challenge9(t *testing.T) {
	// Implement PKCS Padding
	paddedString := utils.AddPKCS7Padding("YELLOW SUBMARINE", 20)
	if paddedString != "YELLOW SUBMARINE\x04\x04\x04\x04" {
		t.Fatal("The padding is all wrong... all wrong.")
	}
}
