package vcipher

import (
	"fmt"
	"log"
	"math"
	"strings"

	"github.com/valakuzhyk/cryptopals/utils"
)

// AppendEncrypter encrypts given input, but always appends some bytes
// to the end.
type AppendEncrypter struct {
	RandomEncrypter
	endBytes []byte
}

// SetEndBytes sets the bytes that are appended to the end of every
// encrypt call
func (e *AppendEncrypter) SetEndBytes(endBytes []byte) {
	log.Println(len(endBytes))
	e.endBytes = endBytes
}

// Encrypt takes the input, appends the endBytes, and returns the result
// of the encryption.
func (e AppendEncrypter) Encrypt(input []byte) []byte {
	return e.RandomEncrypter.Encrypt(append(input, e.endBytes...))
}

// IdentifyHiddenAppendedBytes takes an encrypter a message containing
// a user controlled message followed by an unknown message,
func IdentifyHiddenAppendedBytes(e AppendEncrypter) []byte {
	maxMessageLen := len(e.Encrypt([]byte{}))

	// 1 Find Block Size
	blockSize := CalculateBlockSize(e.Encrypt)
	// 2 Find encryption mode
	mode := ECBvsCBCOracle(e.Encrypt)
	if mode != ECB_ENCODE {
		log.Fatal("identifying appended strings only supported in ECB")
	}

	// 3 Create input that is one byte less and get output
	appendedMessage := []byte{}
	crackingStr := []byte(strings.Repeat("A", maxMessageLen-1))
	blockIdx := len(crackingStr) / blockSize

	for {
		// 4 Find the value that you can append to the input such that this block's value doesn't change.
		nextByte, err := findNextByte(e, crackingStr, appendedMessage, blockIdx, blockSize)
		if err != nil {
			// The string has changed, meaning this is probably padding.
			// Remove the last string that was assumed to be part of the message
			appendedMessage = appendedMessage[:len(appendedMessage)-1]
			break
		}

		// 5 Repeat to find the next byte.
		appendedMessage = append(appendedMessage, nextByte)
		fmt.Println(len(crackingStr))
		if len(crackingStr) == 0 {
			break
		}
		crackingStr = crackingStr[1:]
	}
	return appendedMessage
}

// findNextByte returns the guess for the next byte when trying to do a byte by byte
// decryption of ECB.
func findNextByte(e AppendEncrypter, crackingStr, messageSoFar []byte, blockIdx, blockSize int) (byte, error) {
	desiredOutput := e.Encrypt(crackingStr)
	crackingStr = append(crackingStr, messageSoFar...)
	for i := 0; i <= math.MaxUint8; i++ {
		b := byte(i)
		inputAttempt := append(crackingStr, b)
		encryptionOutput := e.Encrypt(inputAttempt)

		desiredOutputBlock := utils.GetNthBlock(desiredOutput, blockIdx, blockSize)
		encryptionOutputBlock := utils.GetNthBlock(encryptionOutput, blockIdx, blockSize)

		if string(desiredOutputBlock) == string(encryptionOutputBlock) {
			log.Println("Found Byte: " + string(b))
			return b, nil
		}
	}
	return 0, fmt.Errorf("was not able to find the next byte")
}

// CalculateBlockSize returns the block size for a block cipher's encryption function.
func CalculateBlockSize(encrypter func(input []byte) []byte) int {
	// Keep adding data until you find a change in the output size
	message := []byte{}
	outputLen := len(encrypter(message))
	nextOutputLen := outputLen
	for outputLen == nextOutputLen {
		message = append(message, 0x00)
		nextOutputLen = len(encrypter(message))
		if len(message) > 10000 {
			log.Fatal("The output size does not seem to be impacted ")
		}
	}
	// Now we know that the message has just started a new block. we identify
	// the next time the block size
	messageLen := len(message)
	outputLen = nextOutputLen
	for outputLen == nextOutputLen {
		message = append(message, 0x00)
		nextOutputLen = len(encrypter(message))
		if len(message) > 10000 {
			log.Fatal("The output size does not seem to be impacted ")
		}
	}
	blockSize := len(message) - messageLen
	return blockSize
}
