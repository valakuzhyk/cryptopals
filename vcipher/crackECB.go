package vcipher

import (
	"fmt"
	"log"
	"math"
	"strings"

	"github.com/valakuzhyk/cryptopals/utils"
)

// AppendEncrypter encrypts given input, but can have bytes appended at the beginning or end.
type AppendEncrypter struct {
	RandomEncrypter
	prefix []byte
	suffix []byte
}

// SetEndBytes sets the bytes that are appended to the end of every
// encrypt call
func (e *AppendEncrypter) SetEndBytes(bytes []byte) {
	e.suffix = bytes
}

// SetBeginBytes sets the bytes that are appended to the beginning of every
// encrypt call
func (e *AppendEncrypter) SetBeginBytes(bytes []byte) {
	e.prefix = bytes
}

// Encrypt takes the input, appends the endBytes, and returns the result
// of the encryption.
func (e AppendEncrypter) Encrypt(input []byte) []byte {
	inputWithPrefix := append(e.prefix, input...)
	fullInput := append(inputWithPrefix, e.suffix...)
	return e.RandomEncrypter.Encrypt(fullInput)
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

	// 2.5 Figure out the size of the prefix (mod blocksize)
	prefixSize := FindPrefixSize(e, blockSize)

	// 3 Create input that is one byte less and get output
	// We now know that 'message' contains a string that ends at a block end.
	// All we need is the offset. We need to ensure that the string is larger than the message.
	desiredOffset := blockSize - prefixSize - 1
	crackingStr := []byte(strings.Repeat("A", maxMessageLen+desiredOffset))
	blockIdx := len(crackingStr) / blockSize

	appendedMessage := []byte{}
	for {
		// 4 Find the value that you can append to the input such that this block's value doesn't change.
		nextByte, err := findNextByte(e, crackingStr, appendedMessage, blockIdx, blockSize)
		if err != nil {
			if len(appendedMessage) == 0 {
				log.Fatal("Unable to get any matching character")
			}
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

func FindPrefixSize(e AppendEncrypter, blockSize int) int {
	// First, we need to find how long the prefix and suffix are.
	// Start with two blocks worth of identical characters
	//   Are there two new, identical blocks?
	//      Validate that this is actually the added characters (switch the characters used)
	//      if so, you have found the appropriate length, remove a char and end
	//   append a new character

	// Find the block that starts the attacker's control
	emptyMesssage := e.Encrypt([]byte{})
	oneCharMessage := e.Encrypt([]byte("A"))
	blockOfChange := utils.FirstBlockDiff(emptyMesssage, oneCharMessage, blockSize)
	oneCharMessage2 := e.Encrypt([]byte("B"))
	blockOfChange2 := utils.FirstBlockDiff(emptyMesssage, oneCharMessage2, blockSize)
	firstControlledBlock := blockOfChange
	if blockOfChange2 < blockOfChange {
		firstControlledBlock = blockOfChange2
	}
	fmt.Println(firstControlledBlock)

	// Create two blocks and see if the two blocks following the first controlled block are the same.
	message := strings.Repeat("A", blockSize*2+1)
	for len(message) < 3*blockSize+2 {
		output := e.Encrypt([]byte(message))

		firstBlockAfter := utils.GetNthBlock(output, firstControlledBlock+1, blockSize)
		secondBlockAfter := utils.GetNthBlock(output, firstControlledBlock+2, blockSize)
		if string(firstBlockAfter) == string(secondBlockAfter) {
			// Repeat this with a different character to validate that this is
			// really the block we are in control of that are causing these blocks to be the same.
			output := e.Encrypt([]byte(strings.Repeat("B", len(message))))
			firstBlockAfter := utils.GetNthBlock(output, firstControlledBlock+1, blockSize)
			secondBlockAfter := utils.GetNthBlock(output, firstControlledBlock+2, blockSize)
			if string(firstBlockAfter) == string(secondBlockAfter) {
				return blockSize - (len(message) % blockSize)
			}
		}
		message += "A"
	}
	log.Fatal("Ummmm, you weren't able to find the starting point?")
	return -1
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
	return nextOutputLen - outputLen
}
