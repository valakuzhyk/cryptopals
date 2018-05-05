package utils

import (
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	"math/bits"
	"reflect"
)

func HammingDistance(b1, b2 []byte) int {
	dist := 0
	for i := range b1 {
		dist += bits.OnesCount8(uint8(b1[i] ^ b2[i]))
	}
	return dist
}

func ShiftBytesLeft(b1 []byte, idx int) []byte {
	length := len(b1)
	return append(b1[idx%length:], b1[:idx%length]...)
}

func ShiftBytesRight(b1 []byte, idx int) []byte {
	length := len(b1)
	return append(b1[length-(idx%length):], b1[:length-(idx%length)]...)
}

func PrintBytes(b1 []byte) {
	for _, b := range b1 {
		fmt.Printf("%x, ", b)
	}
	fmt.Println()
}

// GetNthBlock returns the nth block after splitting up input in blocks of size blockSize
func GetNthBlock(input []byte, n, blockSize int) []byte {
	return input[n*blockSize : (n+1)*blockSize]
}

// Blockify returns a list of the blocks that are made from the input.
func Blockify(input []byte, blockSize int) ([][]byte, error) {
	numBytes := len(input)
	if numBytes%blockSize != 0 {
		return nil, fmt.Errorf("The length of the input (%d) is not a multiple of the blocksize %d", numBytes, blockSize)
	}
	numBlocks := numBytes / blockSize
	output := [][]byte{}
	for i := 0; i < numBlocks; i++ {
		output = append(output, GetNthBlock(input, i, blockSize))
	}
	return output, nil
}

// FirstBlockDiff returns the first block that is different between the inputs.
// if they are the same, return -1
func FirstBlockDiff(input1, input2 []byte, blockSize int) int {
	for i := 0; i < len(input1)/blockSize; i++ {
		block1 := GetNthBlock(input1, i, blockSize)
		block2 := GetNthBlock(input2, i, blockSize)
		if !reflect.DeepEqual(block1, block2) {
			return i
		}
	}
	return -1
}

// GetRandomBytes returns a number of random bytes between min and max
func GetRandomBytesBetween(min, max int) []byte {
	maxIntSize := big.NewInt(int64(max - min))
	numByteOffset, err := rand.Int(rand.Reader, maxIntSize)
	if err != nil {
		log.Fatal("Issue computing random int: ", err)
	}
	numBytes := min + int(numByteOffset.Uint64())

	return GetRandomBytes(numBytes)
}

func GetRandomBytes(numBytes int) []byte {
	randBytes := make([]byte, numBytes)
	_, err := rand.Read(randBytes)
	if err != nil {
		log.Fatal("Issue computing random bytes: ", err)
	}
	return randBytes
}
