package utils

import (
	"fmt"
	"math/bits"
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
