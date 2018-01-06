package utils

import (
	"math/bits"
)

func HammingDistance(b1, b2 []byte) int {
	dist := 0
	for i := range b1 {
		dist += bits.OnesCount8(uint8(b1[i] ^ b2[i]))
	}
	return dist
}
