package xor

import (
	"log"
	"runtime/debug"
)

func xorPair(b1, b2 []byte) []byte {
	if len(b1) != len(b2) {
		debug.PrintStack()
		log.Fatalf("Buffers do not match, cannot compute xor, %d vs %d\n", len(b1), len(b2))
	}
	output := make([]byte, len(b1))
	for i := range b1 {
		output[i] = b1[i] ^ b2[i]
	}
	return output
}

// Xor returns the xor of any number of smae size arrays.
func Xor(bArrays ...[]byte) []byte {
	output := []byte{}
	for _, array := range bArrays {
		output = xorPair(output, array)
	}
	return output
}

// Repeating xor returns the xor of two byte slices. If one is shorter,
// it's values are repeated until both slices are exhausted.
func RepeatingXor(b1, b2 []byte) []byte {
	output := make([]byte, len(b1))
	for i := range b1 {
		output[i] = b1[i%len(b1)] ^ b2[i%len(b2)]
	}
	return output
}
