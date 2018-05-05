package sha1

import (
	"encoding/binary"
	"log"
	"math/bits"
	"strings"

	"github.com/valakuzhyk/cryptopals/utils"
)

// defaultCalculator is the one used in the traditional SHA1 implementation.
var defaultCalculator = Calculator{
	h0: 0x67452301,
	h1: 0xEFCDAB89,
	h2: 0x98BADCFE,
	h3: 0x10325476,
	h4: 0xC3D2E1F0,
}

// MAC returns a Message Authentication Code for the given key and message.
func MAC(key, message string) []byte {
	return Hash(key + message)
}

// Hash returns the hash for the traditional implementation of SHA1
func Hash(message string) []byte {
	return defaultCalculator.Hash(message)
}

// Calculator computes the result of a block in the SHA1 algorithm
type Calculator struct {
	h0, h1, h2, h3, h4 uint32
}

// Hash returns the SHA1 hash where the initialization is defined by the Calculator.
// To compute the traditional SHA1 hash, you can call the Hash method on the default
// calculator.
func (calc Calculator) Hash(message string) []byte {
	padding := generatePadding(message)
	paddedMessage := message + padding

	return calc.hashPadded([]byte(paddedMessage))
}

func (calc Calculator) hashPadded(paddedMessage []byte) []byte {
	// Iterate over 64 byte chunks
	blocks, err := utils.Blockify(paddedMessage, 64)
	if err != nil {
		log.Fatal("Issue with the padding step: ", err)
	}

	for _, block := range blocks {
		calc.computeBlock(block)
	}
	return calc.dumpState()
}

// dumpState return the output of the SHA1 hashing routine.
func (calc Calculator) dumpState() []byte {
	output := make([]byte, 4*5)
	binary.BigEndian.PutUint32(output[4*0:], calc.h0)
	binary.BigEndian.PutUint32(output[4*1:], calc.h1)
	binary.BigEndian.PutUint32(output[4*2:], calc.h2)
	binary.BigEndian.PutUint32(output[4*3:], calc.h3)
	binary.BigEndian.PutUint32(output[4*4:], calc.h4)
	return output
}

// generatePadding returns the padding that would be used for the given message
func generatePadding(message string) string {
	ml := len(message)

	padding := []byte{0x80}

	currentOffset := (64 + (ml + 1 - 56)) % 64
	bytesToWrite := (64 - currentOffset) % 64
	padding = append(padding, []byte(strings.Repeat("\x00", bytesToWrite))...)

	// Remember that the size of the buffer needs to be in bits, rather than bytes.
	sizeBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(sizeBytes, uint64(ml*8))
	padding = append(padding, sizeBytes...)
	return string(padding)
}

// computeBlock changes the state of the calculator according to the block given.
func (calc *Calculator) computeBlock(block []byte) {
	words, _ := utils.Blockify(block, 4)
	// convert words to ints to make easier to process.
	w := []uint32{}
	for i := 0; i < 80; i++ {
		if i < 16 {
			w = append(w, binary.BigEndian.Uint32(words[i]))
		} else {
			newWord := w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]
			newWord = bits.RotateLeft32(newWord, 1)
			w = append(w, newWord)
		}
	}

	a := calc.h0
	b := calc.h1
	c := calc.h2
	d := calc.h3
	e := calc.h4

	for i, word := range w {
		var k, f uint32
		if i <= 19 {
			f = (b & c) | ((^b) & d)
			k = 0x5A827999
		} else if i <= 39 {
			f = b ^ c ^ d
			k = 0x6ED9EBA1
		} else if i <= 59 {
			f = (b & c) | (b & d) | (c & d)
			k = 0x8F1BBCDC
		} else {
			f = b ^ c ^ d
			k = 0xCA62C1D6
		}

		temp := bits.RotateLeft32(a, 5) + f + e + k + word
		e = d
		d = c
		c = bits.RotateLeft32(b, 30)
		b = a
		a = temp
	}
	calc.h0 = calc.h0 + a
	calc.h1 = calc.h1 + b
	calc.h2 = calc.h2 + c
	calc.h3 = calc.h3 + d
	calc.h4 = calc.h4 + e
}
