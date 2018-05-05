package sha1

import (
	"encoding/binary"
	"log"
	"math/bits"
	"strings"

	"github.com/valakuzhyk/cryptopals/utils"
)

// MAC returns a Message Authentication Code for the given key and message.
func MAC(key, message []byte) []byte {
	return Hash(append(key, message...))
}

// Hash returns the hash of key || message
func Hash(message []byte) []byte {
	ml := len(message)

	// TODO Preprocessing
	message = append(message, 0x80)

	currentOffset := (64 + (ml + 1 - 56)) % 64
	bytesToWrite := (64 - currentOffset) % 64
	message = append(message, []byte(strings.Repeat("\x00", bytesToWrite))...)

	// Remember that the size of the buffer needs to be in bits, rather than bytes.
	sizeBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(sizeBytes, uint64(ml*8))
	message = append(message, sizeBytes...)

	// Iterate over 64 byte chunks
	blocks, err := utils.Blockify(message, 64)
	if err != nil {
		log.Fatal("Issue with the padding step: ", err)
	}

	calc := newDefaultCalculator()
	for _, block := range blocks {
		calc.computeBlock(block)
	}
	return calc.dumpState()
}

// Calculator computes the result of a block in the SHA1 algorithm
type Calculator struct {
	h0, h1, h2, h3, h4 uint32
}

// newDefaultCalculator returns the default calculator used in the normal SHA1
// hashing routine.
func newDefaultCalculator() Calculator {
	return Calculator{
		h0: 0x67452301,
		h1: 0xEFCDAB89,
		h2: 0x98BADCFE,
		h3: 0x10325476,
		h4: 0xC3D2E1F0,
	}
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
		log.Println("Working on this word in main loop ", i)

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
