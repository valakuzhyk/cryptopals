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
	h0 := uint32(0x67452301)
	h1 := uint32(0xEFCDAB89)
	h2 := uint32(0x98BADCFE)
	h3 := uint32(0x10325476)
	h4 := uint32(0xC3D2E1F0)

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

	for _, block := range blocks {
		log.Println("Working on this block")
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

		a := h0
		b := h1
		c := h2
		d := h3
		e := h4

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
		h0 = h0 + a
		h1 = h1 + b
		h2 = h2 + c
		h3 = h3 + d
		h4 = h4 + e
	}
	output := make([]byte, 4*5)
	binary.BigEndian.PutUint32(output[4*0:], h0)
	binary.BigEndian.PutUint32(output[4*1:], h1)
	binary.BigEndian.PutUint32(output[4*2:], h2)
	binary.BigEndian.PutUint32(output[4*3:], h3)
	binary.BigEndian.PutUint32(output[4*4:], h4)
	return output
}
