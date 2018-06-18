package md4

import (
	"encoding/binary"
	"log"
	"math/bits"
	"strings"

	"github.com/valakuzhyk/cryptopals/utils"
)

func f(x, y, z uint32) uint32 {
	return (x & y) | (^x & z)
}

func g(x, y, z uint32) uint32 {
	return (x & y) | (x & z) | (y & z)
}

func h(x, y, z uint32) uint32 {
	return x ^ y ^ z
}

type subtransform func(x, y, z uint32) uint32

func step(f subtransform, a, b, c, d, xVal, constant uint32, s int) uint32 {
	return bits.RotateLeft32(a+f(b, c, d)+xVal+constant, s)
}

// defaultCalculator is the one used in the traditional SHA1 implementation.
var defaultCalculator = Calculator{
	a: 0x67452301,
	b: 0xEFCDAB89,
	c: 0x98BADCFE,
	d: 0x10325476,
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
	a, b, c, d uint32
}

// Hash returns the MD4 hash where the initialization is defined by the Calculator.
// To compute the traditional SHA1 hash, you can call the Hash method on the default
// calculator.
func (calc Calculator) Hash(message string) []byte {
	padding := generatePadding(message)
	paddedMessage := message + padding

	if len(paddedMessage)%64 != 0 {
		log.Fatal("Message is not modulus of 64, instead is ", len(paddedMessage))
	}

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
	output := make([]byte, 4*4)
	binary.LittleEndian.PutUint32(output[4*0:], calc.a)
	binary.LittleEndian.PutUint32(output[4*1:], calc.b)
	binary.LittleEndian.PutUint32(output[4*2:], calc.c)
	binary.LittleEndian.PutUint32(output[4*3:], calc.d)
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
	binary.LittleEndian.PutUint64(sizeBytes, uint64(ml*8))
	padding = append(padding, sizeBytes...)
	return string(padding)
}

func indexingFunction(phase int) func(int) int {
	if phase == 0 {
		return func(i int) int {
			return i
		}
	}
	if phase == 1 {
		return func(i int) int {
			row := i / 4
			col := i % 4
			return col*4 + row
		}
	}
	if phase == 2 {
		return func(i int) int {
			row := i / 4
			col := i % 4
			if row == 1 || row == 2 {
				row ^= 3
			}
			if col == 1 || col == 2 {
				col ^= 3
			}
			return col*4 + row
		}
	}
	log.Fatal("Invalid phase: ", phase)
	return nil
}

func (calc *Calculator) computeBlock(block []byte) {
	wordBytes, _ := utils.Blockify(block, 4)
	words := make([]uint32, 16)
	for i, bytes := range wordBytes {
		words[i] = binary.LittleEndian.Uint32(bytes)
	}
	a := calc.a
	b := calc.b
	c := calc.c
	d := calc.d

	functionList := []subtransform{f, g, h}
	shiftList := [][]int{
		[]int{3, 7, 11, 19},
		[]int{3, 5, 9, 13},
		[]int{3, 9, 11, 15},
	}
	constList := []uint32{0, 0x5A827999, 0x6ED9EBA1}
	for phase := 0; phase < 3; phase++ {
		function := functionList[phase]
		shifts := shiftList[phase]
		constant := constList[phase]
		indexFunc := indexingFunction(phase)
		for i := range words {
			w := words[indexFunc(i)]
			log.Printf("Phase %d, %x", phase, w)
			switch i % 4 {
			case 0:
				a = step(function, a, b, c, d, w, constant, shifts[i%4])
			case 1:
				d = step(function, d, a, b, c, w, constant, shifts[i%4])
			case 2:
				c = step(function, c, d, a, b, w, constant, shifts[i%4])
			case 3:
				b = step(function, b, c, d, a, w, constant, shifts[i%4])
			}
		}
	}

	calc.a += a
	calc.b += b
	calc.c += c
	calc.d += d
}
