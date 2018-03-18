package aes

import (
	"errors"
	"fmt"
	"log"
	"strings"
)

func NewBlockCipher(key []byte, mode int) (*blockCipher, error) {
	var n_k int
	var n_r int
	switch mode {
	case 128:
		n_k = 4
		n_r = 10
	case 192:
		n_k = 6
		n_r = 12
	case 256:
		n_k = 8
		n_r = 14
	default:
		return nil, errors.New("Only valid modes are 128, 192, and 256")
	}
	key = append(key, []byte(strings.Repeat(" ", mode-len(key)))...)

	return &blockCipher{
		key: key,
		n_k: n_k,
		n_r: n_r,
	}, nil
}

func (b blockCipher) extractOutput(dst []byte) {
	for col := range b.state[0] {
		for row := range b.state {
			dst = append(dst, b.state[row][col])
		}
	}
	fmt.Println(dst)
}

// xtime is an abstraction over multiplying a polynomial by x.
// If represent in binary in the way AES is implemented, this is the same
// as multiplying by 2.
func xtime(word byte) byte {
	shifted := int16(word) << 1
	if shifted&0x0100 == 0 {
		return byte(shifted)
	}
	return byte(shifted ^ 0x1b)
}

func xpow(pow int) byte {
	output := byte(1)
	for i := 0; i < pow; i++ {
		output = xtime(output)
	}
	return output
}

func multiply(worda, wordb byte) byte {
	// assume that wordb is the smaller one
	output := byte(0)
	log.Println("Begin")
	log.Printf("%X %X %X\n", worda, wordb, output)
	powX := wordb
	for worda != 0 {
		if worda&1 == 1 {
			output ^= powX
		}
		powX = xtime(powX)
		worda = worda >> 1
		log.Println("Another iter")
		log.Printf("%X %X %X\n", worda, wordb, output)
	}
	log.Println("Done")
	log.Printf("%X %X %X\n", worda, wordb, output)

	return output
}
