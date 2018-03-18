package aes

import (
	"errors"
	"fmt"
	"strings"

	"github.com/valakuzhyk/cryptopals/xor"
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

func (b blockCipher) KeyExpansion(key []byte) byteMat {
	w := make(byteMat, _Nb)
	for i := range w {
		w[i] = make([]byte, _Nb*(b.n_r+1))
	}
	for i := 0; i < b.n_k; i++ {
		w.SetColumn(i, key[4*i:4*i+4])
	}

	var temp []byte
	for i := b.n_k; i < _Nb*(b.n_r+1); i++ {
		temp = w.GetColumn(i - 1)
		if i%b.n_k == 0 {
			temp = xor.Xor(subWord(rotWord(temp)), rCon(i/b.n_k))
		} else if b.n_k > 6 && i%b.n_k == 4 {
			temp = subWord(temp)
		}
		w.SetColumn(i, xor.Xor(w.GetColumn(i-b.n_k), temp))
	}
	return w
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
	powX := wordb
	for worda != 0 {
		if worda&1 == 1 {
			output ^= powX
		}
		powX = xtime(powX)
		worda = worda >> 1
	}

	return output
}
