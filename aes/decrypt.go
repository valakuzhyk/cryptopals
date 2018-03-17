package aes

import (
	"fmt"

	"github.com/valakuzhyk/cryptopals/xor"

	"github.com/valakuzhyk/cryptopals/utils"
)

const blockLength = 128
const _Nb = blockLength / 32

type blockCipher struct {
	key   []byte
	state byteMat
	n_k   int
	n_r   int
}

func (b blockCipher) Decrypt(dst, src []byte) {
}

func (b blockCipher) BlockSize() int {
	return blockLength
}

func (b blockCipher) CryptBlocks(dst, src []byte) {

}

func initState(in []byte) [][]byte {
	state := make([][]byte, 4)
	for i := range state {
		state[i] = make([]byte, _Nb)
	}

	for i, b := range in {
		row := i % 4
		col := i / 4
		state[row][col] = b
	}

	return state
}

func invShiftRows()  {}
func invSubBytes()   {}
func invMixColumns() {}

func rotWord(word []byte) []byte {
	return utils.ShiftBytesLeft(word, 1)
}

func rCon(i int) []byte {
	return []byte{xpow(i - 1), byte(0x0), byte(0x0), byte(0x0)}
}

func (b blockCipher) KeyExpansion(key []byte) [][]byte {
	w := make([][]byte, _Nb*(b.n_r+1))
	for i := 0; i < b.n_k; i++ {
		w[i] = key[4*i : 4*i+4]
	}

	var temp []byte
	for i := b.n_k; i < _Nb*(b.n_r+1); i++ {
		temp = w[i-1]
		if i%b.n_k == 0 {
			temp = xor.Xor(subWord(rotWord(temp)), rCon(i/b.n_k))
		} else if b.n_k > 6 && i%b.n_k == 4 {
			temp = subWord(temp)
		}
		w[i] = xor.Xor(w[i-b.n_k], temp)
	}
	return w
}

func (b blockCipher) addRoundKey(roundKey byteMat) {
	for colIdx := 0; colIdx < b.state.NumCols(); colIdx++ {
		col := b.state.GetColumn(colIdx)
		roundKeyCol := roundKey.GetColumn(colIdx)
		fmt.Println(col, roundKeyCol)
		newCol := xor.Xor(col, roundKeyCol)
		b.state.SetColumn(colIdx, newCol)
	}
}
