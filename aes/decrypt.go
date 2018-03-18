package aes

import (
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

func (b blockCipher) invShiftRows() {
	for rowIdx, row := range b.state {
		b.state[rowIdx] = utils.ShiftBytesRight(row, rowIdx)
	}
}
func (b blockCipher) invSubBytes() {
	for rowIdx, row := range b.state {
		b.state[rowIdx] = invSubWord(row)
	}
}

func invSubWord(word []byte) []byte {
	output := make([]byte, len(word))
	for i, val := range word {
		output[i] = invSBox[val]
	}
	return output
}

func (b blockCipher) invMixColumns() {
	mixer := []byte{0xe, 0xb, 0xd, 0x9}
	for i := 0; i < b.state.NumCols(); i++ {
		col := b.state.GetColumn(i)
		newColumn := mixColumn(col, mixer)
		b.state.SetColumn(i, newColumn)
	}
}

func rotWord(word []byte) []byte {
	return utils.ShiftBytesLeft(word, 1)
}

func rCon(i int) []byte {
	return []byte{xpow(i - 1), byte(0x0), byte(0x0), byte(0x0)}
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

func (b blockCipher) addRoundKey(roundKey byteMat) {
	for colIdx := 0; colIdx < b.state.NumCols(); colIdx++ {
		col := b.state.GetColumn(colIdx)
		roundKeyCol := roundKey.GetColumn(colIdx)
		newCol := xor.Xor(col, roundKeyCol)
		b.state.SetColumn(colIdx, newCol)
	}
}
