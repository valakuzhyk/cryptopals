package aes

import (
	"github.com/valakuzhyk/cryptopals/utils"
)

// Encrypt takes data and encrypts it given the current blockCipher settings.
func (b *blockCipher) Encrypt(dst, src []byte) {
	w := b.KeyExpansion(b.key)
	b.state = initState(src)
	b.addRoundKey(w.GetColumns(0, _Nb))
	for round := 1; round < b.n_r; round++ {
		b.subBytes()
		b.shiftRows()
		b.mixColumns()
		b.addRoundKey(w.GetColumns(round*_Nb, (round+1)*_Nb))
	}
	b.subBytes()
	b.shiftRows()
	b.addRoundKey(w.GetColumns(b.n_r*_Nb, (b.n_r+1)*_Nb))

	b.extractOutput(dst)
}

func (b blockCipher) mixColumns() {
	mixer := []byte{2, 3, 1, 1}
	for i := 0; i < b.state.NumCols(); i++ {
		col := b.state.GetColumn(i)
		newColumn := mixColumn(col, mixer)
		b.state.SetColumn(i, newColumn)
	}
}

func mixColumn(col, mixer []byte) []byte {
	newColumn := make([]byte, len(col))
	for row := range col {
		newRowVal := byte(0)
		for i, mixVal := range mixer {
			if mixVal&1 != 0 {
				newRowVal ^= col[i]
			}
			if mixVal&2 != 0 {
				newRowVal ^= xtime(col[i])
			}
		}
		newColumn[row] = newRowVal
		mixer = utils.ShiftBytesRight(mixer, 1)
	}
	return newColumn
}

func (b blockCipher) shiftRows() {
	for rowIdx, row := range b.state {
		b.state[rowIdx] = utils.ShiftBytesLeft(row, rowIdx)
	}
}

func subWord(word []byte) []byte {
	output := make([]byte, len(word))
	for i, val := range word {
		output[i] = sBox[val]
	}
	return output
}

func (b blockCipher) subBytes() {
	for rowIdx, row := range b.state {
		b.state[rowIdx] = subWord(row)
	}
}
