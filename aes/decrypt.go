package aes

import (
	"errors"
	"fmt"
	"strings"

	"github.com/valakuzhyk/cryptopals/xor"

	"github.com/valakuzhyk/cryptopals/utils"
)

type byteMat [][]byte

func (b byteMat) NumRows() int {
	return len(b)
}

func (b byteMat) NumCols() int {
	if len(b) == 0 {
		return 0
	}
	return len(b[0])
}

func (b byteMat) GetColumn(i int) []byte {
	col := make([]byte, b.NumRows())
	for rowIdx, row := range b {
		fmt.Printf("i: %d, len: %d, rowIdx: %d, len(col): %d\n", i, len(row), rowIdx, len(col))
		col[rowIdx] = row[i]
	}
	return col
}

func (b byteMat) SetColumn(i int, newCol []byte) {
	for rowIdx, val := range newCol {
		b[rowIdx][i] = val
	}
}

const blockLength = 128
const _Nb = blockLength / 32

type blockCipher struct {
	key   []byte
	state byteMat
	n_k   int
	n_r   int
}

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

func (b blockCipher) Encrypt(dst, src []byte) {
	w := b.KeyExpansion(b.key)
	b.state = initState(src)
	b.addRoundKey(w[0:_Nb])

	for round := 1; round < b.n_r; round++ {
		b.subBytes()
		b.shiftRows()
		b.mixColumns()
		b.addRoundKey(w[round*_Nb : (round+1)*_Nb])
	}
	b.subBytes()
	b.shiftRows()
	b.addRoundKey(w[b.n_r*_Nb : (b.n_r+1)*_Nb])

	b.extractOutput(dst)
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

func (b blockCipher) extractOutput(dst []byte) {
	for col := range b.state[0] {
		for row := range b.state {
			dst = append(dst, b.state[row][col])
		}
	}
	fmt.Println(dst)
}

func invShiftRows()  {}
func invSubBytes()   {}
func invMixColumns() {}

func rotWord(word []byte) []byte {
	return utils.ShiftBytesLeft(word, 1)
}

func subWord(word []byte) []byte {
	output := make([]byte, len(word))
	for i, val := range word {
		output[i] = sBox[val]
	}
	return output
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
			if mixVal&0x1 != 0 {
				newRowVal ^= col[i]
			}
			if mixVal&0x10 != 0 {
				newRowVal ^= xtime(col[i])
			}
		}
		newColumn[row] = newRowVal
	}
	return newColumn
}

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

func (b blockCipher) shiftRows() {
	for rowIdx, row := range b.state {
		b.state[rowIdx] = utils.ShiftBytesLeft(row, rowIdx)
	}
}
func (b blockCipher) subBytes() {
	for rowIdx, row := range b.state {
		b.state[rowIdx] = subWord(row)
	}
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
