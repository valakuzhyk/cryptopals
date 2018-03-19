package aes

import "fmt"

type byteMat [][]byte

type bytes []byte

func (b byteMat) NumRows() int {
	return len(b)
}

func (b byteMat) NumCols() int {
	if len(b) == 0 {
		return 0
	}
	return len(b[0])
}

func (b byteMat) GetColumns(i, j int) byteMat {
	columns := make(byteMat, b.NumRows())
	for rowIdx, row := range b {
		columns[rowIdx] = row[i:j]
	}
	return columns
}

func (b byteMat) GetColumn(i int) []byte {
	col := make([]byte, b.NumRows())
	for rowIdx, row := range b {
		col[rowIdx] = row[i]
	}
	return col
}

func (b byteMat) SetColumn(i int, newCol []byte) {
	for rowIdx, val := range newCol {
		b[rowIdx][i] = val
	}
}

func (b byteMat) String() string {
	outputStr := "Printing byteMap \n"
	for _, row := range b {
		for _, val := range row {
			outputStr += fmt.Sprintf("%X ", val)
		}
		outputStr += "\n"
	}
	return outputStr
}
