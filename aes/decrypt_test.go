package aes

import (
	"encoding/hex"
	"fmt"
	"reflect"
	"testing"
)

func Test_blockCipher_KeyExpansion(t *testing.T) {
	type fields struct {
		key   []byte
		state byteMat
		n_k   int
		n_r   int
	}
	tests := []struct {
		name    string
		fields  fields
		wantIdx int
		want    []byte
	}{
		{"Appendix A FIPS 197 128bit i = 4", fields{[]byte{}, [][]byte{}, 4, 10}, 4, []byte{0xa0, 0xfa, 0xfe, 0x17}},
		{"Appendix A FIPS 197 128bit i = 43", fields{[]byte{}, [][]byte{}, 4, 10}, 43, []byte{0xb6, 0x63, 0x0c, 0xa6}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := hex.DecodeString("2b7e151628aed2a6abf7158809cf4f3c")
			if err != nil {
				t.Fatal("couldn't decode string")
			}
			fmt.Println(key)
			b, err := NewBlockCipher(key, 128)
			if err != nil {
				t.Fatal("couldn't create block cipher")
			}
			if got := b.KeyExpansion(key); !reflect.DeepEqual(got[tt.wantIdx], tt.want) {
				t.Errorf("blockCipher.KeyExpansion() = %v, want %v", got[tt.wantIdx], tt.want)
			}
		})
	}
}
