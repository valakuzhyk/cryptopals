package aes

import (
	"encoding/hex"
	"fmt"
	"reflect"
	"testing"
)

// func Test_blockCipher_Encrypt(t *testing.T) {
// 	type args struct {
// 		dst []byte
// 		src []byte
// 	}
// 	tests := []struct {
// 		name string
// 		key  []byte
// 		args args
// 	}{
// 		{
// 			"first",
// 			[]byte{0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c},
// 			args{[]byte{}, []byte{0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34}}},
// 	}
// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			b, err := NewBlockCipher(tt.key, 128)
// 			if err != nil {
// 				t.Fatal("Error in block cipher creation.", err)
// 			}
// 			b.Encrypt(tt.args.dst, tt.args.src)
// 			enc := utils.BytesToBase64(tt.args.dst)
// 			fmt.Println(enc)
// 			if enc == "" {
// 				t.Fatal("Failure")
// 			}
// 		})
// 	}
// }

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

func Test_xtime(t *testing.T) {
	type args struct {
		word byte
	}
	tests := []struct {
		name string
		args args
		want byte
	}{
		{"example 1", args{byte(0x57)}, byte(0xae)},
		{"example 2", args{byte(0xae)}, byte(0x47)},
		{"example 3", args{byte(0x47)}, byte(0x8e)},
		{"example 4", args{byte(0x8e)}, byte(0x07)},
		{"X^2", args{byte(0x01)}, byte(0x02)},
		{"X^3", args{byte(0x02)}, byte(0x04)},
		{"X^4", args{byte(0x04)}, byte(0x08)},
		{"X^5", args{byte(0x08)}, byte(0x10)},
		{"X^6", args{byte(0x10)}, byte(0x20)},
		{"X^7", args{byte(0x20)}, byte(0x40)},
		{"X^8", args{byte(0x40)}, byte(0x80)},
		{"X^9", args{byte(0x80)}, byte(0x1b)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := xtime(tt.args.word); got != tt.want {
				t.Errorf("xtime() = %v, want %v", got, tt.want)
			}
		})
	}
}
