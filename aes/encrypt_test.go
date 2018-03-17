package aes

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/valakuzhyk/cryptopals/utils"
)

func Test_blockCipher_Encrypt(t *testing.T) {
	type args struct {
		dst []byte
		src []byte
	}
	tests := []struct {
		name string
		key  []byte
		args args
	}{
		{
			"first",
			[]byte{0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c},
			args{[]byte{}, []byte{0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := NewBlockCipher(tt.key, 128)
			if err != nil {
				t.Fatal("Error in block cipher creation.", err)
			}
			b.Encrypt(tt.args.dst, tt.args.src)
			enc := utils.BytesToBase64(tt.args.dst)
			fmt.Println(enc)
			if enc == "" {
				t.Fatal("Failure")
			}
		})
	}
}

func Test_blockCipher_mixColumns(t *testing.T) {
	type fields struct {
		key   []byte
		state byteMat
		n_k   int
		n_r   int
	}
	tests := []struct {
		name   string
		fields fields
		want   byteMat
	}{
		{"Appx B, step 1", fields{
			[]byte{0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c},
			byteMat{
				[]byte{0xd4, 0xe0, 0xb8, 0x1e},
				[]byte{0xbf, 0xb4, 0x41, 0x27},
				[]byte{0x5d, 0x52, 0x11, 0x98},
				[]byte{0x30, 0xae, 0xf1, 0xe5},
			},
			4, 10,
		},
			byteMat{
				[]byte{0x04, 0xe0, 0x48, 0x28},
				[]byte{0x66, 0xcb, 0xf8, 0x06},
				[]byte{0x81, 0x19, 0xd3, 0x26},
				[]byte{0xe5, 0x9a, 0x7a, 0x4c},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := blockCipher{
				key:   tt.fields.key,
				state: tt.fields.state,
				n_k:   tt.fields.n_k,
				n_r:   tt.fields.n_r,
			}
			b.mixColumns()
			if !reflect.DeepEqual(tt.want, b.state) {
				t.Fatal("Failed to produce correct state.")
			}
		})
	}
}