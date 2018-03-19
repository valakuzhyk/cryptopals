package aes

import (
	"fmt"
	"reflect"
	"testing"
)

func Test_blockCipher_Decrypt(t *testing.T) {
	type args struct {
		dst []byte
		src []byte
	}
	tests := []struct {
		name string
		key  []byte
		args args
		want byteMat
	}{
		{
			"Appendix B Example",
			[]byte{0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c},
			args{[]byte{}, []byte{0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32}},
			byteMat{
				[]byte{0x32, 0x88, 0x31, 0xe0},
				[]byte{0x43, 0x5a, 0x31, 0x37},
				[]byte{0xf6, 0x30, 0x98, 0x07},
				[]byte{0xa8, 0x8d, 0xa2, 0x34},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := NewBlockCipher(tt.key)
			if err != nil {
				t.Fatal("Error in block cipher creation.", err)
			}
			b.Decrypt(tt.args.dst, tt.args.src)
			if !reflect.DeepEqual(tt.want, b.state) {
				fmt.Println(b.state)
				t.Fatal("Failure")
			}
		})
	}
}

func Test_blockCipher_invMixColumns(t *testing.T) {
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
				[]byte{0x04, 0xe0, 0x48, 0x28},
				[]byte{0x66, 0xcb, 0xf8, 0x06},
				[]byte{0x81, 0x19, 0xd3, 0x26},
				[]byte{0xe5, 0x9a, 0x7a, 0x4c},
			}, 4, 10,
		},
			byteMat{
				[]byte{0xd4, 0xe0, 0xb8, 0x1e},
				[]byte{0xbf, 0xb4, 0x41, 0x27},
				[]byte{0x5d, 0x52, 0x11, 0x98},
				[]byte{0x30, 0xae, 0xf1, 0xe5},
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
			b.invMixColumns()
			if !reflect.DeepEqual(tt.want, b.state) {
				fmt.Println(b.state)
				t.Fatal("Failed to produce correct state.")
			}
		})
	}
}

func Test_blockCipher_invSubBytes(t *testing.T) {
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
				[]byte{0x27, 0xbf, 0xb4, 0x41},
				[]byte{0x11, 0x98, 0x5d, 0x52},
				[]byte{0xae, 0xf1, 0xe5, 0x30},
			}, 4, 10,
		},
			byteMat{
				[]byte{0x19, 0xa0, 0x9a, 0xe9},
				[]byte{0x3d, 0xf4, 0xc6, 0xf8},
				[]byte{0xe3, 0xe2, 0x8d, 0x48},
				[]byte{0xbe, 0x2b, 0x2a, 0x08},
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
			b.invSubBytes()
			if !reflect.DeepEqual(tt.want, b.state) {
				fmt.Println(b.state)
				t.Fatal("Failed to produce correct state.")
			}
		})
	}
}

func Test_blockCipher_invShiftRows(t *testing.T) {
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
			}, 4, 10,
		},
			byteMat{
				[]byte{0xd4, 0xe0, 0xb8, 0x1e},
				[]byte{0x27, 0xbf, 0xb4, 0x41},
				[]byte{0x11, 0x98, 0x5d, 0x52},
				[]byte{0xae, 0xf1, 0xe5, 0x30},
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
			b.invShiftRows()
			if !reflect.DeepEqual(tt.want, b.state) {
				fmt.Println(b.state)
				t.Fatal("Failed to produce correct state.")
			}
		})
	}
}
