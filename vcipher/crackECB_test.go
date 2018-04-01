package vcipher

import (
	"strings"
	"testing"
)

func TestCalculateBlockSize(t *testing.T) {
	type args struct {
		encrypter func(input []byte) []byte
	}
	tests := []struct {
		name string
		args args
		want int
	}{
		{"Basic",
			args{RandomEncrypter{
				Key:  []byte(strings.Repeat("A", 16)),
				Mode: ECB_ENCODE,
			}.Encrypt}, 16,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CalculateBlockSize(tt.args.encrypter); got != tt.want {
				t.Errorf("CalculateBlockSize() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFindPrefixSize(t *testing.T) {
	e := AppendEncrypter{}
	e.SetBeginBytes([]byte("1234"))
	e.SetEndBytes([]byte("sixsix"))
	e.RandomizeKey()
	e.SetEncryptionMode(ECB_ENCODE)
	prefixSize := FindPrefixSize(e, 16)
	if prefixSize != 4 {
		t.Fatal("unable to find the appended bytes by iterative decoding")
	}

	e.SetBeginBytes([]byte("1234567"))
	e.SetEndBytes([]byte("sixsix"))
	e.RandomizeKey()
	e.SetEncryptionMode(ECB_ENCODE)
	prefixSize = FindPrefixSize(e, 16)
	if prefixSize != 7 {
		t.Fatal("unable to find the appended bytes by iterative decoding")
	}
}
