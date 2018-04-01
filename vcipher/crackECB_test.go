package vcipher

import (
	"bytes"
	"log"
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
				Key:  bytes.Repeat([]byte("A"), 16),
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
	want := 4
	if prefixSize != want {
		log.Printf("Thought %d, was %d", want, prefixSize)
		t.Fatal("unable to find the prefix size")
	}

	e.SetBeginBytes([]byte("1234567"))
	e.SetEndBytes([]byte("sixsix"))
	e.RandomizeKey()
	e.SetEncryptionMode(ECB_ENCODE)
	prefixSize = FindPrefixSize(e, 16)
	want2 := 7
	if prefixSize != want2 {
		log.Printf("Thought %d, was %d", want2, prefixSize)

		t.Fatal("unable to find the prefix size, the second time")
	}
}
