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
