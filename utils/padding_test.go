package utils

import (
	"testing"
)

func TestAddPKCS7Padding(t *testing.T) {
	type args struct {
		s         string
		blockSize int
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"Normal Padding", args{"YELLOW SUBMARINE", 20}, "YELLOW SUBMARINE\x04\x04\x04\x04"},
		{"Normal Padding", args{"RED", 3}, "RED\x03\x03\x03"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := AddPKCS7Padding(tt.args.s, tt.args.blockSize); got != tt.want {
				t.Errorf("AddPKCS7Padding() = %v, want %v", []byte(got), []byte(tt.want))
			}
		})
	}
}

func TestRemovePKCS7Padding(t *testing.T) {
	type args struct {
		s         string
		blockSize int
	}
	tests := []struct {
		name  string
		args  args
		want  bool
		want1 string
	}{
		{"HasPadding", args{"YELLOW\x04\x04\x04\x04", 10}, true, "YELLOW"},
		{"NoPadding", args{"YELLOW\x04\x04\x04", 10}, false, "YELLOW\x04\x04\x04"},
		{"NotAtBlockSize", args{"YELLOW\x03\x03\x03", 10}, false, "YELLOW\x03\x03\x03"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1 := RemovePKCS7Padding(tt.args.s, tt.args.blockSize)
			if got != tt.want {
				t.Errorf("RemovePKCS7Padding() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("RemovePKCS7Padding() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}
