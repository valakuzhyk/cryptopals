package md4

import (
	"encoding/hex"
	"reflect"
	"strings"
	"testing"
)

func TestHash(t *testing.T) {
	type args struct {
		message string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"Empty String", args{""}, "31d6cfe0d16ae931b73c59d7e0c089c0"},
		{"Second ietf example", args{"a"}, "bde52cb31de33e46245e05fbdbd6fb24"},
		{"Last ietf example", args{"12345678901234567890123456789012345678901234567890123456789012345678901234567890"}, "e33b4ddc9c38f2199c3e7b164fcc0536"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Hash(tt.args.message)
			gotHexString := hex.EncodeToString(got)
			if gotHexString != tt.want {
				t.Errorf("MD4() = %v, want %v", gotHexString, tt.want)
			}
		})
	}
}

func Test_generatePadding(t *testing.T) {
	type args struct {
		message string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"Empty string",
			args{""},
			"\x80" + strings.Repeat("\x00", 62) + "\x00",
		},
		{"One Byte",
			args{"a"},
			"\x80" + strings.Repeat("\x00", 54) + "\x08\x00\x00\x00\x00\x00\x00\x00",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := generatePadding(tt.args.message); got != tt.want {
				t.Errorf("generatePadding() = %v, want %v", []byte(got), []byte(tt.want))
			}
		})
	}
}

func Test_indexingFunction(t *testing.T) {
	type args struct {
		phase int
		index int
	}
	tests := []struct {
		name string
		args args
		want int
	}{
		{"F1", args{1, 1}, 4},
		{"F1", args{1, 2}, 8},
		{"F1", args{1, 5}, 5},
		{"F1", args{1, 12}, 3},
		{"F2", args{2, 1}, 8},
		{"F2", args{2, 5}, 10},
		{"F2", args{2, 9}, 9},
		{"F2", args{2, 10}, 5},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := indexingFunction(tt.args.phase); !reflect.DeepEqual(got(tt.args.index), tt.want) {
				t.Errorf("indexingFunction() = %v, want %v", got(tt.args.index), tt.want)
			}
		})
	}
}
