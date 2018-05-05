package sha1

import (
	"encoding/hex"
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
		{"Empty String", args{""}, "da39a3ee5e6b4b0d3255bfef95601890afd80709"},
		{"Wiki example", args{"The quick brown fox jumps over the lazy dog"}, "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Hash(tt.args.message)
			gotHexString := hex.EncodeToString(got)
			if gotHexString != tt.want {
				t.Errorf("SHA1() = %v, want %v", gotHexString, tt.want)
			}
		})
	}
}
