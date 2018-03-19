package utils

import "testing"

func TestCountRepeats(t *testing.T) {
	type args struct {
		s         string
		blockSize int
	}
	tests := []struct {
		name string
		args args
		want int
	}{
		{"1 repeat", args{"abcabc", 3}, 1},
		{"1 repeatWithPartial", args{"abcabcd", 3}, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CountRepeats(tt.args.s, tt.args.blockSize); got != tt.want {
				t.Errorf("CountRepeats() = %v, want %v", got, tt.want)
			}
		})
	}
}
