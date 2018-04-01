package utils

import (
	"reflect"
	"testing"
)

func TestHammingDistance(t *testing.T) {
	type args struct {
		b1 []byte
		b2 []byte
	}
	tests := []struct {
		name string
		args args
		want int
	}{
		{"basic",
			args{[]byte("this is a test"), []byte("wokka wokka!!!")},
			37,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := HammingDistance(tt.args.b1, tt.args.b2); got != tt.want {
				t.Errorf("HammingDistance() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestShiftBytesLeft(t *testing.T) {
	type args struct {
		b1  []byte
		idx int
	}
	tests := []struct {
		name string
		args args
		want []byte
	}{
		{"shift0", args{[]byte{0x1, 0x2, 0x3}, 0}, []byte{0x1, 0x2, 0x3}},
		{"shift1", args{[]byte{0x1, 0x2, 0x3}, 1}, []byte{0x2, 0x3, 0x1}},
		{"shiftn", args{[]byte{0x1, 0x2, 0x3}, 3}, []byte{0x1, 0x2, 0x3}},
		{"shiftn+1", args{[]byte{0x1, 0x2, 0x3}, 4}, []byte{0x2, 0x3, 0x1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ShiftBytesLeft(tt.args.b1, tt.args.idx); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ShiftBytesLeft() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestShiftBytesRight(t *testing.T) {
	type args struct {
		b1  []byte
		idx int
	}
	tests := []struct {
		name string
		args args
		want []byte
	}{
		{"shift0", args{[]byte{0x1, 0x2, 0x3}, 0}, []byte{0x1, 0x2, 0x3}},
		{"shift1", args{[]byte{0x1, 0x2, 0x3}, 1}, []byte{0x3, 0x1, 0x2}},
		{"shiftn", args{[]byte{0x1, 0x2, 0x3}, 3}, []byte{0x1, 0x2, 0x3}},
		{"shiftn+1", args{[]byte{0x1, 0x2, 0x3}, 4}, []byte{0x3, 0x1, 0x2}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ShiftBytesRight(tt.args.b1, tt.args.idx); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ShiftBytesRight() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFirstBlockDiff(t *testing.T) {
	type args struct {
		input1    []byte
		input2    []byte
		blockSize int
	}
	tests := []struct {
		name string
		args args
		want int
	}{
		{"Second Block", args{[]byte{0x00, 0x01, 0x02, 0x02}, []byte{0x00, 0x01, 0x02, 0x3}, 2}, 1},
		{"First Block", args{[]byte{0x00, 0x00, 0x02, 0x02}, []byte{0x00, 0x01, 0x02, 0x3}, 2}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FirstBlockDiff(tt.args.input1, tt.args.input2, tt.args.blockSize); got != tt.want {
				t.Errorf("FirstBlockDiff() = %v, want %v", got, tt.want)
			}
		})
	}
}
