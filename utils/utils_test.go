package utils

import "testing"

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
