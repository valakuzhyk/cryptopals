package utils

import (
	"log"
)

func EnglishFreq() []float32 {
	return []float32{
		0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015, // A-G
		0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749, // H-N
		0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758, // O-U
		0.00978, 0.02360, 0.00150, 0.01974, 0.00074, // V-Z
	}
}

func EnglishScore(s string) float32 {
	count := make([]int, 26)
	ignored := 0

	for i := range s {
		c := byte(s[i])
		if c >= 65 && c <= 90 {
			count[c-65]++ // uppercase A-Z
		} else if c >= 97 && c <= 122 {
			count[c-97]++ // lowercase a-z
		} else if c >= 32 && c <= 126 {
			ignored++ // punct with numbers removed.
		} else if c == 9 || c == 10 || c == 13 {
			ignored++ // TAB, CR, LF
		} else {
			return 100000
			// return Infinity;  // not printable ASCII = impossible(?)
		}
	}

	chi2 := float32(0)
	length := len(s) - ignored
	if float32(ignored) > 0.3*float32(len(s)) {
		return 100000
	}
	englishFreq := EnglishFreq()
	for i := 0; i < 26; i++ {
		observed := float32(count[i])
		expected := float32(length) * englishFreq[i]
		difference := observed - expected
		chi2 += difference * difference / expected
	}
	return chi2
}

func Xor(b1, b2 []byte) []byte {
	if len(b1) != len(b2) {
		log.Fatalln("Buffers do not match, cannot compute xor")
	}
	output := make([]byte, len(b1))
	for i := range b1 {
		output[i] = b1[i] ^ b2[i]
	}
	return output
}

func RepeatingXor(b1, b2 []byte) []byte {
	output := make([]byte, len(b1))
	for i := range b1 {
		output[i] = b1[i%len(b1)] ^ b2[i%len(b2)]
	}
	return output
}
