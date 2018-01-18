package utils

import (
	"strings"
	"unicode"
)

// Start blacklisting characters
// Start

func EnglishFreq() map[rune]float64 {
	return map[rune]float64{
		'a': 0.08167, 'b': 0.01492, 'c': 0.02782, 'd': 0.04253, 'e': 0.12702, 'f': 0.02228, 'g': 0.02015, // A-G
		'h': 0.06094, 'i': 0.06966, 'j': 0.00153, 'k': 0.00772, 'l': 0.04025, 'm': 0.02406, 'n': 0.06749, // H-N
		'o': 0.07507, 'p': 0.01929, 'q': 0.00095, 'r': 0.05987, 's': 0.06327, 't': 0.09056, 'u': 0.02758, // O-U
		'v': 0.00978, 'w': 0.02360, 'x': 0.00150, 'y': 0.01974, 'z': 0.00074, // V-Z
	}
}

func EnglishScore(s string) float64 {
	counts := getRuneCounts(s)
	// if float32(numInvalid) > 0.5*float32(len(s)) {
	// 	return 100000
	// }
	chi2 := float64(0)
	englishFreq := EnglishFreq()
	for char, expectedFreq := range englishFreq {
		observed := float64(counts[char])
		expected := float64(len(s)) * expectedFreq
		difference := observed - expected
		chi2 += difference * difference / expected
	}

	for c, count := range counts {
		if c >= 127 {
			chi2 += float64(100 * count)
		} else if unicode.IsSpace(c) {
			// For now we ignore these
		} else if c < 32 {
			chi2 += float64(100 * count)
		} else if unicode.IsDigit(c) {
			chi2 += float64(100 * count)
		} else if strings.ContainsAny(string(c), "<>{}[]()~|%^*#%@&-/`=+_\\") {
			penalty := 100 * count
			chi2 += float64(penalty)
		} else if _, ok := englishFreq[c]; !ok {
			defaultPenalty := float64(20 * count)
			chi2 += defaultPenalty
		}
	}

	return chi2
}

func getRuneCounts(s string) map[rune]int {
	count := make(map[rune]int)
	for _, c := range s {
		count[unicode.ToLower(c)]++
	}
	return count
}
