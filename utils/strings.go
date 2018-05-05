package utils

// CollectEveryNthRune returns every nth rune in the string.
func CollectEveryNthRune(s string, n int) string {
	output := ""
	for i, c := range s {
		if i%n == 0 {
			output += string(c)
		}
	}
	return output
}

// IsValidASCII returns whether all of the bytes are ascii bytes.
func IsValidASCII(bytes []byte) bool {
	for _, b := range bytes {
		if b > 127 {
			return false
		}
	}
	return true
}
