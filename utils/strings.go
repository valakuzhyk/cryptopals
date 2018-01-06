package utils

func CollectEveryNthRune(s string, n int) string {
	output := ""
	for i, c := range s {
		if i%n == 0 {
			output += string(c)
		}
	}
	return output
}
