package utils

import (
	"fmt"
	"strings"
)

// ParseKeyValuePairs returns a map of key value pairs parsed in the same
// format as structured cookies.
func ParseKeyValuePairs(kvPairs string) (map[string]string, error) {
	kvMapping := make(map[string]string)
	pairs := strings.Split(kvPairs, "&")
	for _, p := range pairs {
		keyValue := strings.Split(p, "=")
		if len(keyValue) != 2 {
			return nil, fmt.Errorf("Invalid format for pair", p)
		}
		kvMapping[keyValue[0]] = keyValue[1]

	}
	return kvMapping, nil
}

func ProfileFor(email string) {

}
