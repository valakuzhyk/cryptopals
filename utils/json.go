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
			return nil, fmt.Errorf("Invalid format for pair %s", p)
		}
		kvMapping[keyValue[0]] = keyValue[1]

	}
	return kvMapping, nil
}

// ProfileFor generates a profile according to how we would want it for
// challenge 13.
func ProfileFor(email string) string {
	email = strings.Replace(email, "&", "", -1)
	email = strings.Replace(email, "=", "", -1)
	return fmt.Sprintf("email=%s&uid=10&role=user", email)
}
