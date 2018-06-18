package webserver

import (
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/valakuzhyk/cryptopals/sha1"
	"github.com/valakuzhyk/cryptopals/utils"
)

// insecureCompare compares character by character, ending early at the first deviation.
func insecureCompare(fileName, signature string) bool {
	sigBytes, err := hex.DecodeString(signature)
	if err != nil {
		log.Fatal("Unable to decode signature", err)
	}
	fileHash := sha1.MAC(key, fileName)
	for i, c := range fileHash {
		if i > len(sigBytes)-1 {
			return false
		}
		if c != sigBytes[i] {
			return false
		}
		time.Sleep(20 * time.Millisecond)
	}
	return true
}

// Used in challenge 31
func hmacFileValidator(w http.ResponseWriter, r *http.Request) {
	// Need to parse the arguments, and then validate the file argument has the same sha hash as the file argument.
	uri := strings.TrimPrefix(r.RequestURI, "/challenge31?")
	args, err := utils.ParseKeyValuePairs(uri)
	if err != nil {
		fmt.Fprintf(w, "Invalid uri arguments %s", uri)
		return
	}
	fileName, ok1 := args["file"]
	signature, ok2 := args["signature"]
	if ok1 && ok2 {
		isValid := insecureCompare(fileName, signature)
		if !isValid {
			fmt.Fprintf(w, "Invalid signature (%s) for %s", signature, fileName)
			return
		}
		fmt.Fprintf(w, "Valid signature!")
	}
}
