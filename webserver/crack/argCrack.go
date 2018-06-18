package crack

import (
	"bytes"
	"encoding/hex"
	"log"
	"sort"
	"time"
)

// GuessArgBasedOnDelay returns the input that is most likely to
func GuessArgBasedOnDelay(requestSender func(string) time.Duration, byteLen int) []byte {
	byteVals := make([]int, 256)
	reps := 3

	// Keep guessing first character based on delay in requestSender
	guessedString := bytes.Repeat([]byte{0x00}, byteLen)
	for i := range guessedString {
		timingMap := make(map[int]time.Duration)

		for b := 0; b < 256; b++ {
			guessedString[i] = byte(b)
			s := hex.EncodeToString(guessedString)

			totalDelay := time.Duration(0)
			for j := 0; j < reps; j++ {
				delay := requestSender(s)
				totalDelay += delay
				if delay > (time.Duration(b)+1)*5*time.Millisecond {
					log.Println("Delay for ", s, " was ", delay)
				}
			}

			timingMap[b] = totalDelay / time.Duration(reps)

			// Reset byteVals
			byteVals[b] = b
		}

		sort.Slice(byteVals, func(i, j int) bool {
			return timingMap[byteVals[i]] > timingMap[byteVals[j]]
		})

		// Take the key that was the longest, and make that the actual byte in the key
		guessedString[i] = byte(byteVals[0])
	}

	return guessedString
}
