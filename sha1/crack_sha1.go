package sha1

import (
	"encoding/binary"
	"strings"
)

type ValidatedMessage struct {
	MAC     []byte
	Message string
}

// BreakSHA1KeyedMAC returns the MAC and corresponding final message for
// different guessed keysizes within the specified bounds.
func BreakSHA1KeyedMAC(message, desiredExtension string, oldMAC []byte, minKeyLen, maxKeyLen int) map[int]ValidatedMessage {
	c := Calculator{
		h0: binary.BigEndian.Uint32(oldMAC[0*4:]),
		h1: binary.BigEndian.Uint32(oldMAC[1*4:]),
		h2: binary.BigEndian.Uint32(oldMAC[2*4:]),
		h3: binary.BigEndian.Uint32(oldMAC[3*4:]),
		h4: binary.BigEndian.Uint32(oldMAC[4*4:]),
	}

	// we need to control the padding at the very end of all of this, so we need to know the size of the  + extension.
	// We know that (key + message + padding glue) must be a multiple of 64 * 8.
	// However, this means that the mac generated would be different depending on the key size.
	// We'll simply have to output different values for each key size.

	potentialSolutions := make(map[int]ValidatedMessage)

	for i := minKeyLen; i < maxKeyLen; i++ {
		key := strings.Repeat("A", i)
		paddingGlue := generatePadding(key + message)
		generatedMsg := key + message + string(paddingGlue) + desiredExtension
		generatedMsgPadding := string(generatePadding(generatedMsg))

		newMAC := c.hashPadded([]byte(desiredExtension + generatedMsgPadding))
		expectedMsg := message + string(paddingGlue) + desiredExtension
		potentialSolutions[i] = ValidatedMessage{
			MAC:     newMAC,
			Message: expectedMsg,
		}
	}

	return potentialSolutions
}
