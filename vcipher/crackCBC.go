package vcipher

import (
	"log"
	"math"

	"github.com/valakuzhyk/cryptopals/utils"
)

// Oracle is a struct that is a source of groundtruth about something relating
// to a encryption scheme. Oftentimes, the information that is leaked out of
// an oracle can be used to gain greater understanding of ciphertext, or to
// manipulate ciphertext for your own gain.
type Oracle struct {
	encrypter RandomEncrypter
}

// NewCBCOracle returns an oracle that returns properties of a CBC
// cipher.
func NewCBCOracle(encrypter RandomEncrypter) Oracle {
	if encrypter.Mode != CBC_DECODE {
		log.Fatal("Hey now. Hey now... wrong mode.")
	}
	encrypter.SetIgnorePadding(true)
	return Oracle{encrypter}
}

// HasValidPadding returns true if a given ciphertext has appropriate padding.
// This can be used to mount an attack on CBC.
func (o Oracle) HasValidPadding(iv, ciphertext []byte) bool {
	o.encrypter.IV = iv
	decrypted := o.encrypter.Encrypt(ciphertext)
	validPadding, _ := utils.RemovePKCS7Padding(string(decrypted), o.encrypter.GetBlockSize())
	return validPadding
}

// DecodeCBCWithPaddingOracle returns the plaintext from ciphertext given that you have an oracle
// that tells you whether the padding on a given message is valid.
func DecodeCBCWithPaddingOracle(iv, ciphertext []byte, oracle Oracle) []byte {
	// We can decode each block at a time.
	blockSize := len(iv)
	decodedBlocks := []byte{}

	blocks, err := utils.Blockify(ciphertext, blockSize)
	if err != nil {
		log.Fatal("Ciphertext is not a multiple of the block size: ", err)
	}

	// Special case the first block
	decodedBlocks = append(decodedBlocks,
		decodeCBCBlockWithPaddingOracle(iv, blocks[0], oracle)...)

	for i := 1; i < len(blocks); i++ {
		decodedBlocks = append(decodedBlocks,
			decodeCBCBlockWithPaddingOracle(blocks[i-1], blocks[i], oracle)...)
	}
	_, depaddedString := utils.RemovePKCS7Padding(string(decodedBlocks), blockSize)

	return []byte(depaddedString)
}

func decodeCBCBlockWithPaddingOracle(previousBlock, block []byte, oracle Oracle) []byte {
	blockSize := len(block)
	decryptedBlock := make([]byte, blockSize)

	pBlock := make([]byte, blockSize)
	copy(pBlock, previousBlock)

	for currByte := blockSize - 1; currByte >= 0; currByte-- {
		currByteVal := pBlock[currByte]
		for guess := 0; guess < math.MaxUint8; guess++ {
			pBlock[currByte] = currByteVal ^ byte(guess)
			isValid := oracle.HasValidPadding(pBlock, block)

			if !isValid {
				continue
			}

			if currByte == blockSize-1 {
				pBlock[currByte-1] ^= 1
				isValid := oracle.HasValidPadding(pBlock, block)
				pBlock[currByte-1] ^= 1
				if !isValid {
					continue
				}
			}

			// If this byte is valid, then we think that the byte's value is 'currByte'
			// This means originalByte ^ guess = currByte
			// Which implies originalByte = currByte ^ guess
			paddingByte := byte(blockSize - currByte)
			originalByte := paddingByte ^ byte(guess)
			decryptedBlock[currByte] = originalByte

			// Now we have to set all the padding bytes before this point to the next highest number
			transform := byte(paddingByte ^ (paddingByte + 1))
			for i := currByte; i < blockSize; i++ {
				pBlock[i] ^= transform
			}
			break
		}
	}
	return decryptedBlock
}
