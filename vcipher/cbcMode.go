package vcipher

import (
	"crypto/cipher"
	"fmt"

	"github.com/valakuzhyk/cryptopals/xor"
)

type cbcEncrypter struct {
	blockCipher cipher.Block
	iv          []byte
}

func NewCBCEncrypter(block cipher.Block, iv []byte) (cipher.BlockMode, error) {
	if len(iv) != block.BlockSize() {
		return nil, fmt.Errorf("iv length (%d) must be equal to blocksize (%d)", len(iv), block.BlockSize())
	}
	return cbcEncrypter{blockCipher: block, iv: iv}, nil
}

func (e cbcEncrypter) BlockSize() int {
	return e.blockCipher.BlockSize()
}

func (e cbcEncrypter) CryptBlocks(dst, src []byte) {
	if len(dst) < len(src) {
		panic(fmt.Errorf("Destination smaller than source"))
	} else if len(src)%e.BlockSize() != 0 {
		panic(fmt.Errorf("src is not a multiple of the block size"))
	}
	previousCipherBlock := e.iv
	for i := 0; i < len(src); i += e.BlockSize() {
		blockToEncrypt := xor.Xor(previousCipherBlock, src[i:i+e.BlockSize()])
		e.blockCipher.Encrypt(dst[i:i+e.BlockSize()], blockToEncrypt)
		previousCipherBlock = dst[i : i+e.BlockSize()]
	}
}

type cbcDecrypter struct {
	blockCipher cipher.Block
	iv          []byte
}

func NewCBCDecrypter(block cipher.Block, iv []byte) (cipher.BlockMode, error) {
	if len(iv) != block.BlockSize() {
		return nil, fmt.Errorf("iv length (%d) must be equal to blocksize (%d)", len(iv), block.BlockSize())
	}
	return cbcDecrypter{blockCipher: block, iv: iv}, nil
}

func (e cbcDecrypter) BlockSize() int {
	return e.blockCipher.BlockSize()
}

func (e cbcDecrypter) CryptBlocks(dst, src []byte) {
	if len(dst) < len(src) {
		panic(fmt.Errorf("Destination smaller than source"))
	} else if len(src)%e.BlockSize() != 0 {
		panic(fmt.Errorf("src is not a multiple of the block size"))
	}
	previousCipherBlock := e.iv
	for i := 0; i < len(src); i += e.BlockSize() {
		decryptedBlock := make([]byte, e.BlockSize())
		e.blockCipher.Decrypt(decryptedBlock, src[i:i+e.BlockSize()])
		plaintextBlock := xor.Xor(previousCipherBlock, decryptedBlock)
		for idx, b := range plaintextBlock {
			dst[i+idx] = b
		}
		previousCipherBlock = src[i : i+e.BlockSize()]
	}
}
