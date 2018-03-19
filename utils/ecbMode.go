package utils

import (
	"crypto/cipher"
	"fmt"
)

type ecbEncrypter struct {
	blockCipher cipher.Block
}

func NewECBEncrypter(block cipher.Block) cipher.BlockMode {
	return ecbEncrypter{blockCipher: block}
}

func (e ecbEncrypter) BlockSize() int {
	return e.blockCipher.BlockSize()
}

func (e ecbEncrypter) CryptBlocks(dst, src []byte) {
	if len(dst) < len(src) {
		panic(fmt.Errorf("Destination smaller than source"))
	} else if len(src)%e.BlockSize() != 0 {
		panic(fmt.Errorf("src is not a multiple of the block size"))
	}
	for i := 0; i < len(src); i += e.BlockSize() {
		e.blockCipher.Encrypt(dst[i:i+e.BlockSize()], src[i:i+e.BlockSize()])
	}
}

type ecbDecrypter struct {
	blockCipher cipher.Block
}

func NewECBDecrypter(block cipher.Block) cipher.BlockMode {
	return ecbDecrypter{blockCipher: block}
}

func (d ecbDecrypter) BlockSize() int {
	return d.blockCipher.BlockSize()
}

func (d ecbDecrypter) CryptBlocks(dst, src []byte) {
	if len(dst) < len(src) {
		panic(fmt.Errorf("Destination smaller than source"))
	} else if len(src)%d.BlockSize() != 0 {
		panic(fmt.Errorf("src is not a multiple of the block size"))
	}
	for i := 0; i < len(src); i += d.BlockSize() {
		d.blockCipher.Decrypt(dst[i:i+d.BlockSize()], src[i:i+d.BlockSize()])
	}
}
