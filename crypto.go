package main

import (
	"crypto/cipher"
	"crypto/sha256"

	"golang.org/x/crypto/twofish"
)

// strechPassword runs N iterations of SHA256 on the password+salt.
func strechPassword(pwd string, salt []byte, n uint32) []byte {
	h := sha256.New()
	h.Write([]byte(pwd))
	h.Write(salt)
	for i := uint32(0); i < n; i++ {
		p := h.Sum(nil)
		h.Reset()
		h.Write(p)
	}
	return h.Sum(nil)
}

// decryptECB uses ECB mode to decrypt multiple blocks of data.
func decryptECB(dst, src, key []byte) {
	c, err := twofish.NewCipher(key)
	if err != nil {
		panic(err)
	}
	for i := 0; i < len(src); i += c.BlockSize() {
		c.Decrypt(dst[i:i+c.BlockSize()], src[i:i+c.BlockSize()])
	}
}

// decryptCBC uses CBC mode to decrypt multiple blocks of data with given IV.
func decryptCBC(dst, src, key, iv []byte) {
	c, err := twofish.NewCipher(key)
	if err != nil {
		panic(err)
	}
	cbc := cipher.NewCBCDecrypter(c, iv)
	cbc.CryptBlocks(dst, src)
}
