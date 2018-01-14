package util

import (
	"crypto/aes"
	"crypto/cipher"
)

func CBCMAC(msg []byte, key []byte, iv []byte) []byte {
	if len(key) != len(iv) {
		panic("Invalid key and IV different lengths")
	}

	msg = Pad(msg, len(key))

	block, _ := aes.NewCipher(key)
	mode := cipher.NewCBCEncrypter(block, iv)
	crypted := make([]byte, len(msg))
	mode.CryptBlocks(crypted, msg)
	return crypted[len(crypted)-len(iv):]
}
