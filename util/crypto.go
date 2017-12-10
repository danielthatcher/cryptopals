package util

import (
	"crypto/aes"
	"encoding/binary"
)

func ECBDecrypt(ciphertext []byte, key []byte) []byte {
	block, _ := aes.NewCipher(key)
	plaintext := make([]byte, len(ciphertext))
	for i := 0; i < len(ciphertext); i += len(key) {
		dst := make([]byte, len(key))
		block.Decrypt(dst, ciphertext[i:i+len(key)])
		for j := range dst {
			plaintext[i+j] = dst[j]
		}
	}

	return plaintext
}

func CTRCrypt(ciphertext []byte, key []byte, nonce []byte) []byte {
	block, _ := aes.NewCipher(key)
	plaintext := make([]byte, len(ciphertext))

	for counter := uint64(0); counter*uint64(len(key)) < uint64(len(ciphertext)); counter++ {
		counterSlice := make([]byte, 8)
		binary.LittleEndian.PutUint64(counterSlice, counter)
		combined := append(nonce, counterSlice...)
		c := make([]byte, 16)
		block.Encrypt(c, combined)
		for i := counter * uint64(len(key)); i < (counter+1)*uint64(len(key)) && i < uint64(len(ciphertext)); i++ {
			plaintext[i] = ciphertext[i] ^ c[i-(counter*uint64(len(key)))]
		}
	}

	return plaintext
}
