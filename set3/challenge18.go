package main

import (
	"crypto/aes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
)

func CTRDecrypt(ciphertext []byte, key []byte, nonce []byte) []byte {
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

func main() {
	ciphertext, _ := base64.StdEncoding.DecodeString("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
	nonce := make([]byte, 8)
	for i := range nonce {
		nonce[i] = byte(0)
	}
	fmt.Println(string(CTRDecrypt(CTRDecrypt(ciphertext, []byte("YELLOW SUBMARINE")), nonce)))
}
