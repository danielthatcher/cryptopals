package main

import (
	"crypto/aes"
	"encoding/base64"
	"fmt"
	"io/ioutil"
)

func sliceXOR(a []byte, b []byte) []byte {
	r := make([]byte, len(a))
	for i := range r {
		r[i] = a[i] ^ b[i]
	}
	return r
}

func aesCBC(ciphertext []byte, key []byte, iv []byte) []byte {
	plaintext := make([]byte, len(ciphertext))
	cipher, _ := aes.NewCipher(key)
	for i := 0; i < len(ciphertext); i += len(key) {
		dest := make([]byte, len(key))
		cipher.Decrypt(dest, ciphertext[i:i+len(key)])
		if i > 0 {
			dest = sliceXOR(dest, ciphertext[i-len(key):i])
		} else {
			dest = sliceXOR(dest, iv)
		}

		for j := range dest {
			plaintext[i+j] = dest[j]
		}
	}
	return plaintext
}

func main() {
	f, _ := ioutil.ReadFile("set2/10.txt")
	cipherbytes, _ := base64.StdEncoding.DecodeString(string(f))
	iv := make([]byte, 16)
	for i := range iv {
		iv[i] = 0x00
	}
	fmt.Println(string(aesCBC(cipherbytes, []byte("YELLOW SUBMARINE"), iv)))
}
