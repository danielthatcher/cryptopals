package main

import (
	"crypto/aes"
	"fmt"
	"math/rand"
	"time"
)

func sliceXOR(a []byte, b []byte) []byte {
	r := make([]byte, len(a))
	for i := range r {
		r[i] = a[i] ^ b[i]
	}
	return r
}

func pad(text []byte, blocksize int) []byte {
	padAmount := blocksize - (len(text) % blocksize)
	ret := text
	for i := 0; i < padAmount; i++ {
		ret = append(ret, byte(0x04))
	}
	return ret
}

func CBCEncrypt(plaintext []byte, key []byte, iv []byte) []byte {
	ciphertext := make([]byte, len(plaintext))
	cipher, _ := aes.NewCipher(key)
	for i := 0; i < len(plaintext); i += len(key) {
		dest := make([]byte, len(key))
		xored := make([]byte, len(key))
		if i > 0 {
			xored = sliceXOR(plaintext[i:i+len(key)], plaintext[i-len(key):i])
		} else {
			xored = sliceXOR(plaintext[i:i+len(key)], iv)
		}

		cipher.Encrypt(dest, xored)
		for j := range dest {
			ciphertext[i+j] = dest[j]
		}
	}

	return ciphertext
}

func ECBEncrypt(plaintext []byte, key []byte) []byte {
	ciphertext := make([]byte, len(plaintext))
	cipher, _ := aes.NewCipher(key)
	for i := 0; i < len(plaintext); i += len(key) {
		dest := make([]byte, len(key))
		cipher.Encrypt(dest, plaintext[i:i+len(key)])
		for j := range dest {
			ciphertext[i+j] = dest[j]
		}
	}

	return ciphertext
}

func randomBytes(l int) []byte {
	r := make([]byte, l)
	for i := range r {
		r[i] = byte(rand.Int() % 256)
	}

	return r
}

func randomCrypt(plaintext []byte) []byte {
	key := randomBytes(16)
	ciphertext := make([]byte, len(plaintext))

	// Append random bytes the start and end of the plaintext
	preBytes := randomBytes(5 + rand.Intn(5))
	appBytes := randomBytes(5 + rand.Intn(5))
	plaintext = append(preBytes, plaintext...)
	plaintext = append(plaintext, appBytes...)
	plaintext = pad(plaintext, 16)

	// Encrypt (50/50 CBC/ECB)
	if rand.Int()%2 == 0 {
		iv := randomBytes(16)
		ciphertext = CBCEncrypt(plaintext, key, iv)
	} else {
		ciphertext = ECBEncrypt(plaintext, key)
	}

	return ciphertext
}

func main() {
	rand.Seed(time.Now().UnixNano())
	fmt.Println(randomCrypt([]byte("YELLOW SUBMARINE")))
}
