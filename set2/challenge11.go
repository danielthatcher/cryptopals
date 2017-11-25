package main

import (
	"crypto/aes"
	"fmt"
	"io/ioutil"
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

func randomCrypt(plaintext []byte) ([]byte, string) {
	key := randomBytes(16)
	ciphertext := make([]byte, len(plaintext))

	// Append random bytes the start and end of the plaintext
	preBytes := randomBytes(5 + rand.Intn(5))
	appBytes := randomBytes(5 + rand.Intn(5))
	plaintext = append(preBytes, plaintext...)
	plaintext = append(plaintext, appBytes...)
	plaintext = pad(plaintext, 16)

	// Encrypt (50/50 CBC/ECB)
	var mode string
	if rand.Int()%2 == 0 {
		mode = "CBC"
		iv := randomBytes(16)
		ciphertext = CBCEncrypt(plaintext, key, iv)
	} else {
		mode = "ECB"
		ciphertext = ECBEncrypt(plaintext, key)
	}

	return ciphertext, mode
}

func sliceEq(a []byte, b []byte) bool {
	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}

	return true
}

func detectECB(ciphertext []byte, blocksize int) bool {
	for i := 0; i < len(ciphertext); i += blocksize {
		a := ciphertext[i : i+blocksize]
		for j := i + blocksize; j < len(ciphertext); j += blocksize {
			b := ciphertext[j : j+blocksize]
			if sliceEq(a, b) {
				return true
			}
		}
	}

	return false
}

func main() {
	rand.Seed(time.Now().UnixNano())
	f, _ := ioutil.ReadFile("set2/11.txt")
	ciphertext, mode := randomCrypt([]byte(f))
	detected := detectECB(ciphertext, 16)
	if detected && (mode == "ECB") {
		fmt.Println("Successfully detected ECB")
	} else if !detected && (mode == "CBC") {
		fmt.Println("Successfully detected CBC")
	} else {
		fmt.Println("FAILED!")
	}
}
