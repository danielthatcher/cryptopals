package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"math/rand"
	"strings"
	"time"
)

var key []byte

func randomBytes(l int) []byte {
	r := make([]byte, l)
	for i := range r {
		r[i] = byte(rand.Int() % 256)
	}

	return r
}

func pad(text []byte, blocksize int) []byte {
	padAmount := blocksize - (len(text) % blocksize)
	ret := text
	for i := 0; i < padAmount; i++ {
		ret = append(ret, byte(padAmount))
	}
	return ret
}

func checkPadding(data []byte) bool {
	length := int(data[len(data)-1])

	if length == 0 {
		return false
	}

	for i := 1; i <= length; i++ {
		if data[len(data)-i] != byte(length) {
			return false
		}
	}
	return true
}

func encrypt() ([]byte, []byte) {
	// Read file and pick a random line
	f, _ := ioutil.ReadFile("set3/17.txt")
	lines := strings.Split(string(f), "\n")
	l := lines[rand.Intn(len(lines))]
	plaintext, _ := base64.StdEncoding.DecodeString(l)
	plaintext = pad(plaintext, 16)
	fmt.Println(string(plaintext))

	// Encrypt
	key = randomBytes(16)
	iv := randomBytes(16)
	block, _ := aes.NewCipher(key)
	mode := cipher.NewCBCEncrypter(block, iv)
	ciphertext := make([]byte, len(plaintext))
	mode.CryptBlocks(ciphertext, plaintext)

	return ciphertext, iv
}

func decrypt(ciphertext []byte, iv []byte) bool {
	block, _ := aes.NewCipher(key)
	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)
	return checkPadding(plaintext)
}

func decryptBlock(prev []byte, cur []byte) []byte {
	plaintext := make([]byte, len(cur))
	for i := len(prev) - 1; i >= 0; i-- {
		p := make([]byte, len(prev))
		copy(p, prev)
		t := byte(len(prev) - i)

		// Fix so that the padding works
		for j := i + 1; j < len(p); j++ {
			p[j] = prev[j] ^ plaintext[j] ^ t
		}

		// Find the byte
		for b := byte(0); b < 255; b++ {
			p[i] = b
			if decrypt(cur, p) {
				// Verify we're not in the middle of valid padding
				if i != 0 {
					p[i-1] = p[i-1] ^ 0x42
				}

				if i == 0 || decrypt(cur, p) {
					plaintext[i] = prev[i] ^ b ^ t
					break
				}
				p[i-1] = prev[i-1]
			}
		}
	}

	return plaintext
}

func attack(ciphertext []byte, iv []byte) {
	keysize := len(iv)
	plaintext := make([]byte, len(ciphertext))
	for i := len(ciphertext) - keysize; i >= keysize; i -= keysize {
		decr := decryptBlock(ciphertext[i-keysize:i], ciphertext[i:i+keysize])
		for j := range decr {
			plaintext[i+j] = decr[j]
		}
	}

	decr := decryptBlock(iv, ciphertext[:keysize])
	for i := range decr {
		plaintext[i] = decr[i]
	}

	fmt.Println(plaintext)
	fmt.Println(string(plaintext))
}

func main() {
	rand.Seed(time.Now().UnixNano())
	ciphertext, iv := encrypt()
	attack(ciphertext, iv)
}
