package main

import (
	"crypto/aes"
	"encoding/base64"
	"fmt"
	"math/rand"
	"time"
)

var key []byte

func pad(text []byte, blocksize int) []byte {
	padAmount := blocksize - (len(text) % blocksize)
	ret := text
	for i := 0; i < padAmount; i++ {
		ret = append(ret, byte(0x04))
	}
	return ret
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

func encrypt(plaintext []byte) []byte {
	app, _ := base64.StdEncoding.DecodeString("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
	plaintext = append(plaintext, []byte(app)...)
	plaintext = pad(plaintext, len(key))
	ciphertext := ECBEncrypt(plaintext, key)
	return ciphertext
}

func decrypt() []byte {
	// Get the keysize - keep adding more bytes to the start of the text
	// until the length of the returned ciphertext changes
	// Also get the length of the hidden text
	var keysize int
	var hiddenLength int
	padText := []byte("")
	ciphertext := encrypt(padText)
	cipherLength := len(ciphertext)
	for true {
		padText = append(padText, 'A')
		ciphertext = encrypt(padText)
		if len(ciphertext) > cipherLength {
			keysize = len(ciphertext) - cipherLength
			hiddenLength = cipherLength - len(padText)
			break
		}
		cipherLength = len(ciphertext)
	}

	// Check that the text is using ECB mode
	padText = make([]byte, 2*keysize)
	for i := range padText {
		padText[i] = 'A'
	}
	ciphertext = encrypt(padText)
	if !sliceEq(ciphertext[0:keysize], ciphertext[keysize:2*keysize]) {
		fmt.Println("WARNING: Not ECB!")
	}

	// Get the hidden string one byte at a time from encrypted padding
	plaintext := make([]byte, 0)
	offset := keysize - (hiddenLength % keysize)
	padding := make([]byte, hiddenLength+offset-1)
	for i := range padding {
		padding[i] = 'A'
	}

	blockStart := len(padding) - keysize
	for i := 0; i < hiddenLength; i++ {
		ciphertext = encrypt(padding)
		encryptedBlock := ciphertext[blockStart : blockStart+keysize]
		for b := 0; b < 256; b++ {
			tmpPadding := append(padding, plaintext...)
			testBlock := encrypt(append(tmpPadding, byte(b)))
			testBlock = testBlock[blockStart : blockStart+keysize]
			if sliceEq(encryptedBlock, testBlock) {
				plaintext = append(plaintext, byte(b))
				padding = padding[1:]
				break
			}
		}
	}

	return plaintext
}

func main() {
	rand.Seed(time.Now().UnixNano())
	key = randomBytes(16)
	fmt.Println(string(decrypt()))
}
