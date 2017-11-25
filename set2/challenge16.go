package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"math/rand"
	"strings"
	"time"
)

var key []byte
var iv []byte

func pad(text []byte, blocksize int) []byte {
	padAmount := blocksize - (len(text) % blocksize)
	ret := text
	for i := 0; i < padAmount; i++ {
		ret = append(ret, byte(0x04))
	}
	return ret
}

func randomBytes(l int) []byte {
	r := make([]byte, l)
	for i := range r {
		r[i] = byte(rand.Int() % 256)
	}

	return r
}

func getData(data string) []byte {
	// Strip out metachars
	data = strings.Replace(data, ";", "", -1)
	data = strings.Replace(data, "=", "", -1)

	// Concatenate
	data = fmt.Sprintf("comment1=cooking%%20MCs;userdata=%s;comment2=%%20like%%20a%%20pound%%20of%%20bacon", data)

	// Encrypt and return
	dataBytes := pad([]byte(data), 16)
	ret := make([]byte, len(dataBytes))
	block, _ := aes.NewCipher(key)
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ret, dataBytes)

	return ret
}

func processData(data []byte) bool {
	// Decrypt
	block, _ := aes.NewCipher(key)
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(data, data)

	// Search for ";admin=true;"
	fmt.Println(string(data))
	return strings.Contains(string(data), ";admin=true;")
}

func attack() {
	// Input is placed somewhere amongst other text, so make input longer than
	// other text so we know we're targeting out input
	datalength := len(getData(""))
	input := make([]byte, datalength*4)
	for i := range input {
		input[i] = byte(0x00)
	}

	// Exploit the XOR process of the CBC decrypt to modify our input
	data := getData(string(input))
	offset := datalength * 2
	finalStr := []byte(";admin=true;")
	for i := range finalStr {
		data[offset+i] = data[offset+i] ^ finalStr[i]
	}

	// Go!
	if processData(data) {
		fmt.Println("Success!")
	} else {
		fmt.Println("Uh Oh!")
	}
}

func main() {
	rand.Seed(time.Now().UnixNano())
	key = randomBytes(16)
	iv = randomBytes(16)
	attack()
}
