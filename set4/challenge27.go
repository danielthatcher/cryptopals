package main

import (
	"crypto/aes"
	"crypto/cipher"
	"cryptopals/util"
	"fmt"
	"math/rand"
	"strings"
	"time"
)

var key []byte
var iv []byte

func getData(data string) ([]byte, string) {
	// Strip out metachars
	data = strings.Replace(data, ";", "", -1)
	data = strings.Replace(data, "=", "", -1)

	// Concatenate
	data = fmt.Sprintf("comment1=cooking%%20MCs;userdata=%s;comment2=%%20like%%20a%%20pound%%20of%%20bacon", data)

	// Check for high ascii
	databytes := []byte(data)
	for i := range databytes {
		if databytes[i] > 127 {
			return nil, data
		}
	}

	// Encrypt and return
	dataBytes := util.Pad([]byte(data), 16)
	ret := make([]byte, len(dataBytes))
	block, _ := aes.NewCipher(key)
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ret, dataBytes)

	return ret, ""
}

func processData(data []byte) (bool, []byte) {
	// Decrypt
	block, _ := aes.NewCipher(key)
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(data, data)

	// Check for high ASCII
	for i := range data {
		if data[i] > 127 {
			return false, data
		}
	}

	// Search for ";admin=true;"
	fmt.Println(string(data))
	return strings.Contains(string(data), ";admin=true;"), nil
}

func attack() {
	// Encrypt at least 3 bytes long
	pad := make([]byte, 32)
	for i := range pad {
		pad[i] = byte('A')
	}

	crypted, _ := getData(string(pad))

	// Zero out the second block
	keysize := 16
	for i := keysize; i < 2*keysize; i++ {
		crypted[i] = byte(0)
	}

	// Copy the first block to the third
	for i := 0; i < keysize; i++ {
		crypted[(2*keysize)+i] = crypted[i]
	}

	_, data := processData(crypted)
	if data == nil {
		fmt.Println("No error generated on decryption")
		return
	}

	key := util.SliceXOR(data[:keysize], data[2*keysize:3*keysize])
	fmt.Println(key)
}

func main() {
	rand.Seed(time.Now().UnixNano())
	key = util.RandomBytes(16)
	iv = key
	fmt.Println(key)
	attack()
}
