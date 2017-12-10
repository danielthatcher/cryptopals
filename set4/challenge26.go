package main

import (
	"cryptopals/util"
	"fmt"
	"math/rand"
	"strings"
	"time"
)

var key []byte
var iv []byte

func getData(data string) []byte {
	// Strip out metachars
	data = strings.Replace(data, ";", "", -1)
	data = strings.Replace(data, "=", "", -1)

	// Concatenate
	data = fmt.Sprintf("comment1=cooking%%20MCs;userdata=%s;comment2=%%20like%%20a%%20pound%%20of%%20bacon", data)

	// Encrypt and return
	return util.CTRCrypt([]byte(data), key, iv)
}

func processData(data []byte) bool {
	// Decrypt
	data = util.CTRCrypt(data, key, iv)

	// Search for ";admin=true;"
	fmt.Println(string(data))
	return strings.Contains(string(data), ";admin=true;")
}

func attack() {
	// Create padding longer than the rest of the data, so that
	// we're sure we are XORing a known value
	clen := len(getData(""))
	pad := make([]byte, clen+20)
	for i := range pad {
		pad[i] = byte('A')
	}

	target := []byte(";admin=true;")
	ciphertext := getData(string(pad))
	for i := range target {
		ciphertext[clen+i] ^= target[i] ^ byte('A')
	}

	if processData(ciphertext) {
		fmt.Println("Success")
	} else {
		fmt.Println("Failure")
	}
}

func main() {
	rand.Seed(time.Now().UnixNano())
	key = util.RandomBytes(16)
	iv = util.RandomBytes(16)
	attack()
}
