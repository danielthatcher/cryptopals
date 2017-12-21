package main

import (
	"cryptopals/util"
	"fmt"
	"math/big"
	"math/rand"
	"time"
)

// Store the state of the server basically
type Server struct {
	S []byte
}

// Public info
var d util.DiffieHellman
var A big.Int
var B big.Int
var server Server

func echoKey(A big.Int) big.Int {
	b := rand.Int()
	B = d.PublicKey(b)
	server.S, _ = d.SharedKey(A, b)
	return B
}

func echoMessage(msg []byte, iv []byte) ([]byte, []byte) {
	plaintext := util.DHDecrypt(msg, server.S, iv)
	fmt.Println("Server received: ", string(plaintext))

	ciphertext, iv := util.DHEncrypt(plaintext, server.S)
	return ciphertext, iv
}

func main() {
	rand.Seed(time.Now().UnixNano())
	d = util.NISTDiffieHellman()

	a := rand.Int()
	A = d.PublicKey(a)

	echoKey(A)
	S, _ := d.SharedKey(B, a)

	ciphertext, iv := util.DHEncrypt([]byte("This is a testing message"), S)
	ciphertext, iv = echoMessage(ciphertext, iv)
	plaintext := util.DHDecrypt(ciphertext, S, iv)
	fmt.Println("Client received: ", string(plaintext))
}
