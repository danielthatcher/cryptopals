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

// Server functions
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

// MitM functions
func mitmKey(A big.Int) big.Int {
	echoKey(d.P)
	return d.P
}

func mitmMessage(msg []byte, iv []byte) ([]byte, []byte) {
	// We know that the shared key (pre-hash) is going to be 0
	var s big.Int
	s.SetInt64(0)
	S, _ := d.SharedKey(s, 1)
	fmt.Println("Attacker received: ", string(util.DHDecrypt(msg, S, iv)))
	return echoMessage(msg, iv)
}

// Client
func main() {
	rand.Seed(time.Now().UnixNano())
	d = util.NISTDiffieHellman()

	// Non-MitM vesion
	fmt.Println("Normal operation:")
	a := rand.Int()
	A = d.PublicKey(a)

	echoKey(A)
	S, _ := d.SharedKey(B, a)

	ciphertext, iv := util.DHEncrypt([]byte("This is a testing message"), S)
	ciphertext, iv = echoMessage(ciphertext, iv)
	plaintext := util.DHDecrypt(ciphertext, S, iv)
	fmt.Println("Client received: ", string(plaintext))

	// MitM version
	fmt.Println("")
	fmt.Println("MitM operation:")
	a = rand.Int()
	A = d.PublicKey(a)

	mitmB := mitmKey(A)
	S, _ = d.SharedKey(mitmB, a)

	ciphertext, iv = util.DHEncrypt([]byte("This is a testing message"), S)
	ciphertext, iv = mitmMessage(ciphertext, iv)
	plaintext = util.DHDecrypt(ciphertext, S, iv)
	fmt.Println("Client received: ", string(plaintext))
}
