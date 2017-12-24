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
	D util.DiffieHellman
}

// Public info
var A big.Int
var B big.Int
var server Server
var mitm Server
var mode int

// Server
func receiveGroup(d util.DiffieHellman) bool {
	server.D = d
	return true
}

func receivePublicKey(key big.Int) big.Int {
	b := rand.Int()
	B = server.D.PublicKey(b)
	server.S, _ = server.D.SharedKey(key, b)
	return B
}

func receiveMessage(msg []byte, iv []byte) ([]byte, []byte) {
	plaintext := util.DHDecrypt(msg, server.S, iv)
	ciphertext, iv := util.DHEncrypt(plaintext, server.S)
	return ciphertext, iv
}

// MitM functions
func mitmReceiveGroup(d util.DiffieHellman) bool {
	if mode == 0 {
		x := big.NewInt(1)
		mitm.D = util.DiffieHellman{P: d.P, G: *x}
		receiveGroup(mitm.D)
	} else if mode == 1 {
		mitm.D = util.DiffieHellman{P: d.P, G: d.P}
		receiveGroup(mitm.D)
	} else if mode == 2 {
		var p big.Int
		p.Sub(&d.P, big.NewInt(1))
		mitm.D = util.DiffieHellman{P: d.P, G: p}
		receiveGroup(mitm.D)
	}

	return true
}

func mitmReceivePublicKey(key big.Int) big.Int {
	// Let the key go through unchanged
	return receivePublicKey(key)
}

func mitmReceiveMessage(msg []byte, iv []byte) ([]byte, []byte) {
	if mode == 0 {
		// We know that B's public key will be 1, so the client will have a shared
		// secret of 1 (pre-hash), and the server will have an unknown shared secret
		x := big.NewInt(1)
		mitm.S, _ = mitm.D.SharedKey(*x, 1)
		plaintext := util.DHDecrypt(msg, mitm.S, iv)
		fmt.Println("MitM received:", string(plaintext))

	} else if mode == 1 {
		// We know that B's public key will be 0, so the client will have a shared
		// sercret of 0 (pre-hash), and the server will have an unknown shared secret
		x := big.NewInt(0)
		mitm.S, _ = mitm.D.SharedKey(*x, 1)
		plaintext := util.DHDecrypt(msg, mitm.S, iv)
		fmt.Println("MitM received:", string(plaintext))
	} else if mode == 2 {
		// We know that B's public key will be +/-1, so the client will have a shared
		// sercret of +/-1 (pre-hash), and the server will have an unknown shared secret
		x := big.NewInt(-1)
		mitm.S, _ = mitm.D.SharedKey(*x, 1)
		plaintext := util.DHDecrypt(msg, mitm.S, iv)
		fmt.Println("MitM received (-1):", string(plaintext))

		x = big.NewInt(1)
		mitm.S, _ = mitm.D.SharedKey(*x, 1)
		plaintext = util.DHDecrypt(msg, mitm.S, iv)
		fmt.Println("MitM received (1):", string(plaintext))
	}
	return receiveMessage(msg, iv)
}

// Client
func main() {
	rand.Seed(time.Now().UnixNano())
	d := util.NISTDiffieHellman()

	// Non-MitM vesion
	fmt.Println("Normal operation:")
	a := rand.Int()
	A = d.PublicKey(a)

	receiveGroup(d)
	B := receivePublicKey(A)
	S, _ := d.SharedKey(B, a)

	ciphertext, iv := util.DHEncrypt([]byte("This is a testing message"), S)
	ciphertext, iv = receiveMessage(ciphertext, iv)
	plaintext := util.DHDecrypt(ciphertext, S, iv)
	fmt.Println("Client received:", string(plaintext))

	for i := 0; i < 3; i++ {
		mode = i

		// MitM version
		fmt.Println("")
		fmt.Printf("MitM operation (mode %d):\n", mode)
		a = rand.Int()
		A = d.PublicKey(a)

		mitmReceiveGroup(d)
		B = mitmReceivePublicKey(A)
		S, _ = d.SharedKey(B, a)

		ciphertext, iv = util.DHEncrypt([]byte("This is a testing message"), S)
		ciphertext, iv = mitmReceiveMessage(ciphertext, iv)
		plaintext = util.DHDecrypt(ciphertext, S, iv)
	}

}
