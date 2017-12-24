package main

import (
	"cryptopals/util/rsa"
	"fmt"
	"math/big"
)

func main() {
	// Generate 3 keypairs, and encrypt a plaintext under them
	plaintext := "Testing 1,2...Testing 1,2"
	pubkeys := make([][2]big.Int, 3)
	ciphertexts := make([][]byte, 3)
	for i := range pubkeys {
		pubkeys[i], _ = rsa.GenerateKeypair(256)
		ciphertexts[i] = rsa.Crypt([]byte(plaintext), pubkeys[i])
	}

	// Use the CRT
	ciphertextInts := make([]*big.Int, 3)
	exponents := make([]*big.Int, 3)
	for i := range ciphertextInts {
		var c big.Int
		c.SetBytes(ciphertexts[i])
		ciphertextInts[i] = &c
		exponents[i] = &pubkeys[i][1]
	}
	x, _ := rsa.CRT(ciphertextInts, exponents)
	x = rsa.Root(3, *x)
	fmt.Println(string(x.Bytes()))
}
