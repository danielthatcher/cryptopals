package main

import (
	"cryptopals/util/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
)

var pubkey [2]big.Int
var privkey [2]big.Int

// Return true if the decrypted text is even
func parityOracle(ciphertext big.Int) bool {
	plaintext := rsa.CryptInt(ciphertext, privkey)
	return plaintext.Bit(0) == 0
}

func encrypt() []byte {
	plaintext, _ := base64.StdEncoding.DecodeString("VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==")

	var p big.Int
	p.SetBytes(plaintext)
	fmt.Println(p.String())

	ciphertext := rsa.Crypt(plaintext, pubkey)
	return ciphertext
}

func main() {
	pubkey, privkey = rsa.GenerateKeypair(1024)
	ciphertext := encrypt()

	var bound [2]big.Int
	var c big.Int
	bound[0] = *big.NewInt(0)
	bound[1].Set(&pubkey[1])
	c.SetBytes(ciphertext)

	multiplier := rsa.CryptInt(*big.NewInt(2), pubkey)
	for bound[0].Cmp(&bound[1]) == -1 {
		c.Mul(&c, &multiplier)
		c.Mod(&c, &pubkey[1])

		var midpoint big.Int
		midpoint.Add(&bound[1], &bound[0])
		midpoint.Div(&midpoint, big.NewInt(2))
		if midpoint.Cmp(&bound[1]) == 0 || midpoint.Cmp(&bound[0]) == 0 {
			break
		}

		if parityOracle(c) {
			bound[1].Add(&midpoint, big.NewInt(1))
		} else {
			bound[0].Set(&midpoint)
		}

		fmt.Println(string(bound[1].Bytes()))
	}

	// Just to get the true int out again
	encrypt()

	fmt.Println(bound[0].String())
	fmt.Println(bound[0].Bytes())
	fmt.Println(string(bound[0].Bytes()))
}
