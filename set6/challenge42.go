package main

import (
	"crypto/sha256"
	"cryptopals/util/rsa"
	"fmt"
	"math/big"
)

func validateSignature(sig []byte, msg []byte, pubkey [2]big.Int) bool {
	// Decrypt signature and extract the hash
	// We assume that sha256 is used to simplify things
	decrypted := rsa.CryptFixed(sig, pubkey, 128)
	fmt.Println(decrypted)
	if decrypted[0] != byte(0) || decrypted[1] != byte(1) {
		return false
	}

	var i int
	for i = 2; decrypted[i] == byte(0xff); i++ {
	}

	if decrypted[i] != byte(0) {
		return false
	}

	i++
	special := []byte("ASN.1")
	for j := range special {
		if decrypted[i+j] != special[j] {
			return false
		}
	}

	i += len(special)
	sigHash := decrypted[i : i+32]

	// Now actually verify the hash
	trueHash := sha256.Sum256(msg)
	for j := range trueHash {
		if trueHash[j] != sigHash[j] {
			return false
		}
	}

	return true
}

func main() {
	pubkey, _ := rsa.GenerateKeypair(512)
	msg := []byte("hi mom")
	hash := sha256.Sum256(msg)

	// Forge the start of the signature
	plainSig := []byte{0, 1, 0xff, 0}
	plainSig = append(plainSig, []byte("ASN.1")...)
	plainSig = append(plainSig, hash[:]...)
	fmt.Println(plainSig)

	// Fill with 0xff until we are at the right length. Then there should be
	// a cube number less than this that has the same starting digits, and can
	// be found using rsa.Root
	for len(plainSig) < 128 {
		plainSig = append(plainSig, byte(0xff))
	}

	var p big.Int
	p.SetBytes(plainSig)
	sigInt := *rsa.Root(3, p)
	sig := sigInt.Bytes()

	if validateSignature(sig, msg, pubkey) {
		fmt.Println("It worked")
	} else {
		fmt.Println(":(")
	}
}
