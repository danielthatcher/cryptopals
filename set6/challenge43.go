package main

import (
	"cryptopals/util/dsa"
	"fmt"
)

func main() {
	d := dsa.NewDSA()
	keypair := d.GenerateUserKeypair()
	msg := []byte("DSA?")
	sig := d.SignMessage(msg, keypair)

	if d.VerifySignature(msg, sig, keypair[0]) {
		fmt.Println("Working!")
	} else {
		fmt.Println(":(")
	}
}
