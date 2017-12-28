package main

import (
	"cryptopals/util/dsa"
	"fmt"
	"math/big"
)

func main() {
	d := dsa.NewDSA()

	// Client supplying params
	// Note that since I took the implementaiton from wikipedia, I reject r=0 for a signature,
	// so g=0 will not work. However, this will cause any message signed with any key (which will
	// give r=0) to be accepted as a signature for any message (since v=0 in the calcs)

	d.G.Set(big.NewInt(1))
	keypair := d.GenerateUserKeypair()

	// For g = 1 mod q, using r = s = pubkey is simplest
	msg1 := []byte("Hello, world")
	msg2 := []byte("Goodbye, world")
	r := keypair[0]
	s := keypair[0]
	signature := [2]big.Int{r, s}

	if d.VerifySignature(msg1, signature, keypair[0]) {
		fmt.Println("Success for message 1")
	}

	if d.VerifySignature(msg2, signature, keypair[0]) {
		fmt.Println("Success for message 2")
	}
}
