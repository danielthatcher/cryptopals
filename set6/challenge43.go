package main

import (
	"crypto/sha1"
	"cryptopals/util/dsa"
	"cryptopals/util/rsa"
	"fmt"
	"math/big"
)

func recoverPrivkey(d *dsa.DSA, k *big.Int, signature [2]big.Int, msgHash *big.Int) (privkey *big.Int) {
	privkey = big.NewInt(0) // Save a null pointer dereference
	privkey.Mul(&signature[1], k)
	privkey.Sub(privkey, msgHash)
	privkey.Mod(privkey, &d.Q)

	rinv := rsa.InvMod(signature[0], d.Q)
	privkey.Mul(privkey, &rinv)
	privkey.Mod(privkey, &d.Q)

	return
}

func main() {
	d := dsa.NewDSA()
	d.Hash = sha1.New
	msg := []byte(`For those that envy a MC it can be hazardous to your health
So be friendly, a matter of life and death, just like a etch-a-sketch
`)

	// Test with a tmp keypair
	tmpKeypair := d.GenerateUserKeypair()
	tmpSignature := d.SignMessage(msg, tmpKeypair)
	fmt.Println(tmpSignature)
	if d.VerifySignature(msg, tmpSignature, tmpKeypair[0]) {
		fmt.Println("Test successful")
	} else {
		fmt.Println("Test failed")
	}

	if fmt.Sprintf("%x", sha1.Sum(msg)) != "d2d0714f014a9784047eaeccf956520045c45265" {
		fmt.Errorf("Incorrect SHA1 sum:\n%x\n", sha1.Sum(msg))
	}

	var msgHash big.Int
	msgHash.SetString("d2d0714f014a9784047eaeccf956520045c45265", 16)

	var signature [2]big.Int
	signature[0].SetString("548099063082341131477253921760299949438196259240", 10)
	signature[1].SetString("857042759984254168557880549501802188789837994940", 10)

	var keypair [2]big.Int
	keypair[0].SetString("84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07bbb283e6633451e535c45513b2d33c99ea17", 16)

	// Verify the signature so that our DSA implementation matches
	if !d.VerifySignature(msg, signature, keypair[0]) {
		fmt.Println("Signature not valid!")
	} else {
		fmt.Println("Signature valid. Continuing...")
	}

	var bigk big.Int
	for k := int64(0); k < (1 << 16); k++ {
		bigk.SetInt64(k)
		keypair[1].Set(recoverPrivkey(&d, &bigk, signature, &msgHash))

		testSig := d.SignMessageWithK(msg, keypair, bigk)
		if testSig[0].Cmp(&signature[0]) == 0 {
			fmt.Println("SUCCESS")
			fmt.Println("k:", k)
			fmt.Printf("Private Key: 0x%x\n", &keypair[1])
			break
		}
	}
}
