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

	// Can tell the k reuse through the signatures with the same r
	// I have manually taken them from the file
	s1 := big.NewInt(0)
	s2 := big.NewInt(0)
	msg1 := big.NewInt(0)
	msg2 := big.NewInt(0)

	s1.SetString("1267396447369736888040262262183731677867615804316", 10)
	s2.SetString("1021643638653719618255840562522049391608552714967", 10)
	msg1.SetString("a4db3de27e2db3e5ef085ced2bced91b82e0df19", 16)
	msg2.SetString("d22804c4899b522b23eda34d2137cd8cc22b9ce8", 16)

	numerator := big.NewInt(0)
	denominator := big.NewInt(0)
	k := big.NewInt(0)

	numerator.Sub(msg1, msg2)
	denominator.Sub(s1, s2)
	x := rsa.InvMod(*denominator, d.Q)
	k.Mul(numerator, &x)
	k.Mod(k, &d.Q)

	var signature [2]big.Int
	signature[0].SetString("1105520928110492191417703162650245113664610474875", 10)
	signature[1].Set(s1)
	privkey := recoverPrivkey(&d, k, signature, msg1)

	privkeyHash := sha1.Sum([]byte(fmt.Sprintf("%x", privkey)))
	if fmt.Sprintf("%x", privkeyHash[:]) == "ca8f6f7c66fa362d40760d135b763eb8527d3d52" {
		fmt.Println("SUCCESS")
	}
}
