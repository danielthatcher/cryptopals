package dsa

import (
	"crypto/rand"
	"crypto/sha256"
	"cryptopals/util/rsa"
	"fmt"
	"hash"
	"math/big"
)

type DSA struct {
	P, Q, G big.Int
	Hash    func() hash.Hash
}

func NewDSA() DSA {
	var p, q, g big.Int
	p.SetString("800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1", 16)
	q.SetString("f4f47f05794b256174bba6e9b396a7707e563c5b", 16)
	g.SetString("5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291", 16)

	return DSA{P: p, Q: q, G: g, Hash: sha256.New}
}

func (d *DSA) GenerateUserKeypair() [2]big.Int {
	var y big.Int
	x, _ := rand.Int(rand.Reader, &d.Q)
	y.Exp(&d.G, x, &d.P)

	return [2]big.Int{y, *x}
}

func (d *DSA) SignMessage(msg []byte, keypair [2]big.Int) [2]big.Int {
	var r, k, s big.Int
	s.SetInt64(0)
	r.SetInt64(0)

	// We have to start again if r or s is 0
	for r.Cmp(big.NewInt(0)) == 0 || s.Cmp(big.NewInt(0)) == 0 {
		kptr, _ := rand.Int(rand.Reader, &d.Q)
		k = *kptr
		kinv := rsa.InvMod(k, d.Q)
		r.Exp(&d.G, &k, &d.P)
		r.Mod(&r, &d.Q)

		var h big.Int
		hashFunc := d.Hash()
		hashFunc.Write(msg)
		h.SetString(fmt.Sprintf("%x", hashFunc.Sum(nil)), 16)

		s.Mul(&keypair[1], &r)
		s.Mod(&s, &d.Q)
		s.Add(&s, &h)
		s.Mod(&s, &d.Q)
		s.Mul(&s, &kinv)
		s.Mod(&s, &d.Q)
	}

	return [2]big.Int{r, s}
}

func (d *DSA) SignMessageWithK(msg []byte, keypair [2]big.Int, k big.Int) [2]big.Int {
	var r, s big.Int
	s.SetInt64(0)
	r.SetInt64(0)

	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovered in signing")
		}
	}()
	kinv := rsa.InvMod(k, d.Q)
	r.Exp(&d.G, &k, &d.P)
	r.Mod(&r, &d.Q)

	var h big.Int
	hashFunc := d.Hash()
	hashFunc.Write(msg)
	h.SetString(fmt.Sprintf("%x", hashFunc.Sum(nil)), 16)

	s.Mul(&keypair[1], &r)
	s.Mod(&s, &d.Q)
	s.Add(&s, &h)
	s.Mod(&s, &d.Q)
	s.Mul(&s, &kinv)
	s.Mod(&s, &d.Q)

	return [2]big.Int{r, s}
}

func (d *DSA) VerifySignature(msg []byte, signature [2]big.Int, pubkey big.Int) bool {
	// Require that 0 < r,s < q
	if signature[0].Cmp(big.NewInt(0)) == 0 || signature[1].Cmp(big.NewInt(0)) == 0 {
		return false
	}
	if signature[0].Cmp(&d.Q) != -1 || signature[1].Cmp(&d.Q) != -1 {
		return false
	}

	var w, u1, u2, v1, v2, v big.Int
	w = rsa.InvMod(signature[1], d.Q)

	h := d.Hash()
	h.Write(msg)
	u1.SetString(fmt.Sprintf("%x", h.Sum(nil)), 16)
	u1.Mul(&u1, &w)
	u1.Mod(&u1, &d.Q)

	u2.Mul(&signature[0], &w)
	u2.Mod(&u2, &d.Q)

	v1.Exp(&d.G, &u1, &d.P)
	v2.Exp(&pubkey, &u2, &d.P)
	v.Mul(&v1, &v2)
	v.Mod(&v, &d.P)
	v.Mod(&v, &d.Q)

	// v == r implies a valid signature
	return v.Cmp(&signature[0]) == 0
}
