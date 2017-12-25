package rsa

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// The joys of Euclid's algorithm
// https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm#Modular_integers
func InvMod(a big.Int, n big.Int) big.Int {
	t := *big.NewInt(0)
	newt := *big.NewInt(1)
	var r, newr big.Int
	r.Set(&n)
	newr.Set(&a)

	for newr.Cmp(big.NewInt(0)) != 0 {
		var quotient big.Int
		quotient.Div(&r, &newr)

		var oldt, oldr big.Int
		oldt.Set(&t)
		oldr.Set(&r)

		t.Set(&newt)
		r.Set(&newr)

		newt.Mul(&quotient, &newt)
		newt.Sub(&oldt, &newt)
		newr.Mul(&quotient, &newr)
		newr.Sub(&oldr, &newr)
	}

	if r.Cmp(big.NewInt(1)) == 1 {
		panic("a is not invertible")
	}

	t.Mod(&t, &n)

	return t
}

func GenerateKeypair(bits int) (pubkey [2]big.Int, privkey [2]big.Int) {
	var n, totient big.Int
	var x big.Int
	var p, q *big.Int
	e := *big.NewInt(3)
	totient.SetInt64(3)

	// We need to loop until e and the totient are coprime
	for x.Mod(&totient, &e).Cmp(big.NewInt(0)) == 0 {
		// Two random primes
		p, _ = rand.Prime(rand.Reader, bits)
		q, _ = rand.Prime(rand.Reader, bits)

		// n and totient
		n.Mul(p, q)
		p.Sub(p, big.NewInt(1))
		q.Sub(q, big.NewInt(1))
		totient.Mul(p, q)
	}

	// Keygen
	d := InvMod(e, totient)
	pubkey = [2]big.Int{e, n}
	privkey = [2]big.Int{d, n}

	return
}

func Crypt(msg []byte, key [2]big.Int) []byte {
	var msgi big.Int
	msgi.SetBytes(msg)
	msgi.Exp(&msgi, &key[0], &key[1])
	return msgi.Bytes()
}

func CryptFixed(msg []byte, key [2]big.Int, length int) []byte {
	var msgi big.Int
	msgi.SetBytes(msg)
	msgi.Exp(&msgi, &key[0], &key[1])
	b := msgi.Bytes()
	if length < len(b) {
		panic("Length too short")
	}

	for len(b) < length {
		b = append([]byte{0}, b...)
	}

	return b
}

func CryptInt(msg big.Int, key [2]big.Int) big.Int {
	return *msg.Exp(&msg, &key[0], &key[1])
}

// https://rosettacode.org/wiki/Chinese_remainder_theorem#Go
func CRT(a []*big.Int, n []*big.Int) (*big.Int, error) {
	p := new(big.Int).Set(n[0])
	for _, n1 := range n[1:] {
		p.Mul(p, n1)
	}
	var x, q, s, z big.Int
	for i, n1 := range n {
		q.Div(p, n1)
		z.GCD(nil, &s, n1, &q)
		if z.Cmp(big.NewInt(1)) != 0 {
			return nil, fmt.Errorf("%d not coprime", n1)
		}
		x.Add(&x, s.Mul(a[i], s.Mul(&s, &q)))
	}
	return x.Mod(&x, p), nil
}

// https://rosettacode.org/wiki/Integer_roots#big.Int
func Root(N int, xx big.Int) *big.Int {
	var x, deltar big.Int
	nn := big.NewInt(int64(N))
	for r := big.NewInt(1); ; {
		x.Set(&xx)
		for i := 1; i < N; i++ {
			x.Quo(&x, r)
		}
		// big.Quo performs Go-like truncated division and would allow direct
		// translation of the int-based solution, but package big also provides
		// Div which performs Euclidean rather than truncated division.
		// This gives the desired result for negative x so the int-based
		// correction is no longer needed and the code here can more directly
		// follow the Wikipedia article.
		deltar.Div(x.Sub(&x, r), nn)
		if len(deltar.Bits()) == 0 {
			return r
		}
		r.Add(r, &deltar)
	}
}
