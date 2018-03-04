package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"cryptopals/util"
	"cryptopals/util/rsa"
	"fmt"
	"math/big"
	"math/rand"
	"time"
)

type Bob struct {
	secret    int
	PublicKey *big.Int
	Message   []byte
	DH        *util.DiffieHellman
}

func NewBob(dh *util.DiffieHellman) *Bob {
	rand.Seed(time.Now().UnixNano())
	secret := rand.Int()
	pub := dh.PublicKey(secret)
	m := []byte("crazy flamboyant for the rap enjoyment")
	return &Bob{secret: secret, PublicKey: &pub, Message: m, DH: dh}
}

func (b *Bob) sendKey(h *big.Int) []byte {
	shared, _ := b.DH.SharedKey(*h, b.secret)
	m := hmac.New(sha256.New, shared)
	m.Write(b.Message)
	return m.Sum(nil)
}

func (b *Bob) revealSecret() {
	fmt.Println("Bob's secret:", b.secret)
}

func compBytes(a, b []byte) bool {
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func main() {
	p, _ := new(big.Int).SetString("7199773997391911030609999317773941274322764333428698921736339643928346453700085358802973900485592910475480089726140708102474957429903531369589969318716771", 10)
	g, _ := new(big.Int).SetString("4565356397095740655436854503483826832136106141639563487732438195343690437606117828318042418238184896212352329118608100083187535033402010599512641674644143", 10)

	// j = (p-1) / q = ord(GF(p)) / q
	j, _ := new(big.Int).SetString("30477252323177606811760882179058908038824640750610513771646768011063128035873508507547741559514324673960576895059570", 10)

	// Find all the prime factors of j smaller than 2^16
	fmt.Println("Finding factors...")
	factors := make([]*big.Int, 1)
	factors[0] = big.NewInt(2)

	for i := 3; i < (2 << 16); i += 2 {
		bigi := big.NewInt(int64(i))

		// Check not repeating factor
		y := new(big.Int)
		r := new(big.Int)
		div := false
		for k := 0; k < len(factors) && !div; k++ {
			y.QuoRem(bigi, factors[k], r)
			if r.Cmp(big.NewInt(0)) == 0 {
				div = true
				break
			}
		}

		// Check if factor
		if !div {
			y.QuoRem(j, bigi, r)
			if r.Cmp(big.NewInt(0)) == 0 {
				factors = append(factors, bigi)
			}
		}
	}

	fmt.Println("Found factors:", factors)

	// Bob's keygen
	dh := util.DiffieHellman{P: *p, G: *g}
	bob := NewBob(&dh)

	// For each factor, recover part of the public key
	randGen := rand.New(rand.NewSource(1234))
	bases := make([]*big.Int, 0)
	for _, r := range factors {
		// Find h, and element of order r
		h := big.NewInt(1)
		for h.Cmp(big.NewInt(1)) == 0 {
			h = new(big.Int).Rand(randGen, p)
			pow := new(big.Int).Sub(p, big.NewInt(1))
			pow.Div(pow, r)
			h.Exp(h, pow, p)
		}

		// Get and brute force the MAC
		mac := bob.sendKey(h)
		trials := new(big.Int).SetInt64(1)
		for ; r.Cmp(trials) == 1; trials.Add(trials, big.NewInt(1)) {
			pow := new(big.Int).Exp(h, trials, p)
			data, _ := pow.GobEncode()
			trialKey := sha256.Sum256(data)
			m := hmac.New(sha256.New, trialKey[:16])
			m.Write(bob.Message)
			trialMac := m.Sum(nil)
			if compBytes(trialMac, mac) {
				break
			}
		}

		fmt.Printf("secret = %d mod %d\n", trials, r)
		bases = append(bases, trials)
	}

	bobSecret, err := rsa.CRT(bases, factors)
	if err != nil {
		fmt.Println("CRT failed!")
	}

	fmt.Println("Calculated secret:", bobSecret)
	bob.revealSecret()
}
