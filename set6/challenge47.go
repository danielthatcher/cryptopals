package main

import (
	"cryptopals/util/rsa"
	"fmt"
	"math/big"
)

type Server struct {
	Pubkey  [2]big.Int
	privkey [2]big.Int
}

// Used to store values used by the attacker functions
type Attacker struct {
	B          *big.Int
	S          *big.Int
	M          [][2]*big.Int
	I          int
	Ciphertext []byte
	Server     Server
}

var byteLen int

func NewServer() Server {
	s := Server{}
	s.Pubkey, s.privkey = rsa.GenerateKeypair(128)
	return s
}

func (s *Server) Encrypt() []byte {
	plaintext := PKCSPad([]byte("kick it, CC"))
	fmt.Println("Message: ", new(big.Int).SetBytes(plaintext))
	return rsa.CryptFixed(plaintext, s.Pubkey, byteLen)
}

func (s *Server) PKCSOracle(ciphertext []byte) bool {
	plaintext := rsa.CryptFixed(ciphertext, s.privkey, byteLen)
	return (plaintext[0] == byte(0) && plaintext[1] == byte(2))
}

func PKCSPad(msg []byte) []byte {
	for i := len(msg); i < byteLen-2; i++ {
		msg = append([]byte{0}, msg...)
	}

	msg = append([]byte{2}, msg...)
	msg = append([]byte{0}, msg...)
	return msg
}

// Step 1
func NewAttacker() Attacker {
	a := Attacker{}

	a.B = new(big.Int).Sub(big.NewInt(int64(byteLen)), big.NewInt(2))
	a.B.Mul(a.B, big.NewInt(8))
	a.B.Exp(big.NewInt(2), a.B, nil)

	a.S = new(big.Int).SetInt64(1) // Assume the ciphertext is conformant
	a.M = [][2]*big.Int{a.InitialRange()}
	a.I = 1

	return a
}

func (a *Attacker) InitialRange() [2]*big.Int {
	x := new(big.Int).Mul(a.B, big.NewInt(2))
	y := new(big.Int).Mul(a.B, big.NewInt(3))
	y.Sub(y, big.NewInt(1))

	return [2]*big.Int{x, y}
}

// Step 2a
func (a *Attacker) InitialSearch() *big.Int {
	s := new(big.Int).Mul(big.NewInt(3), a.B)
	s.Div(&a.Server.Pubkey[1], s)
	ret := new(big.Int).SetInt64(0)

	ciphertext := new(big.Int).SetInt64(0)
	c := new(big.Int).SetBytes(a.Ciphertext)
	for ; ret.Cmp(big.NewInt(0)) == 0; s.Add(s, big.NewInt(1)) {
		sCrypt := new(big.Int).Exp(s, &a.Server.Pubkey[0], &a.Server.Pubkey[1])
		ciphertext.Mul(c, sCrypt)
		ciphertext.Mod(ciphertext, &a.Server.Pubkey[1])
		if a.Server.PKCSOracle(ciphertext.Bytes()) {
			ret.Set(s)
			break
		}
	}

	return ret
}

// Step 2b
func (a *Attacker) ContinueSearch() *big.Int {
	s := new(big.Int).Set(a.S)
	s.Add(s, big.NewInt(1))

	ciphertext := new(big.Int).SetInt64(0)
	c := new(big.Int).SetBytes(a.Ciphertext)
	for ; !a.Server.PKCSOracle(ciphertext.Bytes()); s.Add(s, big.NewInt(1)) {
		sCrypt := new(big.Int).Exp(s, &a.Server.Pubkey[0], &a.Server.Pubkey[1])
		ciphertext.Mul(c, sCrypt)
		sCrypt.Mod(sCrypt, &a.Server.Pubkey[1])
	}

	return s
}

// Step 2c
func (a *Attacker) OneIntervalSearch() *big.Int {
	twoB := new(big.Int).Mul(big.NewInt(2), a.B)
	threeB := new(big.Int).Mul(big.NewInt(3), a.B)
	n := &a.Server.Pubkey[1]
	Ma, Mb := a.M[0][0], a.M[0][1]

	r := new(big.Int).Mul(Mb, a.S)
	r.Sub(r, twoB)
	r.Mul(r, big.NewInt(2))
	r.Div(r, n)

	newS := new(big.Int).SetInt64(0)
	for ; newS.Cmp(big.NewInt(0)) == 0; r.Add(r, big.NewInt(1)) {
		sLower := new(big.Int).Mul(r, n)
		sLower.Add(sLower, twoB)
		sLower.Div(sLower, Mb)

		sUpper := new(big.Int).Mul(r, n)
		sUpper.Add(sUpper, threeB)
		sUpper.Div(sUpper, Ma)
		sUpper.Add(sUpper, big.NewInt(1))

		s := new(big.Int)
		c := new(big.Int).SetBytes(a.Ciphertext)
		for s.Set(sLower); s.Cmp(sUpper) == -1; s.Add(s, big.NewInt(1)) {
			sCrypt := new(big.Int).Exp(s, &a.Server.Pubkey[0], &a.Server.Pubkey[1])
			ciphertext := new(big.Int).Mul(c, sCrypt)
			ciphertext.Mod(ciphertext, &a.Server.Pubkey[1])

			if a.Server.PKCSOracle(ciphertext.Bytes()) {
				newS.Set(s)
				break
			}
		}
	}

	return newS
}

// Step 3
func (a *Attacker) NarrowSolutions() [][2]*big.Int {
	twoB := new(big.Int).Mul(big.NewInt(2), a.B)
	threeB := new(big.Int).Mul(big.NewInt(3), a.B)
	n := &a.Server.Pubkey[1]

	newM := make([][2]*big.Int, 0)

	for i := range a.M {
		Ma, Mb := a.M[i][0], a.M[i][1]
		rLower, rUpper := a.rBounds(Ma, Mb, a.S)
		var r *big.Int
		for r = new(big.Int).Set(rLower); r.Cmp(rUpper) < 1; r.Add(r, big.NewInt(1)) {
			lowerCmp := new(big.Int).Mul(r, n)
			lowerCmp.Add(lowerCmp, twoB)
			lowerCmp.Div(lowerCmp, a.S)

			upperCmp := new(big.Int).Mul(r, n)
			upperCmp.Add(upperCmp, threeB)
			upperCmp.Sub(upperCmp, big.NewInt(1))
			upperCmp.Div(upperCmp, a.S)
			//upperCmp.Sub(upperCmp, big.NewInt(1))

			if lowerCmp.Cmp(Mb) == 1 {
				fmt.Println("lowerCmp too big!")
			}
			if upperCmp.Cmp(Ma) == -1 {
				fmt.Println("upperCmp too small!")
			}
			if lowerCmp.Cmp(upperCmp) == 1 {
				fmt.Println("lowerCmp larger than upperCmp!")
			}

			if Ma.Cmp(lowerCmp) == 1 {
				lowerCmp.Set(Ma)
			}
			if Mb.Cmp(upperCmp) == -1 {
				upperCmp.Set(Mb)
			}

			M := [2]*big.Int{lowerCmp, upperCmp}
			unique := true
			for j := range newM {
				if newM[j][0].Cmp(M[0]) == 0 && newM[j][1].Cmp(M[1]) == 0 {
					unique = false
					break
				}
			}
			if unique {
				newM = append(newM, M)
			}
		}
	}

	return newM
}

func (a *Attacker) rBounds(Ma, Mb, s *big.Int) (lower *big.Int, upper *big.Int) {
	twoB := new(big.Int).Mul(big.NewInt(2), a.B)
	threeB := new(big.Int).Mul(big.NewInt(3), a.B)
	n := &a.Server.Pubkey[1]

	lower = new(big.Int).Mul(Ma, s)
	lower.Sub(lower, threeB)
	lower.Add(lower, big.NewInt(1))
	lower.Div(lower, n)
	lower.Add(lower, big.NewInt(1))

	upper = new(big.Int).Mul(Mb, s)
	upper.Sub(upper, twoB)
	upper.Div(upper, n)

	return
}

func main() {
	fmt.Println("Generating keypair...")
	server := NewServer()
	byteLen = len(server.Pubkey[1].Bytes())

	attacker := NewAttacker()
	attacker.Server = server
	attacker.Ciphertext = server.Encrypt()
	fmt.Println("n:", &attacker.Server.Pubkey[1])
	fmt.Println("Initial M:", attacker.M)

	fmt.Println("Starting attack...")
	for true {
		if attacker.I == 1 {
			fmt.Println("Running step 2a...")
			attacker.S = attacker.InitialSearch()
		} else if len(attacker.M) > 1 {
			fmt.Println("Running step 2b...")
			attacker.S = attacker.ContinueSearch()
		} else if len(attacker.M) == 1 {
			fmt.Println("Running step 2c...")
			attacker.S = attacker.OneIntervalSearch()
		} else {
			panic("Unexpected condition!")
		}

		attacker.M = attacker.NarrowSolutions()
		fmt.Println("M at iteration", attacker.I, ":", attacker.M)
		if len(attacker.M) == 1 && attacker.M[0][0].Cmp(new(big.Int).Sub(attacker.M[0][1], big.NewInt(1))) == 0 {
			break
		}
		attacker.I++
	}

	fmt.Println("Decrypted text:")
	fmt.Println(string(attacker.M[0][1].Bytes()))
}
