package main

import (
	"crypto/sha1"
	"cryptopals/util/rsa"
	"fmt"
	"math/big"
)

type Server struct {
	hashlist [][20]byte
	Pubkey   [2]big.Int
	privkey  [2]big.Int
}

func NewServer() Server {
	pub, priv := rsa.GenerateKeypair(256)
	return Server{Pubkey: pub, privkey: priv, hashlist: make([][20]byte, 0)}
}

func (s *Server) Encrypt(msg []byte) []byte {
	return rsa.Crypt(msg, s.Pubkey)
}

func (s *Server) Decrypt(ciphertext []byte) []byte {
	// Check that this message hasn't been decrypted
	msgHash := sha1.Sum(ciphertext)
	for i := range s.hashlist {
		equal := true
		for j := range msgHash {
			if msgHash[j] != s.hashlist[i][j] {
				equal = false
				break
			}
		}

		if equal {
			fmt.Errorf("Already decrypted!")
			return make([]byte, 0)
		}
	}

	s.hashlist = append(s.hashlist, msgHash)

	return rsa.Crypt(ciphertext, s.privkey)
}

func main() {
	server := NewServer()

	// Victim
	msg := "Let's keep this secret"
	ciphertext := server.Encrypt([]byte(msg))

	// Now the attacker with access to ciphertext and public key
	var c, s, p big.Int
	s.Sub(&server.Pubkey[1], big.NewInt(1)) // Should be coprime to N
	sinv := rsa.InvMod(s, server.Pubkey[1])
	c.SetBytes(ciphertext)
	s = rsa.CryptInt(s, server.Pubkey)

	c.Mul(&c, &s)
	c.Mod(&c, &server.Pubkey[1])
	modCiphertext := c.Bytes()
	modMsg := server.Decrypt(modCiphertext)
	p.SetBytes(modMsg)
	p.Mul(&p, &sinv)
	p.Mod(&p, &server.Pubkey[1])
	fmt.Println(string(p.Bytes()))
}
