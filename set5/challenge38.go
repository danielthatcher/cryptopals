package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"cryptopals/util"
	"cryptopals/util/srp"
	"fmt"
	"math/big"
	"math/rand"
	"time"
)

// Also combine the user object
type Server struct {
	email    string
	x        big.Int
	verifier big.Int
	salt     int64
	Group    srp.Group
	key      []byte
}

type MitM struct {
	Group srp.Group
	A     big.Int
}

// Just use functions rather than making a library for this one since it'simple
// Server
func NewServer() Server {
	group := srp.NewGroup()
	return Server{Group: group}
}

func (s *Server) Register(email string, password string) {
	s.email = email
	s.salt = rand.Int63()
	xH := sha256.Sum256([]byte(fmt.Sprintf("%d%s", s.salt, password)))
	s.x.SetBytes(xH[:])
	s.verifier.Exp(&s.Group.G, &s.x, &s.Group.N)
}

func (s *Server) Login(email string, A big.Int) (big.Int, int64, big.Int) {
	if s.email != email {
		panic("Invalid email supplied")
	}

	// Generate the pubkey
	b := rand.Int63()
	var B big.Int
	B.Exp(&s.Group.G, big.NewInt(b), &s.Group.N)

	// u is now just a random 128 bit number
	var u big.Int
	u.SetBytes(util.RandomBytes(16))

	// Derive the shared secret
	var S big.Int
	S.Exp(&s.verifier, &u, &s.Group.N)
	S.Mul(&S, &A)
	S.Mod(&S, &s.Group.N)
	S.Exp(&S, big.NewInt(b), &s.Group.N)
	K := sha256.Sum256([]byte(S.String()))
	s.key = K[:]

	return B, s.salt, u
}

func (s *Server) ValidateHMAC(auth []byte) bool {
	h := hmac.New(sha256.New, s.key)
	trueHMAC := h.Sum([]byte(string(s.salt)))
	return hmac.Equal(auth, trueHMAC)
}

//MitM
func (m *MitM) MitMLogin(email string, A big.Int) (big.Int, int64, big.Int) {
	// We just need to return known values really
	// Making u=1 will make calculations easier, as will b=1 (i.e B=G=2)
	m.A = A
	m.Group = srp.NewGroup()
	return m.Group.G, int64(0), *big.NewInt(1)
}

func (m *MitM) MitMValidation(auth []byte) bool {
	// Pretend we're doing a dictionary attack...
	pwlist := []string{"test", "notthepassword", "password", "1234"}
	for _, pw := range pwlist {
		// Calculate a verifier
		xH := sha256.Sum256([]byte(fmt.Sprintf("0%s", pw)))
		var x big.Int
		x.SetBytes(xH[:])
		var verifier big.Int
		verifier.Exp(&m.Group.G, &x, &m.Group.N)

		// Using u = b = 1
		var S big.Int
		S.Mul(&m.A, &verifier)
		S.Mod(&S, &m.Group.N)
		K := sha256.Sum256([]byte(S.String()))
		key := K[:]

		// If the key is a valid key, we have a valid pw
		h := hmac.New(sha256.New, key)

		// For some reason, []byte("0") != []byte(string(0))
		hmacGuess := h.Sum([]byte(string(0)))

		// hmac.Equal is not the quickest, but doesn't matter here
		if hmac.Equal(hmacGuess, auth) {
			fmt.Println("Found password:", pw)
			break
		}
	}

	// Don't alert the client
	return true
}

// Client
func main() {
	// Initial setup
	rand.Seed(time.Now().UnixNano())
	server := NewServer()
	email := "test@mail.com"
	password := "password"
	server.Register(email, password)

	//Normal operation
	a := rand.Int63()
	var A big.Int
	A.Exp(&server.Group.G, big.NewInt(a), &server.Group.N)
	B, salt, u := server.Login(email, A)

	xH := sha256.Sum256([]byte(fmt.Sprintf("%d%s", salt, password)))
	var x big.Int
	x.SetBytes(xH[:])
	var S big.Int
	S.Mul(&u, &x)
	S.Mod(&S, &server.Group.N)
	S.Add(&S, big.NewInt(a))
	S.Mod(&S, &server.Group.N)
	S.Exp(&B, &S, &server.Group.N)
	K := sha256.Sum256([]byte(S.String()))
	key := K[:]

	h := hmac.New(sha256.New, key)
	auth := h.Sum([]byte(string(salt)))

	if server.ValidateHMAC(auth) {
		fmt.Println("Normal operation working")
	} else {
		fmt.Println("Something went wrong...")
	}

	// MitM operation
	var mitm MitM
	a = rand.Int63()
	A.Exp(&server.Group.G, big.NewInt(a), &server.Group.N)
	B, salt, u = mitm.MitMLogin(email, A)

	xH = sha256.Sum256([]byte(fmt.Sprintf("%d%s", salt, password)))
	x.SetBytes(xH[:])
	S.Mul(&u, &x)
	S.Mod(&S, &server.Group.N)
	S.Add(&S, big.NewInt(a))
	S.Mod(&S, &server.Group.N)
	S.Exp(&B, &S, &server.Group.N)
	K = sha256.Sum256([]byte(S.String()))
	key = K[:]

	h = hmac.New(sha256.New, key)
	auth = h.Sum([]byte(string(salt)))
	mitm.MitMValidation(auth)
}
