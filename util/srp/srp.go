package srp

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"math/big"
	"math/rand"
)

type Server struct {
	Group Group
	user  User  // Just one for simplicity
	salt  int64 // Really should be part of user, but can't be bothered to change
	k     [32]byte
}

type User struct {
	email    string
	verifier big.Int
}

type Group struct {
	N big.Int
	G big.Int
	K big.Int
}

func (g *Group) GenerateClientKey(a int64) big.Int {
	var x big.Int
	x.Exp(&g.G, big.NewInt(a), &g.N)
	return x
}

func ComputeMixed(A big.Int, B big.Int) big.Int {
	combined := fmt.Sprintf("%s%s", A.String(), B.String())
	var x big.Int
	data := sha256.Sum256([]byte(combined))
	x.SetBytes(data[:])
	return x
}

func (g *Group) ComputeSecretClient(B *big.Int, salt int64, a int64, u *big.Int, x *big.Int) [32]byte {
	var s big.Int
	s.Exp(&g.G, x, &g.N)
	s.Mul(&s, &g.K)
	s.Sub(B, &s)
	s.Mod(&s, &g.N)

	var e big.Int
	e.Mul(u, x)
	e.Mod(&e, &g.N)
	e.Add(&e, big.NewInt(a))
	e.Mod(&e, &g.N)

	s.Exp(&s, &e, &g.N)
	return sha256.Sum256([]byte(s.String()))
}

func NewGroup() Group {
	var N big.Int
	N.SetString("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16)

	return Group{N: N, G: *big.NewInt(2), K: *big.NewInt(3)}
}

func NewServer() Server {
	return Server{Group: NewGroup(), user: User{}}
}

func (s *Server) RegisterUser(email string, password string) {
	s.user.email = email
	s.salt = rand.Int63()
	combined := fmt.Sprintf("%d%s", s.salt, password)
	xH := sha256.Sum256([]byte(combined))
	var x big.Int
	x.SetBytes(xH[:])
	s.user.verifier.Exp(&s.Group.G, &x, &s.Group.N)
}

func (s *Server) Login(email string, A big.Int) (big.Int, int64) {
	if email != s.user.email {
		panic("Invalid email address")
	}

	// Calculate B = kv + g**b
	b := rand.Int63()
	var exp big.Int
	exp.Exp(&s.Group.G, big.NewInt(b), &s.Group.N)
	var B big.Int
	B.Mul(&s.Group.K, &s.user.verifier)
	B.Add(&B, &exp)
	B.Mod(&B, &s.Group.N)

	// Compute the shared key
	u := ComputeMixed(A, B)

	var S big.Int
	S.Exp(&s.user.verifier, &u, &s.Group.N)
	S.Mul(&S, &A)
	S.Mod(&S, &s.Group.N)
	S.Exp(&S, big.NewInt(b), &s.Group.N)
	s.k = sha256.Sum256([]byte(S.String()))

	return B, s.salt
}

func (s *Server) ValidateHMAC(h []byte) bool {
	m := hmac.New(sha256.New, s.k[:])
	trueHMAC := m.Sum([]byte(string(s.salt)))
	return hmac.Equal(h, trueHMAC)
}
