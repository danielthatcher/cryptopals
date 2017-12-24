package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"cryptopals/util/srp"
	"fmt"
	"math/big"
	"math/rand"
	"time"
)

func main() {
	// Setup and registration
	rand.Seed(time.Now().UnixNano())
	server := srp.NewServer()
	password := "AmazingPassword"
	email := "test@mail.com"
	server.RegisterUser(email, password)

	// Logging in
	a := rand.Int63()
	A := server.Group.GenerateClientKey(a)
	B, salt := server.Login(email, A)

	// Compute x
	combined := fmt.Sprintf("%d%s", salt, password)
	xH := sha256.Sum256([]byte(combined))
	var x big.Int
	x.SetBytes(xH[:])

	// Derive the shared key
	u := srp.ComputeMixed(A, B)
	k := server.Group.ComputeSecretClient(&B, salt, a, &u, &x)

	// Send the HMAC to the client
	h := hmac.New(sha256.New, k[:])
	auth := h.Sum([]byte(string(salt)))

	if server.ValidateHMAC(auth) {
		fmt.Println("It appears to be working")
	} else {
		fmt.Println("That didn't go as plan")
	}
}
