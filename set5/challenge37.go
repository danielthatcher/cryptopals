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

	// Logging in with a 0 key - we now know that S is 0, so K is SHA256(0)
	A := *big.NewInt(0)
	_, salt := server.Login(email, A)
	k := sha256.Sum256([]byte("0"))

	// Send the HMAC to the client
	h := hmac.New(sha256.New, k[:])
	auth := h.Sum([]byte(string(salt)))

	if server.ValidateHMAC(auth) {
		fmt.Println("It appears to be working")
	} else {
		fmt.Println("That didn't go as plan")
	}
}
