package main

import (
	"cryptopals/util/rsa"
	"fmt"
)

func main() {
	pubkey, privkey := rsa.GenerateKeypair(256)
	fmt.Println(pubkey)
	message := []byte("This is a test message")
	fmt.Println(string(message))
	fmt.Println(message)
	crypted := rsa.Crypt(message, pubkey)
	fmt.Println(crypted)
	decrypted := rsa.Crypt(crypted, privkey)
	fmt.Println(decrypted)
	fmt.Println(string(decrypted))
}
