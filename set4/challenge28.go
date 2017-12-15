package main

import (
	"cryptopals/util/sha1"
	"fmt"
)

func SHA1MAC(message []byte) [20]byte {
	key := []byte("SupaDupaSecret")
	concat := append(key, message...)
	return sha1.Sum(concat)
}

func main() {
	fmt.Println(SHA1MAC([]byte("This is a test")))
	fmt.Println(SHA1MAC([]byte("Thos is a test")))
}
