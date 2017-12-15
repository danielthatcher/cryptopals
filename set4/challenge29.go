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

}
