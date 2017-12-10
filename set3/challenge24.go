package main

import (
	"cryptopals/util"
	"encoding/binary"
	"fmt"
)

func crypt(plaintext []byte, key uint16) []byte {
	r := util.NewMT19337(uint64(key))
	ciphertext := make([]byte, len(plaintext))
	for i := 0; i < len(plaintext); i += 4 {
		k := r.NextInt()
		ks := make([]byte, 8)
		binary.PutUvarint(ks, k)
		for j := 0; j < 4; j++ {
			if i+j >= len(ciphertext) {
				break
			}
			ciphertext[i+j] = plaintext[i+j] ^ ks[j]
		}
	}

	return ciphertext
}

func main() {
	p := []byte("this is a test...")
	c := crypt(p, 1293)
	fmt.Println(c)
	fmt.Println(string(crypt(c, 1293)))

	// Just brute force keys basically. The keyspace is pretty small
	// CBA
}
