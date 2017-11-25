package main

import (
	"encoding/hex"
	"fmt"
)

func main() {
	plaintext := `Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal`
	key := []byte("ICE")
	plainbytes := []byte(plaintext)

	cipherbytes := make([]byte, len(plainbytes))
	for i := range plainbytes {
		cipherbytes[i] = plainbytes[i] ^ key[i%len(key)]
	}

	fmt.Println(cipherbytes)
	fmt.Println(hex.EncodeToString(cipherbytes))
}
