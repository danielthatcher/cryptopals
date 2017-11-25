package main

import (
	"crypto/aes"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"strings"
)

func main() {
	f, _ := ioutil.ReadFile("set1/7.txt")
	fstr := strings.Replace(string(f), "\n", "", -1)
	decoded, _ := base64.StdEncoding.DecodeString(fstr)
	key := []byte("YELLOW SUBMARINE")
	cipher, _ := aes.NewCipher(key)

	dst := make([]byte, len(decoded))
	for i := 0; i < len(dst); i += 16 {
		blockDst := make([]byte, 16)
		cipher.Decrypt(blockDst, decoded[i:i+16])
		for j := 0; j < 16; j++ {
			dst[i+j] = blockDst[j]
		}
	}

	fmt.Println(string(dst))
}
