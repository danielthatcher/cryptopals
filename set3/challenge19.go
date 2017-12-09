package main

import (
	"crypto/aes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"math"
	"math/rand"
	"strings"
	"time"
)

var key []byte
var nonce []byte

func randomBytes(l int) []byte {
	r := make([]byte, l)
	for i := range r {
		r[i] = byte(rand.Int() % 256)
	}

	return r
}

func sliceXOR(a []byte, b []byte) []byte {
	l := math.Min(float64(len(a)), float64(len(b)))
	r := make([]byte, int(l))
	for i := range r {
		r[i] = a[i] ^ b[i]
	}
	return r
}

func CTR(ciphertext []byte, key []byte, nonce []byte) []byte {
	block, _ := aes.NewCipher(key)
	plaintext := make([]byte, len(ciphertext))

	for counter := uint64(0); counter*uint64(len(key)) < uint64(len(ciphertext)); counter++ {
		counterSlice := make([]byte, 8)
		binary.LittleEndian.PutUint64(counterSlice, counter)
		combined := append(nonce, counterSlice...)
		c := make([]byte, 16)
		block.Encrypt(c, combined)
		for i := counter * uint64(len(key)); i < (counter+1)*uint64(len(key)) && i < uint64(len(ciphertext)); i++ {
			plaintext[i] = ciphertext[i] ^ c[i-(counter*uint64(len(key)))]
		}
	}

	return plaintext
}

// Could change this into a score function, but I think I get the idea that
// this approach is sub-optimal, so fuck it...
func isPrintable(c byte) bool {
	return (c > 65 && c < 122) || c == 32 || (c > 47 && c < 58) || c == 33 || c == 46
}

func decrypt(ciphertexts [][]byte) []byte {
	// Operate under the assumption that all strings are completely printable
	keystream := make([]byte, 0)
	cont := true
	for i := 0; cont; i++ {
		cont = false
		for b := byte(0); b <= 255; b++ {
			p := true
			for j := range ciphertexts {
				if i < len(ciphertexts[j]) {
					cont = true
					if !isPrintable(ciphertexts[j][i] ^ b) {
						p = false
						break
					}
				}
			}

			if p {
				keystream = append(keystream, b)
				break
			}
		}
	}

	return keystream
}

func main() {
	// Initialize
	rand.Seed(time.Now().UnixNano())
	key = randomBytes(16)
	nonce = make([]byte, 8)
	for i := range nonce {
		nonce[i] = 0
	}

	// Load in the strings and encrypt
	f, _ := ioutil.ReadFile("set3/19.txt")
	lines := strings.Split(string(f), "\n")
	crypted := make([][]byte, len(lines))
	for i := range lines {
		d, _ := base64.StdEncoding.DecodeString(lines[i])
		crypted[i] = CTR(d, key, nonce)
	}
	keystream := decrypt(crypted)

	for i := range crypted {
		d := sliceXOR(crypted[i], keystream)
		fmt.Println(string(d))
	}
}
