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

func hammingDisance(a []byte, b []byte) int {
	dist := 0
	for i := range a {
		diffs := a[i] ^ b[i]
		for j := 0; j < 8; j++ {
			dist += int(diffs & 1)
			diffs = diffs >> 1
		}
	}
	return dist
}

func decrypt(ciphertexts [][]byte) []byte {
	// Compute the keysize
	keysize := len(ciphertexts[0])
	for i := range ciphertexts {
		if len(ciphertexts[i]) < keysize {
			keysize = len(ciphertexts[i])
		}
	}

	// Get the best key
	keystream := make([]byte, keysize)
	for i := 0; i < keysize; i++ {
		maxScore := 0
		bestByte := byte(0)
		for b := byte(0); b < 255; b++ {
			fmt.Println(b)
			d := make([]byte, len(ciphertexts))
			for j := range ciphertexts {
				d[j] = ciphertexts[j][i] ^ b
			}
			s := score(d)
			if s > maxScore {
				maxScore = s
				bestByte = b
			}
		}

		keystream[i] = bestByte
	}

	return keystream
}

func score(b []byte) int {
	s := 0
	for i := range b {
		if (b[i] > 65 && b[i] < 91) || (b[i] > 96 && b[i] < 123) {
			s++
		}

		// Extra rewards for vowels
		if b[i] == 97 || b[i] == 101 || b[i] == 105 || b[i] == 111 || b[i] == 117 {
			s++
		}

		// Extra for a space
		if b[i] == 32 {
			s += 2
		}
	}

	return s
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
	f, _ := ioutil.ReadFile("set3/20.txt")
	lines := strings.Split(string(f), "\n")
	crypted := make([][]byte, len(lines))
	for i := range lines {
		d, _ := base64.StdEncoding.DecodeString(lines[i])
		crypted[i] = CTR(d, key, nonce)
	}

	// Remove the empty line at the end
	crypted = crypted[:len(crypted)-1]

	keystream := decrypt(crypted)
	fmt.Println(keystream)

	for i := range crypted {
		d := sliceXOR(crypted[i], keystream)
		fmt.Println(string(d))
	}
}
