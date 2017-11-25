package main

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"strings"
)

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

func getKeySize(decoded []byte) int {
	// Try keysizes between 2 and 40
	minDistance := float32(100.0)
	minSize := 0
	for ksize := 2; ksize < 41; ksize++ {
		tot := 0
		sum := float32(0.0)
		for i := 0; i < len(decoded)-(2*ksize); i += ksize {
			tot++
			d := hammingDisance(decoded[i:i+ksize], decoded[i+ksize:i+(2*ksize)])
			sum += float32(d) / float32(ksize)
		}

		if sum/float32(tot) < minDistance {
			minDistance = sum / float32(tot)
			minSize = ksize
		}
	}

	return minSize
}

func splitAndTranspose(decoded []byte, ksize int) [][]byte {
	chunks := make([][]byte, ksize)
	for i, b := range decoded {
		index := i % ksize
		chunks[index] = append(chunks[index], b)
	}
	return chunks
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

func solveSingleByteXOR(input []byte) byte {
	maxScore := 0
	var key byte
	var b byte
	for b = 0; b < 255; b++ {
		guess := make([]byte, len(input))
		for i := range input {
			guess[i] = b ^ input[i]
		}
		s := score(guess)
		if s > maxScore {
			maxScore = s
			key = b
		}
	}
	return key
}

func decrypt(cipherbytes []byte, key []byte) []byte {
	plainbytes := make([]byte, len(cipherbytes))
	for i := range cipherbytes {
		plainbytes[i] = cipherbytes[i] ^ key[i%len(key)]
	}
	return plainbytes
}

func main() {
	// Get the raw bytes encoded in the file
	f, _ := ioutil.ReadFile("set1/6.txt")
	fstr := strings.Replace(string(f), "\n", "", -1)
	decoded, _ := base64.StdEncoding.DecodeString(fstr)
	keysize := getKeySize(decoded)
	chunks := splitAndTranspose(decoded, keysize)
	key := make([]byte, len(chunks))
	for i := range key {
		key[i] = solveSingleByteXOR(chunks[i])
	}
	fmt.Println(string(key))
	fmt.Println(string(decrypt(decoded, key)))
}
