package main

import (
	"crypto/aes"
	"fmt"
	"math/rand"
	"strings"
	"time"
)

var key []byte
var chunkStart int // Fuck it

func pad(text []byte, blocksize int) []byte {
	padAmount := blocksize - (len(text) % blocksize)
	ret := text
	for i := 0; i < padAmount; i++ {
		ret = append(ret, byte(0x04))
	}
	return ret
}

func sliceEq(a []byte, b []byte) bool {
	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}

	return true
}

func ECBEncrypt(plaintext []byte, key []byte) []byte {
	plaintext = pad(plaintext, len(key))
	ciphertext := make([]byte, len(plaintext))
	cipher, _ := aes.NewCipher(key)
	for i := 0; i < len(plaintext); i += len(key) {
		dest := make([]byte, len(key))
		cipher.Encrypt(dest, plaintext[i:i+len(key)])
		for j := range dest {
			ciphertext[i+j] = dest[j]
		}
	}

	return ciphertext
}

func ECBDecrypt(ciphertext []byte, key []byte) []byte {
	plaintext := make([]byte, len(ciphertext))
	cipher, _ := aes.NewCipher(key)
	for i := 0; i < len(ciphertext); i += len(key) {
		dest := make([]byte, len(key))
		cipher.Decrypt(dest, ciphertext[i:i+len(key)])
		for j := 0; j < len(key); j++ {
			plaintext[i+j] = dest[j]
		}
	}

	return plaintext
}

func randomBytes(l int) []byte {
	r := make([]byte, l)
	for i := range r {
		r[i] = byte(rand.Int() % 256)
	}

	return r
}

func encode(data map[string]string) string {
	e := ""
	keys := [3]string{"id", "email", "role"}
	for _, k := range keys {
		e = fmt.Sprintf("%s&%s=%s", e, k, data[k])
	}
	return e[1:]
}

func decode(data string) map[string]string {
	pairs := strings.Split(data, "&")
	m := make(map[string]string)
	for _, v := range pairs {
		x := strings.Split(v, "=")
		m[x[0]] = x[1]
	}

	return m
}

func profileFor(email string) string {
	email = strings.Replace(email, "&", "", -1)
	email = strings.Replace(email, "=", "", -1)
	m := make(map[string]string)
	m["email"] = email
	m["role"] = "user"
	m["id"] = "10"
	return encode(m)
}

func profileForCrypt(email string) []byte {
	p := profileFor(email)
	return ECBEncrypt([]byte(p), key)
}

func processProfile(data []byte) {
	d := ECBDecrypt(data, key)
	m := decode(string(d))
	fmt.Println(m)
}

func detectECB(ciphertext []byte, blocksize int) bool {
	for i := 0; i <= len(ciphertext)-(2*blocksize); i++ {
		a := ciphertext[i : i+blocksize]
		for j := i + blocksize; j <= len(ciphertext)-blocksize; j += blocksize {
			b := ciphertext[j : j+blocksize]
			if sliceEq(a, b) {
				chunkStart = i
				return true
			}
		}
	}

	return false
}

func forgeProfile() {
	// Take a shortcut as it's easy to find out anyway
	keysize := 16
	c := make([]byte, 2*keysize)
	for i := range c {
		c[i] = 'A'
	}

	// Find the offset needed to have the email address at a start of a chunk
	pad := make([]byte, 0)
	var offset int
	for offset = 0; true; offset++ {
		ciphertext := profileForCrypt(string(append(pad, c...)))
		if detectECB(ciphertext, keysize) {
			fmt.Println("Found offset as", offset)
			break
		}

		pad = append(pad, 'Z')
	}

	// Get 'admin\x04\x04\x04\x04...' encrypted
	r := []byte("admin")
	for i := len(r); i < keysize; i++ {
		r = append(r, byte(0x04))
	}

	ciphertext := profileForCrypt(string(append(pad, r...)))
	adminCrypt := ciphertext[chunkStart : chunkStart+keysize]

	// Get 'user\x04\x04\x04\x04...' encrypted
	r = []byte("user")
	for i := len(r); i < keysize; i++ {
		r = append(r, byte(0x04))
	}

	ciphertext = profileForCrypt(string(append(pad, r...)))
	userCrypt := ciphertext[chunkStart : chunkStart+keysize]

	// Keep padding until the last block is 'user\x04\x04\x04'
	pad = make([]byte, 0)
	for !sliceEq(ciphertext[len(ciphertext)-keysize:], userCrypt) {
		ciphertext = profileForCrypt(string(pad))
		pad = append(pad, 'A')
	}

	// Overwrite the last block with the admin string
	for i := 0; i < keysize; i++ {
		ciphertext[len(ciphertext)-keysize+i] = adminCrypt[i]
	}
	processProfile(ciphertext)
}

func main() {
	rand.Seed(time.Now().UnixNano())
	key = randomBytes(16)
	forgeProfile()
}
