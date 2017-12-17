package main

import (
	"cryptopals/util/sha1"
	"fmt"
)

func SHA1MAC(message []byte) []byte {
	key := []byte("SupaDupaSecret")
	h := sha1.New()
	h.Write(key)
	h.Write(message)
	return h.Sum(nil)
}

func verify(message []byte, mac []byte) bool {
	c := SHA1MAC(message)
	for i := range c {
		if c[i] != mac[i] {
			return false
		}
	}

	return true
}

func putUint64(x []byte, s uint64) {
	_ = x[7]
	x[0] = byte(s >> 56)
	x[1] = byte(s >> 48)
	x[2] = byte(s >> 40)
	x[3] = byte(s >> 32)
	x[4] = byte(s >> 24)
	x[5] = byte(s >> 16)
	x[6] = byte(s >> 8)
	x[7] = byte(s)
}

func pad(msg []byte, keyLen int) []byte {
	var res []byte
	len := len(msg) + keyLen

	// From the golang sha1 library
	// Padding.  Add a 1 bit and 0 bits until 56 bytes mod 64.
	var tmp [64]byte
	tmp[0] = 0x80
	if len%64 < 56 {
		res = append(res, tmp[0:56-len%64]...)
	} else {
		res = append(res, tmp[0:64+56-len%64]...)
	}

	// Length in bits.
	len <<= 3
	putUint64(tmp[:], uint64(len))
	res = append(res, tmp[0:8]...)
	return res
}

func main() {
	baseStr := []byte("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon")
	mac := SHA1MAC(baseStr)
	app := []byte(";admin=true")

	// Try different key lengths
	for i := 0; i < 100; i++ {
		gluePad := pad(baseStr, i)
		forged := append(baseStr, gluePad...)
		prevLen := len(forged) + i
		forged = append(forged, app...)

		d := sha1.NewForged(mac[:], uint64(prevLen))
		d.Write(app)
		newSign := d.Sum(nil)

		if verify(forged, newSign[:]) {
			fmt.Println("SUCCESS")
			fmt.Println(forged)
			fmt.Println(newSign)
		}
	}
}
