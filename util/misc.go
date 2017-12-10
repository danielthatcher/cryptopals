package util

import (
	"math"
	"math/rand"
)

func SliceXOR(a []byte, b []byte) []byte {
	r := make([]byte, int(math.Min(float64(len(a)), float64(len(b)))))
	for i := range r {
		r[i] = a[i] ^ b[i]
	}
	return r
}

func RandomBytes(l int) []byte {
	r := make([]byte, l)
	for i := range r {
		r[i] = byte(rand.Int() % 256)
	}

	return r
}
