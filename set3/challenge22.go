package main

import (
	"fmt"
	"math/rand"
	"time"
)

type Rand struct {
	state      []int
	seed       int
	index      int
	w          int
	n          int
	m          int
	r          int
	a          int
	u          int
	d          int
	s          int
	b          int
	t          int
	c          int
	I          int
	upper_mask int
	lower_mask int
}

func (r *Rand) Init(seed int) {
	r.w = 32
	r.n = 624
	r.m = 397
	r.r = 31
	r.a = 0x9908B0DF
	r.u = 11
	r.d = 0xFFFFFFFF
	r.s = 7
	r.b = 0x9D2C5680
	r.t = 15
	r.c = 0xEFC60000
	r.I = 18
	r.lower_mask = 0x7fffffff
	r.upper_mask = 0x80000000
	r.index = 0
	r.state = make([]int, r.n)
	r.seed = seed
	r.state[0] = seed & 0xffffffff
	for i := 1; i < len(r.state); i++ {
		r.state[i] = (1812433253*(r.state[i-1]^(r.state[i-1]>>30)) + i)
		r.state[i] = r.state[i] & 0xffffffff
	}
	r.index = r.n + 1
}

func (r *Rand) NextInt() int32 {
	// Reset state if necessary
	if r.index >= r.n {
		mag01 := []int{0, r.a}
		if r.index == r.n+1 {
			r.Init(r.seed)
		}

		// First loop
		for k := 0; k < r.n-r.m; k++ {
			y := (r.state[k] & r.upper_mask) | (r.state[k+1] & r.lower_mask)
			r.state[k] = r.state[k+r.m] ^ (y >> 1) ^ mag01[y&1]
		}

		// Second loop
		for k := r.n - r.m; k < r.n-1; k++ {
			y := (r.state[k] & r.upper_mask) | (r.state[k+1] & r.lower_mask)
			r.state[k] = r.state[k+r.m-r.n] ^ (y >> 1) ^ mag01[y&1]
		}

		y := (r.state[r.n-1] & r.upper_mask) | (r.state[0] & r.lower_mask)
		r.state[r.n-1] = r.state[r.n-1] ^ (y >> 1) ^ mag01[y&1]
		r.index = 0
	}

	y := r.state[r.index]
	r.index += 1
	y ^= (y >> 11)
	y ^= (y << 7) & r.b
	y ^= (y << 15) & r.c
	y ^= (y >> 18)

	return int32(y)
}

func getSeed(output int32) int64 {
	startTime := (time.Now().Add(-1001 * time.Second)).Unix()
	endTime := time.Now().Add(time.Second).Unix()

	for i := startTime; i < endTime; i++ {
		r := Rand{}
		r.Init(int(i))
		if r.NextInt() == output {
			return i
		}
	}

	return 0
}

func main() {
	rand.Seed(time.Now().Unix())
	delay := int64(40 + rand.Intn(960))
	r := Rand{}
	seed := int(time.Now().Add(time.Duration(-delay)).Unix())
	fmt.Println("Actual seed:", seed)
	r.Init(seed)

	// Gimme seed
	fmt.Println("Found seed:", getSeed(r.NextInt()))
}
