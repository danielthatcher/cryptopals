package main

import (
	"cryptopals/util"
	"fmt"
)

// Invert right shift XOR, e.g. y ^= y>>18
func invertXOR(x uint64, shift uint) uint64 {
	for i := 0; i <= 32; i++ {
		x ^= (x >> shift) & (uint64(1) << (32 - uint(i)))
	}
	return x
}

func invertXORMask(x uint64, shift uint, mask uint64) uint64 {
	for i := 0; i <= 32; i++ {
		x ^= (x << shift) & (uint64(1) << uint(i)) & mask
	}
	return x
}

func untemper(x uint64) uint64 {
	b := uint64(0x9D2C5680)
	c := uint64(0xEFC60000)

	x = invertXOR(x, 18)
	x = invertXORMask(x, 15, c)
	x = invertXORMask(x, 7, b)
	x = invertXOR(x, 11)

	return x
}

func main() {
	m := util.NewMT19337(3)
	state := make([]uint64, 624)
	for i := 0; i < 624; i++ {
		state[i] = untemper(m.NextInt())
	}

	cloned := util.NewMT19337State(state)

	for i := range cloned.State {
		if cloned.State[i] != m.State[i] {
			fmt.Println("Failed at", i)
		}
	}

	z := m.NextInt()
	for cloned.NextInt() != z {
	}

	for i := 0; i < 10; i++ {
		fmt.Println(m.NextInt(), cloned.NextInt())
	}
}
