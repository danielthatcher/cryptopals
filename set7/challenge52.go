package main

import (
	"cryptopals/util"
	"fmt"
)

// Find 2^n collisions (all these collide with a stream of 0 bytes)
func generateCollisionsA(n int) (collisions [][]byte) {
	collisions = make([][]byte, 0)
	pairs := make([][2][]byte, 0)
	hash := util.NewHashA()
	state := hash.H
	h := hash.Sum(make([]byte, 16))

	// Pairs for each block
	for j := 0; j < n; j++ {
		// Find a collision in the jth block
		i := 15
		c := make([]byte, 16)
		for {
			c[i]++
			for c[i] == 255 {
				c[i] = 0
				i--
				c[i]++
			}
			i = 15

			hash.H = state
			x := hash.Sum(c)
			if x[0] == h[0] && x[1] == h[1] {
				pairs = append(pairs, [2][]byte{make([]byte, 16), c})
				state = hash.H
				h = hash.Sum(make([]byte, 16))
				if j == 0 {
					collisions = append(collisions, make([]byte, 16))
					collisions = append(collisions, c)
				} else {
					collisions = append(collisions, collisions...)
					for k := range collisions {
						if k < len(collisions)/2 {
							collisions[k] = append(collisions[k], make([]byte, 16)...)
						} else {
							collisions[k] = append(collisions[k], c...)
						}
					}
				}
				break
			}
		}
	}

	return
}

func main() {
	collisions := generateCollisionsA(5)
	h := util.NewHashA()
	for i := range collisions {
		h.Reset()
		fmt.Println(h.Sum(collisions[i]))
	}
}
