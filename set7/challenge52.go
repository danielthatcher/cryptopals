package main

import (
	"bytes"
	"cryptopals/util"
	"fmt"
)

// Find 2^n collisions (all these collide with a stream of 0 bytes)
func generateCollisionsA(n int) (collisions [][]byte) {
	collisions = make([][]byte, 1<<uint(n))
	for i := range collisions {
		collisions[i] = make([]byte, 16*n)
	}
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
				state = hash.H
				h = hash.Sum(make([]byte, 16))

				divider := len(collisions) / (1 << uint(j+1))
				startIndex := 16 * j
				for k := range collisions {
					var z []byte
					if (k/divider)%2 == 0 {
						z = make([]byte, 16)
					} else {
						z = c
					}

					for l := 0; l < 16; l++ {
						collisions[k][l+startIndex] = z[l]
					}
				}

				break
			}
		}
	}

	return
}

func main() {
	fmt.Println("Generating initial collisions")
	b2 := 32 // Should be 64, but 32 works and prevents out of memory
	collisions := generateCollisionsA(b2 / 2)

	// Hash all the collisions in hashb
	fmt.Println("Hashing with second function")
	hb := util.NewHashB()
	hashed := make([][]byte, len(collisions))
	for i := range collisions {
		hb.Reset()
		hashed[i] = hb.Sum(collisions[i])
	}

	// Now check for duplicates in hashed
	fmt.Println("Finding final collisions")
	output := make([][]byte, 0)
	for i := range hashed {
		for j := i + 1; j < len(hashed); j++ {
			if bytes.Compare(hashed[i], hashed[j]) == 0 {
				output = append(output, collisions[i])
				output = append(output, collisions[j])
				break
			}
		}

		if len(output) == 2 {
			break
		}
	}

	fmt.Println("Found collisions:")
	fmt.Printf("%x\n%x\n", output[0], output[1])

	ha := util.NewHashA()
	for i := range output {
		ha.Reset()
		hb.Reset()

		fmt.Printf("Combined hash of output number %d:\n", i+1)
		fmt.Printf("%x%x\n", ha.Sum(output[i]), hb.Sum(output[i]))
	}
}
