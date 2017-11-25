package main

import (
	"fmt"
)

func pad(text []byte, blocksize int) []byte {
	padAmount := blocksize - (len(text) % blocksize)
	ret := text
	for i := 0; i < padAmount; i++ {
		ret = append(ret, byte(0x04))
	}
	return ret
}

func main() {
	padded := pad([]byte("YELLOW SUBMARINE"), 20)
	fmt.Println(padded)
}
