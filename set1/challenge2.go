package main

import (
	"encoding/hex"
	"fmt"
	"os"
)

func main() {
	x1, _ := hex.DecodeString(os.Args[1])
	x2, _ := hex.DecodeString(os.Args[2])
	y := make([]byte, len(x1))
	for i := range x1 {
		y[i] = x1[i] ^ x2[i]
	}
	fmt.Println(hex.EncodeToString(y))
}
