package main

import (
	"cryptopals/util"
	"fmt"
)

func main() {
	d := util.NISTDiffieHellman()
	fmt.Println(d.PublicKey(21939320))
}
