package main

import (
	"cryptopals/util"
	"fmt"
)

func hash(msg []byte) []byte {
	key := []byte("YELLOW SUBMARINE")
	iv := make([]byte, 16)
	return util.CBCMAC(msg, key, iv)
}

func main() {
	// First generate the first hash
	trueMsg := "alert('MZA who was that?');"
	trueHash := hash([]byte(trueMsg))
	fmt.Printf("%x\n", trueHash)

	// Let's forge
	fakeMsg := "alert('Ayo, the Wu is back!');//"
	fakeHash := hash([]byte(fakeMsg))
	fakeMsg = string(util.Pad([]byte(fakeMsg), 16))

	xored := util.SliceXOR([]byte(trueMsg[:16]), fakeHash)
	fakeMsg = fmt.Sprintf("%s%s%s", fakeMsg, string(xored), trueMsg[16:])

	fmt.Printf("%x\n", hash([]byte(fakeMsg)))
	fmt.Println(fakeMsg)
}
