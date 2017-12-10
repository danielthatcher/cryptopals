package main

import (
	"cryptopals/util"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"strings"
)

var key []byte
var iv []byte

func edit(ciphertext []byte, offset int, newtext []byte) []byte {
	decrypted := util.CTRCrypt(ciphertext, key, iv)
	for i := range newtext {
		decrypted[offset+i] = newtext[i]
	}

	return util.CTRCrypt(decrypted, key, iv)
}

func attack(ciphertext []byte) []byte {
	zeroed := make([]byte, len(ciphertext))
	for i := range zeroed {
		zeroed[i] = 0
	}
	keystream := edit(ciphertext, 0, zeroed)
	return util.SliceXOR(keystream, ciphertext)
}

func main() {
	f, _ := ioutil.ReadFile("set4/25.txt")
	fstr := strings.Replace(string(f), "\n", "", -1)
	decoded, _ := base64.StdEncoding.DecodeString(fstr)
	decrypted := util.ECBDecrypt(decoded, []byte("YELLOW SUBMARINE"))

	key = util.RandomBytes(16)
	iv = util.RandomBytes(16)
	crypted := util.CTRCrypt(decrypted, key, iv)
	fmt.Println(string(attack(crypted)))
}
