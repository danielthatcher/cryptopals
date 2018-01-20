package main

import (
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"cryptopals/util"
	"fmt"
)

func compressionOracle(data []byte) int {
	sessionId := "TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE="
	contents := fmt.Sprintf(`POST / HTTP/1.1
Host: hapless.com
Cookie: sessionid=%s
Content-Length: %d

%s`, sessionId, len(data), string(data))

	var b bytes.Buffer
	w := zlib.NewWriter(&b)
	w.Write([]byte(contents))
	w.Close()

	padded := util.Pad(b.Bytes(), 16)
	encrypted := make([]byte, len(padded))
	key := util.RandomBytes(16)
	iv := util.RandomBytes(16)
	block, _ := aes.NewCipher(key)
	cbc := cipher.NewCBCEncrypter(block, iv)
	cbc.CryptBlocks(encrypted, padded)

	return len(encrypted)
}

func main() {
	rbytes := util.RandomBytes(32)
	rbytes = append([]byte{1}, rbytes...)
	secret := []byte("Cookie: sessionid=")

	for {
		// Find the cutoff length
		n := compressionOracle(secret)
		var base int
		for base = 0; compressionOracle(append(secret, rbytes[:base+1]...)) == n; base++ {
		}

		l := len(secret)
		for b := byte(0); b < 255; b++ {
			trialSecret := append(secret, b)
			trialSecret = append(trialSecret, rbytes[:base]...)
			if compressionOracle(trialSecret) <= n {
				secret = append(secret, b)
				fmt.Printf("\r%s", string(secret))
				break
			}
		}

		// Nothing new found
		if l == len(secret) {
			break
		}

		// Don't grab new headers
		if secret[len(secret)-1] == '\n' {
			secret = secret[:len(secret)-1]
			break
		}
	}

	fmt.Println("")
	fmt.Println(string(secret))

	if string(secret) == "Cookie: sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=" {
		fmt.Println("Successfully found secret")
	} else {
		fmt.Println("Not quite...")
	}
}
