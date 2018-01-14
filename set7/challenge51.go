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

	encrypted := make([]byte, len(b.Bytes()))
	key := util.RandomBytes(16)
	iv := util.RandomBytes(16)
	block, _ := aes.NewCipher(key)
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(encrypted, []byte(b.Bytes()))

	return len(encrypted)
}

func main() {
	secret := []byte("sessionid=")
	n := compressionOracle(secret)

	for {
		l := len(secret)
		for b := byte(0); b < 255; b++ {
			if compressionOracle(append(secret, b)) <= n {
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

	if string(secret) == "sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=" {
		fmt.Println("Successfully found secret")
	} else {
		fmt.Println("Not quite...")
	}
}
