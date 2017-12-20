package main

import (
	"crypto/sha1"
	"cryptopals/util"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"
)

func calculateHMAC(key []byte, data []byte) [20]byte {
	// Pad or hash the key
	if len(key) >= 64 {
		x := sha1.Sum(key)
		key = x[:]
	} else {
		key = append(key, make([]byte, 64-len(key))...)
	}

	// Inner and outer padding
	opad := make([]byte, len(key))
	ipad := make([]byte, len(key))

	for i := range opad {
		opad[i] = byte(0x5c)
		ipad[i] = byte(0x36)
	}

	opad = util.SliceXOR(key, opad)
	ipad = util.SliceXOR(key, ipad)

	x := sha1.Sum(append(ipad, data...))
	x = sha1.Sum(append(opad, x[:]...))
	return x
}

func verifyHMAC(w http.ResponseWriter, req *http.Request) {
	params := req.URL.Query()
	hmacString, hmacExists := params["signature"]
	if !hmacExists {
		w.WriteHeader(http.StatusInternalServerError)
	}

	hmac, err := hex.DecodeString(hmacString[0])
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	truehmac := calculateHMAC([]byte("This is a key!"), []byte("This might as well be a file, it doesn't matter"))
	if len(truehmac) != len(hmac) {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	for i := range truehmac {
		if truehmac[i] != hmac[i] {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		time.Sleep(50 * time.Millisecond)
	}

	w.WriteHeader(http.StatusOK)
}

func webapp() {
	http.HandleFunc("/test", verifyHMAC)
	http.ListenAndServe(":8080", nil)
}

func attack() {
	urlbase := "http://localhost:8080/test?signature="
	diff := 50 * time.Millisecond

	hmac := make([]byte, 20)
	delay := diff
	for i := 0; i < 20; i++ {
		for b := byte(0); b <= 255; b++ {
			curtime := time.Now()
			hmac[i] = b
			http.Get(fmt.Sprintf("%s%s", urlbase, hex.EncodeToString(hmac)))
			timediff := time.Now().Sub(curtime)
			if timediff > delay {
				fmt.Println(b)
				delay += diff
				break
			}
		}
	}

	fmt.Println(hex.EncodeToString(hmac))
}

func main() {
	go webapp()
	fmt.Println("Running server...")
	attack()
}
