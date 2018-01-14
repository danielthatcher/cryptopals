package main

import (
	"cryptopals/util"
	"encoding/hex"
	"fmt"
	"math/rand"
	"strconv"
	"strings"
	"time"
)

type API struct {
	signedInUser int
	secretKey    []byte
}

func newAPI() *API {
	rand.Seed(time.Now().UnixNano())
	k := util.RandomBytes(16)
	a := API{secretKey: k, signedInUser: 42}
	return &a
}

func (api *API) generateSendRequest(toID int, amount int) string {
	msg := fmt.Sprintf("from=%d&to=%d&amount=%d", api.signedInUser, toID, amount)
	iv := util.RandomBytes(16)
	mac := util.CBCMAC([]byte(msg), api.secretKey, iv)
	return fmt.Sprintf("%s$%x$%x", msg, iv, mac)
}

func (api *API) receiveSendRequest(req string) bool {
	parts := strings.Split(req, "$")
	if len(parts) != 3 {
		fmt.Println("Invalid request string")
		return false
	}

	// Extract the parts
	msg := parts[0]

	iv, err := hex.DecodeString(parts[1])
	if err != nil {
		fmt.Println("Error decoding iv")
		return false
	}

	mac, err := hex.DecodeString(parts[2])
	if err != nil {
		fmt.Println("Error decoding MAC")
		return false
	}

	// Compare MAC (with a timing side channel)
	trialMAC := util.CBCMAC([]byte(msg), api.secretKey, iv)
	for j := range trialMAC {
		if trialMAC[j] != mac[j] {
			fmt.Println("Invalid MAC")
			return false
		}
	}

	// If we've gotten to this point, we can transfer the money
	msgParts := strings.Split(msg, "&")
	var toID, fromID, amount int
	for i := range msgParts {
		if strings.HasPrefix(msgParts[i], "from=") {
			fromID, err = strconv.Atoi(strings.Split(msgParts[i], "=")[1])
			if err != nil {
				return false
			}
		} else if strings.HasPrefix(msgParts[i], "to=") {
			toID, err = strconv.Atoi(strings.Split(msgParts[i], "=")[1])
			if err != nil {
				fmt.Println("Invalid to ID")
				return false
			}
		} else if strings.HasPrefix(msgParts[i], "amount=") {
			amount, err = strconv.Atoi(strings.Split(msgParts[i], "=")[1])
			if err != nil {
				fmt.Println("Invalid amount")
				return false
			}
		} else {
			fmt.Println("Invalid message")
			return false
		}
	}
	fmt.Printf("Transfering %d spacebucks from user %d to user %d\n", amount, fromID, toID)
	return true
}

func main() {
	api := newAPI()
	req := api.generateSendRequest(42, 10000000)
	firstBlock := req[:16]
	req = strings.Replace(req, "from=42", "from=01", 1)

	reqParts := strings.Split(req, "$")
	ivStr := reqParts[1]
	iv, _ := hex.DecodeString(ivStr)

	xored := util.SliceXOR([]byte(firstBlock), []byte(req[:16]))
	iv = util.SliceXOR(iv, xored)
	req = fmt.Sprintf("%s$%x$%s", reqParts[0], iv, reqParts[2])

	api.receiveSendRequest(req)
}
