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
	iv           []byte
}

func newAPI() *API {
	rand.Seed(time.Now().UnixNano())
	k := util.RandomBytes(16)
	a := API{secretKey: k, signedInUser: 42, iv: make([]byte, 16)}
	return &a
}

func (api *API) generateSendRequest(txList [][2]int) string {
	txString := ""
	for i := range txList {
		if i > 0 {
			txString = fmt.Sprintf("%s;", txString)
		}
		txString = fmt.Sprintf("%s%d:%d", txString, txList[i][0], txList[i][1])
	}

	msg := fmt.Sprintf("from=%d&tx_list=%s", api.signedInUser, txString)
	mac := util.CBCMAC([]byte(msg), api.secretKey, api.iv)
	return fmt.Sprintf("%s$%x", msg, mac)
}

func (api *API) receiveSendRequest(req string) bool {
	parts := strings.Split(req, "$")
	if len(parts) != 2 {
		fmt.Println("Invalid request string")
		return false
	}

	// Extract the parts
	msg := parts[0]
	mac, err := hex.DecodeString(parts[1])
	if err != nil {
		fmt.Println("Error decoding MAC")
		return false
	}

	// Compare MAC (with a timing side channel)
	trialMAC := util.CBCMAC([]byte(msg), api.secretKey, api.iv)
	for j := range trialMAC {
		if trialMAC[j] != mac[j] {
			fmt.Println("Invalid MAC")
			return false
		}
	}

	// If we've gotten to this point, we can transfer the money
	msgParts := strings.Split(msg, "&")
	var fromID int
	txList := make([][2]int, 0)
	for i := range msgParts {
		if strings.HasPrefix(msgParts[i], "from=") {
			fromID, err = strconv.Atoi(strings.Split(msgParts[i], "=")[1])
			if err != nil {
				return false
			}
		} else if strings.HasPrefix(msgParts[i], "tx_list=") {
			txParts := strings.Split(msgParts[i], "=")
			if len(txParts) != 2 {
				fmt.Println("Invalid transaction list")
				return false
			}

			txParts = strings.Split(txParts[1], ";")
			for j := range txParts {
				p := strings.Split(txParts[j], ":")
				if len(p) != 2 {
					fmt.Println("Invalid transaction list")
					continue
				}

				to, err := strconv.Atoi(p[0])
				if err != nil {
					fmt.Println("Invalid transaction list")
					continue
				}

				amount, err := strconv.Atoi(p[1])
				if err != nil {
					fmt.Println("Invalid transaction list")
					continue
				}

				txList = append(txList, [2]int{to, amount})
			}
		} else {
			fmt.Println("Invalid message")
			return false
		}
	}

	fmt.Println("Running transactions...")
	for i := range txList {
		fmt.Printf("Transfering %d spacebuck from user %d to user %d\n", txList[i][1], fromID, txList[i][0])
	}

	return true
}

func main() {
	api := newAPI()

	// Capture request from victim
	req := api.generateSendRequest([][2]int{[2]int{4, 100}, [2]int{12, 1003}})
	fmt.Println(req)

	// We're going to get easily predictable padding before CBC, so add it
	victimParts := strings.Split(req, "$")
	victimMAC, _ := hex.DecodeString(victimParts[1])
	msg := string(util.Pad([]byte(victimParts[0]), 16))
	fmt.Println([]byte(msg))

	// CBA to implement diff users, but doesn't matter here
	attackerReq := api.generateSendRequest([][2]int{[2]int{1, 1}, [2]int{42, 1000000}})
	attackerParts := strings.Split(attackerReq, "$")
	attackerMAC, _ := hex.DecodeString(attackerParts[1])
	attackerMsg := attackerParts[0]
	attackerBlock := attackerParts[0]

	attackerBlock = string(util.SliceXOR([]byte(attackerBlock), victimMAC))
	attackerMsg = fmt.Sprintf("%s%s", attackerBlock, attackerMsg[16:])
	msg = fmt.Sprintf("%s%s", msg, attackerMsg)
	fmt.Println(msg)

	req = fmt.Sprintf("%s$%x", msg, attackerMAC)
	api.receiveSendRequest(req)
}
