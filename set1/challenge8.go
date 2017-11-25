package main

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"strings"
)

func hammingDisance(a []byte, b []byte) int {
	dist := 0
	for i := range a {
		diffs := a[i] ^ b[i]
		for j := 0; j < 8; j++ {
			dist += int(diffs & 1)
			diffs = diffs >> 1
		}
	}
	return dist
}

func main() {
	f, _ := ioutil.ReadFile("set1/8.txt")
	lines := strings.Split(string(f), "\n")
	minDistance := 100000
	minIndex := 0
	for i := range lines {
		byteLine, _ := hex.DecodeString(lines[i])
		if len(byteLine) == 0 {
			continue
		}
		dist := 0
		for j := 0; j+32 <= len(byteLine); j += 16 {
			dist += hammingDisance(byteLine[j:j+16], byteLine[j+16:j+32])
		}
		if dist < minDistance {
			minDistance = dist
			minIndex = i
		}
	}

	fmt.Println(minIndex)
	fmt.Println(lines[minIndex])
}
