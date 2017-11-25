package main

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"strings"
)

func score(b []byte) int {
	s := 0
	for i := range b {
		if (b[i] > 65 && b[i] < 91) || (b[i] > 96 && b[i] < 123) {
			s++
		}

		// Extra rewards for vowels
		if b[i] == 97 || b[i] == 101 || b[i] == 105 || b[i] == 111 || b[i] == 117 {
			s++
		}
	}

	return s
}

func maxScore(b []byte) (int, []byte) {
	var k byte
	max := 0
	bestGuess := make([]byte, len(b))
	for k = 0; k < 255; k++ {
		guess := make([]byte, len(b))
		for i := range b {
			guess[i] = k ^ b[i]
		}
		s := score(guess)
		if s > max {
			max = s
			bestGuess = guess
		}
	}

	return max, bestGuess
}

func main() {
	f, _ := ioutil.ReadFile("set1/4.txt")
	fstr := string(f)
	lines := strings.Split(fstr, "\n")
	max := 0
	maxIndex := 0
	guess := make([]byte, len(lines[0]))
	for i, l := range lines {
		b, _ := hex.DecodeString(l)
		s, g := maxScore(b)
		if s > max {
			max = s
			maxIndex = i
			guess = g
		}
	}

	fmt.Println(lines[maxIndex])
	fmt.Println(guess)
	fmt.Println(string(guess))
}
