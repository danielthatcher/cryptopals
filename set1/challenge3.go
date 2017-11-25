package main

import (
	"encoding/hex"
	"fmt"
)

func score(b []byte) int {
	s := 0
	for i := range b {
		if (b[i] > 65 && b[i] < 91) || (b[i] > 96 && b[i] < 123) {
			s++
		}
	}
	return s
}

func main() {
	input, _ := hex.DecodeString(
		"1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")

	maxScore := 0
	maxScoreAnswer := make([]byte, len(input))
	var b byte
	for b = 0; b < 255; b++ {
		guess := make([]byte, len(input))
		for i := range input {
			guess[i] = b ^ input[i]
		}
		s := score(guess)
		if s > maxScore {
			maxScore = s
			maxScoreAnswer = guess
		}
	}

	fmt.Println(maxScoreAnswer)
	fmt.Println(string(maxScoreAnswer))
}
