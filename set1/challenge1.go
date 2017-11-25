package main

import (
	"fmt"
	"os"
	"strconv"
)

func hexToBase64(s string) string {
	//Pad the string
	overflow := (len(s) % 6) / 2
	for i := 0; i < overflow; i += 2 {
		s = s + "00"
	}

	ret := ""
	for i := 0; i < len(s); i += 6 {
		val, _ := strconv.ParseInt(s[i:i+6], 16, 64)
		var mask int64 = 63 << 18
		for j := 0; j < 4; j++ {
			syte := (val & mask) >> 18
			val = val << 6

			// Convert to char
			if syte < 26 {
				ret += string('A' + int32(syte))
			} else if syte < 52 {
				ret += string('a' + int32(syte) - int32(26))
			} else if syte < 62 {
				ret += string('0' + int32(syte) - int32(52))
			} else if syte == 62 {
				ret += "+"
			} else if syte == 63 {
				ret += "/"
			}
		}
	}

	return ret
}

func main() {
	fmt.Println(hexToBase64(os.Args[1]))
}
