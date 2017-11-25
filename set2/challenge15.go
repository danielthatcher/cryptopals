package main

import (
	"fmt"
)

func isPrintable(c byte) bool {
	return c > 32 && c < 127
}

func stripPadding(data []byte) ([]byte, error) {
	// Check of no padding
	if isPrintable(data[len(data)-1]) {
		return data, nil
	}

	newData := data
	for i := len(data) - 1; !isPrintable(data[i]); i-- {
		if data[i] != byte(0x04) {
			return nil, fmt.Errorf("Invalid padding")
		}
		newData = data[:i]
	}

	return newData, nil
}

func main() {
	fmt.Println(stripPadding([]byte{0x42, 0x43, 0x44, 0x45, 0x04, 0x04, 0x04, 0x04}))
	fmt.Println(stripPadding([]byte{0x42, 0x43, 0x44, 0x45, 0x05, 0x04, 0x04, 0x04}))
	fmt.Println(stripPadding([]byte{0x42, 0x43, 0x44, 0x45, 0x04, 0x04, 0x04, 0x05}))
}
