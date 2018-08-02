package sm4

import (
	"fmt"
	"strings"
	"testing"
)

func Test_Crypt(t *testing.T) {
	data := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}
	fmt.Printf("da : %x \n", data)
	key := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}
	en := EncriptB(key, data)
	fmt.Printf("en : %x \n", en)
	de := DecriptB(key, en)
	fmt.Printf("de : %x \n", de)
}

func ToString(input []byte, offset, count int) string {
	var builder []string = make([]string, count)
	for i := 0; i < count; i++ {
		builder[i] = fmt.Sprintf("%x", input[i])
	}
	return strings.Join(builder, "")
}
