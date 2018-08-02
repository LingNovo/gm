package main

import (
	"bytes"
	"crypto/cipher"
	"fmt"
	"gm/sm3"
	"gm/sm4"
	"strconv"
)

func hashSm3(src []byte) []byte {
	h := sm3.New()
	h.Write(src)
	return h.Sum(nil)
}

func ensm4(src, key []byte) []byte {
	block, err := sm4.NewCipher(key)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	blockSize := block.BlockSize()
	data := ZeroPadding(src, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, key[:blockSize])
	crypted := make([]byte, 16)
	blockMode.CryptBlocks(crypted, data)
	return crypted
}

func desm4(crypted, key []byte) []byte {
	block, err := sm4.NewCipher(key)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, key[:blockSize])
	text := crypted
	blockMode.CryptBlocks(text, crypted)
	text = ZeroUnPadding(text)
	return text
}

func ensm4none(src, key []byte) []byte {
	block, err := sm4.NewCipher(key)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	var dst []byte
	block.Encrypt(dst, src)
	return dst
}

func desm4none(src, key []byte) []byte {
	block, err := sm4.NewCipher(key)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	var dst []byte
	block.Decrypt(dst, src)
	return dst
}

func ZeroPadding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{0}, padding)
	return append(ciphertext, padtext...)
}

func ZeroUnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	// 去掉最后一个字节 unpadding 次
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

//二进制转十六进制
func btox(b string) string {
	base, _ := strconv.ParseInt(b, 2, 10)
	return strconv.FormatInt(base, 16)
}

//十六进制转二进制
func xtob(x string) string {
	base, _ := strconv.ParseInt(x, 16, 10)
	return strconv.FormatInt(base, 2)
}

func hb(s string) []byte {
	count := len(s) / 2
	result := make([]byte, count)
	for i := 0; i < count; i++ {
		x := s[i*2 : i*2+1]
		y := s[i*2+1 : i*2+2]
		z, _ := strconv.ParseInt(x, 2, 10)
		w, _ := strconv.ParseInt(y, 2, 10)
		result[i] = byte(z*16 + w)
	}
	return result
}

func main() {
	data := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}
	fmt.Printf("da : %X \n", data)
	key := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}
	en := ensm4none(data, key)
	fmt.Printf("en : %X \n", en)
	de := desm4none(en, key)
	fmt.Printf("de : %X \n", de)
	fmt.Println("over")
}
