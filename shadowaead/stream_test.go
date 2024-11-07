package shadowaead

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"testing"
)

func TestCopy(t *testing.T) {
	s := []string{"a", "b"}

	s2 := make([]string, 1)
	copy(s2, s)
	fmt.Println(s2)

	s3 := s[:1]
	fmt.Println(s3)

	println("=====================")
	bs := make([]byte, 16)
	fmt.Printf("%v\n", bs)
}

func TestA(t *testing.T) {
	src := bytes.Repeat([]byte{0xFF}, 16)
	fmt.Printf("原始数据\n%+X\n", src)
	dst := make([]byte, len(src))
	key := make([]byte, 16)
	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}
	println(block.BlockSize())

	cbc := cipher.NewCBCEncrypter(block, key)
	cbc.CryptBlocks(dst, src)
	fmt.Printf("%+X\n", dst)

	println("================== 解密中 =====================")
	deBs := make([]byte, len(dst))
	cbcDecrypter := cipher.NewCBCDecrypter(block, key)
	cbcDecrypter.CryptBlocks(deBs, dst)
	fmt.Printf("解密后数据\n%+X\n", src)
}

func TestC(t *testing.T) {
	repeat := bytes.Repeat([]byte{0xFF}, 5)
	fmt.Printf("%+X", repeat)

	println("++++++++++++++++++++++++")
	var arr []byte
	println(arr)
	println(arr[0])
}

func TestAppend(t *testing.T) {
	var arr []string
	arr = append(arr, "哈哈")
	fmt.Printf("%v", arr)
	fmt.Printf("%v", arr[:0])
}

func TestD(t *testing.T) {
	h := md5.New()
	h.Write([]byte("啊哈"))
	sum := h.Sum(nil)
	fmt.Printf("%+X", sum)
}

func TestShadow(t *testing.T) {

}

func TestCrypt(t *testing.T) {
	source := "hello world 123"
	text := []byte(source)
	key := bytes.Repeat([]byte{0xFF}, 16)
	log.Printf("plain text: %s--> %s | key: %s\n", source, hex.EncodeToString(text), hex.EncodeToString(key))

	block, err := aes.NewCipher(key)
	if err != nil {
		log.Printf("block err:%+v\n", err)
		return
	}

	aes, err := cipher.NewGCM(block)
	if err != nil {
		log.Printf("aes err:%+v\n", err)
		return
	}

	//salt
	// nonce 其向量
	salt := make([]byte, aes.NonceSize())
	rand.Reader.Read(salt)
	log.Printf("random salt: %s len:%d nonceSize %d\n", hex.EncodeToString(salt), len(salt), aes.NonceSize())

	seal := aes.Seal(nil, salt, text, nil)
	log.Printf("seal: %s, len: %d\n", hex.EncodeToString(seal), len(seal))

	open, err := aes.Open(nil, salt, seal, nil)
	if err != nil {
		return
	}
	log.Printf("open %s souce: %s\n", hex.EncodeToString(open), string(open))
}
func TestSlice(t *testing.T) {
	s := make([]byte, 10)
	log.Printf("%p", s)
	s2 := s[:2]
	log.Printf("%p", s2)

	b := make([]byte, 100)
	println(copy(b, s2))
	log.Printf("%p", b)

	log.Printf("%+v", b[:0])

	println("======================")

	bs := []byte{1, 2, 3, 4, 5, 6}
	bs[2]++
	bs2 := bs[:0]
	log.Printf("%p, %p, %+v, %+v\n", bs, bs2, bs, bs2)
}
