package core

import (
	"bytes"
	"fmt"
	"net"
	"testing"
)

func TestAeadCipher_PacketConn(t *testing.T) {
	p := impl{}
	p.Say()
}

type impl struct {
	B
}

type I interface {
	Say()
}

type B struct {
}

func (b *B) Say() {
	fmt.Println("hello say say ")
}

func TestKDF(t *testing.T) {
	b := Kdf("123", 2)
	fmt.Printf("%X", b)
}

func TestA(t *testing.T) {
	for k, v := range aeadList {
		fmt.Printf("%s, %v\n", k, v)
	}

	s := aeadList["AEAD_AES_128_GCM"]
	cipher, err := s.New(bytes.Repeat([]byte{0xFF}, 16))
	if err != nil {
		return
	}
	println(cipher)
}

var m = map[string]struct {
	a int
	f func() string
}{
	"a": {97, func() string {
		return "A"
	}},
	"b": {98, BF},
}

func BF() string {
	return "b"
}

func TestMultiMapUse(t *testing.T) {
	println(m["b"].f())
}

type a interface {
	sayA()
}

type b interface {
	sayB()
}

type c interface {
	a
	b
}

func TestCipher(t *testing.T) {
	key := bytes.Repeat([]byte{0xFF}, 16)
	cipher, err := PickCipher("aes-128-gcm", key, "123455")
	if err != nil {
		return
	}
	conn := cipher.StreamConn(nil)
	println(conn)
}

type v interface {
	v()
}

var vMap = map[string]struct {
	Name string
	New  func() v
}{
	"v1": {
		Name: "v1实现者",
		New:  newV1,
	},
}

type v1 struct {
}

func newV1() v {
	println("v1开始构造")
	return &v1{}
}

func (v *v1) v() {
	println("v1")
}

func TestV1(t *testing.T) {
	vMap["v1"].New().v()
}

type shadowConn struct {
	net.Conn
}

func TestName(t *testing.T) {
	s := shadowConn{}
	s.Write([]byte{0, 1, 2})
}
