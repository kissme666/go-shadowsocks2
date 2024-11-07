package main

import (
	"net"
	"testing"
	"time"
)

func TestFunc(t *testing.T) {

	ShowFunc(func(s string) string {
		return s
	})
}

func ShowFunc(f func(s string) string) {
	print(f("哇哈哈"))
}

func TestServer(t *testing.T) {
	l, err := net.Listen("tcp", ":8008")
	if err != nil {
		return
	}

	for {
		c, err := l.Accept()
		if err != nil {
			return
		}

		defer c.Close()

		_, err = c.Write([]byte(`hello`))
		if err != nil {
			return
		}
		println("close " + c.RemoteAddr().String())
	}
}

func TestA(t *testing.T) {
	ch := make(chan int)
	go func() {
		time.Sleep(3 * time.Second)
		ch <- 10
	}()

	a := <-ch
	println(a)
}
func TestC(t *testing.T) {
}
