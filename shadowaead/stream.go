package shadowaead

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"net"

	"github.com/shadowsocks/go-shadowsocks2/internal"
)

// payloadSizeMask is the maximum size of payload in bytes.
const payloadSizeMask = 0x3FFF // 16*1024 - 1

type writer struct {
	io.Writer
	cipher.AEAD        // 加密
	nonce       []byte //  aes iv
	buf         []byte // 临时的一个切片
}

// NewWriter wraps an io.Writer with AEAD encryption.
func NewWriter(w io.Writer, aead cipher.AEAD) io.Writer { return newWriter(w, aead) }

func newWriter(w io.Writer, aead cipher.AEAD) *writer {
	return &writer{
		Writer: w,
		AEAD:   aead,
		buf:    make([]byte, 2+aead.Overhead()+payloadSizeMask+aead.Overhead()),
		nonce:  make([]byte, aead.NonceSize()),
	}
}

// Write encrypts b and writes to the embedded io.Writer.
func (w *writer) Write(b []byte) (int, error) {
	n, err := w.ReadFrom(bytes.NewBuffer(b))
	return int(n), err
}

// ReadFrom reads from the given io.Reader until EOF or error, encrypts and
// writes to the embedded io.Writer. Returns number of bytes read from r and
// any error encountered.
// 加密写入
func (w *writer) ReadFrom(r io.Reader) (n int64, err error) {
	for {
		buf := w.buf
		// todo:  这个长度也有讲究吗
		payloadBuf := buf[2+w.Overhead() : 2+w.Overhead()+payloadSizeMask]
		// bytes.Buffer 实现了 io.Reader
		nr, er := r.Read(payloadBuf)

		// nr > 0 bytes.Buffer 里面还存着写入的数据 说明 写入的数据还有剩余
		if nr > 0 {
			n += int64(nr)

			// todo wtf overHead
			buf = buf[:2+w.Overhead()+nr+w.Overhead()]

			payloadBuf = payloadBuf[:nr]
			buf[0], buf[1] = byte(nr>>8), byte(nr) // big-endian payload size
			// 单独加密payload大小
			w.Seal(buf[:0], w.nonce, buf[:2], nil)
			increment(w.nonce)

			//todo: wtf 加两次密是做啥
			// 加密 payload
			w.Seal(payloadBuf[:0], w.nonce, payloadBuf, nil)
			increment(w.nonce)

			// 开始写
			_, ew := w.Writer.Write(buf)
			if ew != nil {
				err = ew
				break
			}
		}

		if er != nil {
			if er != io.EOF { // ignore EOF as per io.ReaderFrom contract
				err = er
			}
			break
		}
	}

	return n, err
}

type reader struct {
	io.Reader
	cipher.AEAD
	nonce    []byte
	buf      []byte
	leftover []byte //缓存的作用
}

// NewReader wraps an io.Reader with AEAD decryption.
func NewReader(r io.Reader, aead cipher.AEAD) io.Reader { return newReader(r, aead) }

func newReader(r io.Reader, aead cipher.AEAD) *reader {
	return &reader{
		Reader: r,
		AEAD:   aead,
		buf:    make([]byte, payloadSizeMask+aead.Overhead()),
		nonce:  make([]byte, aead.NonceSize()),
	}
}

// read and decrypt a record into the internal buffer. Return decrypted payload length and any error encountered.
func (r *reader) read() (int, error) {
	// decrypt payload size
	// 避开了前两个字节 size 2byte
	buf := r.buf[:2+r.Overhead()]

	// r.Reader 就是 net.Conn
	_, err := io.ReadFull(r.Reader, buf)
	if err != nil {
		return 0, err
	}

	// todo: 这个如何控制解密数据的长度
	// todo： 有一个想法 就是加密了两次 第一次解密会得到 payload 2byte 两个大小的明文, 第二次解密得到了 原始明文
	// todo: 既然这样2次加密为啥不直接一次加密之后解密 ？？？
	_, err = r.Open(buf[:0], r.nonce, buf, nil)
	increment(r.nonce)
	if err != nil {
		return 0, err
	}

	// payload 大小
	size := (int(buf[0])<<8 + int(buf[1])) & payloadSizeMask

	// decrypt payload
	buf = r.buf[:size+r.Overhead()]
	_, err = io.ReadFull(r.Reader, buf)
	if err != nil {
		return 0, err
	}

	_, err = r.Open(buf[:0], r.nonce, buf, nil)
	increment(r.nonce)
	if err != nil {
		return 0, err
	}

	return size, nil
}

// Read reads from the embedded io.Reader, decrypts and writes to b.
func (r *reader) Read(b []byte) (int, error) {
	// copy decrypted bytes (if any) from previous record first
	// 读取数据未完全
	if len(r.leftover) > 0 {
		n := copy(b, r.leftover)
		r.leftover = r.leftover[n:]
		return n, nil
	}

	// 完全读取了
	n, err := r.read()
	m := copy(b, r.buf[:n])
	// 没有读取完毕
	// 最大 m == n
	if m < n { //insufficient len(b), keep leftover for next read
		// 放入 buf 里面数据 等待下次取出即可
		r.leftover = r.buf[m:n]
	}
	return m, err
}

// WriteTo reads from the embedded io.Reader, decrypts and writes to w until
// there's no more data to write or when an error occurs. Return number of
// bytes written to w and any error encountered.
func (r *reader) WriteTo(w io.Writer) (n int64, err error) {
	// write decrypted bytes left over from previous record
	for len(r.leftover) > 0 {
		nw, ew := w.Write(r.leftover)
		r.leftover = r.leftover[nw:]
		n += int64(nw)
		if ew != nil {
			return n, ew
		}
	}

	for {
		nr, er := r.read()
		if nr > 0 {
			nw, ew := w.Write(r.buf[:nr])
			n += int64(nw)

			if ew != nil {
				err = ew
				break
			}
		}

		if er != nil {
			if er != io.EOF { // ignore EOF as per io.Copy contract (using src.WriteTo shortcut)
				err = er
			}
			break
		}
	}

	return n, err
}

// increment little-endian encoded unsigned integer b. Wrap around on overflow.
func increment(b []byte) {
	for i := range b {
		b[i]++
		if b[i] != 0 {
			return
		}
	}
}

type streamConn struct {
	net.Conn
	Cipher
	r *reader
	w *writer
}

func (c *streamConn) initReader() error {
	salt := make([]byte, c.SaltSize())
	if _, err := io.ReadFull(c.Conn, salt); err != nil {
		return err
	}
	aead, err := c.Decrypter(salt)
	if err != nil {
		return err
	}

	if internal.CheckSalt(salt) {
		return ErrRepeatedSalt
	}

	c.r = newReader(c.Conn, aead)
	return nil
}

func (c *streamConn) Read(b []byte) (int, error) {
	if c.r == nil {
		if err := c.initReader(); err != nil {
			return 0, err
		}
	}
	return c.r.Read(b)
}

func (c *streamConn) WriteTo(w io.Writer) (int64, error) {
	if c.r == nil {
		if err := c.initReader(); err != nil {
			return 0, err
		}
	}
	return c.r.WriteTo(w)
}

func (c *streamConn) initWriter() error {
	salt := make([]byte, c.SaltSize())
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return err
	}
	// 真实创建了 加密对象 aes
	aead, err := c.Encrypter(salt)
	if err != nil {
		return err
	}
	// todo: 先发送salt  why
	// salt 是完全随机生成，也就说双发的 secret 一致但是 保证不了 salt 一致，所以必须写入
	// 创建aead完毕之后会发送salt
	// 如果 salt 读写双方不一致那么就会加解密对不上1
	// 这个写是raw的也就是不加密啊的
	_, err = c.Conn.Write(salt)
	if err != nil {
		return err
	}
	// todo: wtf: ? 在干啥 why
	// 安全考虑 暂时不
	internal.AddSalt(salt)
	c.w = newWriter(c.Conn, aead)
	return nil
}

func (c *streamConn) Write(b []byte) (int, error) {
	if c.w == nil {
		if err := c.initWriter(); err != nil {
			return 0, err
		}
	}
	return c.w.Write(b)
}

func (c *streamConn) ReadFrom(r io.Reader) (int64, error) {
	if c.w == nil {
		if err := c.initWriter(); err != nil {
			return 0, err
		}
	}
	return c.w.ReadFrom(r)
}

// NewConn wraps a stream-oriented net.Conn with cipher.
func NewConn(c net.Conn, ciph Cipher) net.Conn {
	return &streamConn{Conn: c, Cipher: ciph}
}
