package shadowaead

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"errors"
	"io"
	"strconv"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// ErrRepeatedSalt means detected a reused salt
var ErrRepeatedSalt = errors.New("repeated salt detected")

type Cipher interface {
	KeySize() int  //
	SaltSize() int //  key
	Encrypter(salt []byte) (cipher.AEAD, error)
	Decrypter(salt []byte) (cipher.AEAD, error)
}

type KeySizeError int

func (e KeySizeError) Error() string {
	return "key size error: need " + strconv.Itoa(int(e)) + " bytes"
}

func hkdfSHA1(secret, salt, info, outkey []byte) {
	r := hkdf.New(sha1.New, secret, salt, info)
	if _, err := io.ReadFull(r, outkey); err != nil {
		panic(err) // should never happen
	}
}

type metaCipher struct {
	psk      []byte                                // 密钥 md5 kdf 生成的密钥
	makeAEAD func(key []byte) (cipher.AEAD, error) // new gcm func
}

// KeySize 密钥size
func (a *metaCipher) KeySize() int { return len(a.psk) }

// SaltSize 初始化向量最大不超过16
func (a *metaCipher) SaltSize() int {
	if ks := a.KeySize(); ks > 16 {
		return ks
	}
	return 16
}

// Encrypter salt 作用是什么?
func (a *metaCipher) Encrypter(salt []byte) (cipher.AEAD, error) {
	subkey := make([]byte, a.KeySize())
	// 这里psk也就是原始密码+ md5 补足的 key 作为了 真实的 kdf secret salt 就是一个加盐
	// subKey  其实是真正创建 aes 加密的密钥
	// 其实也就是说 aes 密钥就是 salt + (pwd + md5补齐)然后通过标准 kdf 函数算出来的一个初始化 key
	hkdfSHA1(a.psk, salt, []byte("ss-subkey"), subkey)
	aead, err := a.makeAEAD(subkey)
	if err != nil {
		return nil, err
	}
	return aead, nil
}
func (a *metaCipher) Decrypter(salt []byte) (cipher.AEAD, error) {
	subkey := make([]byte, a.KeySize())
	hkdfSHA1(a.psk, salt, []byte("ss-subkey"), subkey)
	return a.makeAEAD(subkey)
}

// key 就是 init reader & writer 的时候真实生成的
func aesGCM(key []byte) (cipher.AEAD, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

// AESGCM creates a new Cipher with a pre-shared key. len(psk) must be
// one of 16, 24, or 32 to select AES-128/196/256-GCM.
func AESGCM(psk []byte) (Cipher, error) {
	switch l := len(psk); l {
	case 16, 24, 32: // AES 128/196/256
	default:
		return nil, aes.KeySizeError(l)
	}
	return &metaCipher{psk: psk, makeAEAD: aesGCM}, nil
}

// Chacha20Poly1305 creates a new Cipher with a pre-shared key. len(psk)
// must be 32.
func Chacha20Poly1305(psk []byte) (Cipher, error) {
	if len(psk) != chacha20poly1305.KeySize {
		return nil, KeySizeError(chacha20poly1305.KeySize)
	}
	return &metaCipher{psk: psk, makeAEAD: chacha20poly1305.New}, nil
}
