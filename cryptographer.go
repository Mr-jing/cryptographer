package cryptographer

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"hash"

	"github.com/pkg/errors"
)

type Cryptographer interface {
	Encrypt(plaintext []byte) (string, error)
	Decrypt(cipherText string) (string, error)
}

type Crypto struct {
	key     string
	macHash func() hash.Hash
	macSize int
	block   cipher.Block
}

func (c *Crypto) Encrypt(plainText []byte) (string, error) {
	// 密文
	cipherByte := make([]byte, aes.BlockSize+c.macSize+len(plainText))

	// iv 长度等于 aes.BlockSize
	iv := cipherByte[0:aes.BlockSize]

	mac := cipherByte[aes.BlockSize : aes.BlockSize+c.macSize]

	cipherText := cipherByte[aes.BlockSize+c.macSize:]

	// 随机填充 iv
	if _, err := rand.Read(iv); err != nil {
		return "", errors.Wrap(err, "rand.Read err")
	}

	// 生成密文
	stream := cipher.NewCFBEncrypter(c.block, iv)
	stream.XORKeyStream(cipherText, plainText)

	// 生成并填充 mac
	s := c.generateMAC(iv, cipherText)
	copy(mac, s)

	// 返回 base64 字符串
	return base64.StdEncoding.EncodeToString(cipherByte), nil
}

func (c *Crypto) generateMAC(iv []byte, cipherText []byte) []byte {
	var p []byte
	h := hmac.New(c.macHash, []byte(c.key))
	p = append(p, iv...)
	p = append(p, cipherText...)
	h.Write(p)
	return h.Sum(nil)
}

func (c *Crypto) validMAC(iv, cipherText, mac []byte) bool {
	expectedMAC := c.generateMAC(iv, cipherText)
	return hmac.Equal(mac, expectedMAC)
}

func (c *Crypto) Decrypt(cipherText string) (string, error) {
	cipherByte, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return "", errors.Wrap(err, "base64.StdEncoding.DecodeString err")
	}
	if len(cipherByte) < aes.BlockSize+c.macSize {
		return "", errors.New("cipherText too short")
	}

	iv := cipherByte[0:aes.BlockSize]
	mac := cipherByte[aes.BlockSize : aes.BlockSize+c.macSize]
	realCipherText := cipherByte[aes.BlockSize+c.macSize:]

	if !c.validMAC(iv, realCipherText, mac) {
		return "", errors.Wrap(err, "invalid cipherText")
	}

	stream := cipher.NewCFBDecrypter(c.block, iv)
	stream.XORKeyStream(realCipherText, realCipherText)
	return string(realCipherText), nil
}

func NewCryptographer(key string) (Cryptographer, error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, errors.Wrap(err, "aes.NewCipher err")
	}
	return &Crypto{
		key:     key,
		macHash: sha512.New,
		macSize: sha512.Size,
		block:   block,
	}, nil
}
