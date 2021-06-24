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

type crypto struct {
	key     string
	macHash func() hash.Hash
	macSize int
	block   cipher.Block
}

func (c *crypto) Encrypt(plainText []byte) (string, error) {
	// 密文
	cipherText := make([]byte, aes.BlockSize+c.macSize+len(plainText))

	// iv 长度等于 aes.BlockSize
	iv := cipherText[0:aes.BlockSize]

	mac := cipherText[aes.BlockSize : aes.BlockSize+c.macSize]

	// 随机填充 iv
	if _, err := rand.Read(iv); err != nil {
		return "", errors.Wrap(err, "rand.Read err")
	}

	// 生成密文
	stream := cipher.NewCFBEncrypter(c.block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize+c.macSize:], plainText)

	// 生成并填充 mac
	copy(mac, c.generateMAC(iv, cipherText))

	// 返回 base64 字符串
	return base64.StdEncoding.EncodeToString(cipherText), nil
}

func (c *crypto) generateMAC(iv []byte, cipherText []byte) []byte {
	h := hmac.New(c.macHash, []byte(c.key))
	h.Write(append(iv, cipherText...))
	return h.Sum(nil)
}

func (c *crypto) validMac(iv, cipherText, mac []byte) bool {
	expectedMAC := c.generateMAC(iv, cipherText)
	return hmac.Equal(mac, expectedMAC)
}

func (c *crypto) Decrypt(cipherText string) (string, error) {
	cipherByte, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return "", errors.Wrap(err, "base64.StdEncoding.DecodeString err")
	}
	if len(cipherByte) < aes.BlockSize+c.macSize {
		return "", errors.Wrap(err, "cipherText too short")
	}
	iv := cipherByte[0:aes.BlockSize]
	mac := cipherByte[aes.BlockSize : aes.BlockSize+c.macSize]
	cipherByte = cipherByte[aes.BlockSize+c.macSize:]
	if !c.validMac(iv, cipherByte, mac) {
		return "", errors.Wrap(err, "invalid cipherText")
	}

	stream := cipher.NewCFBDecrypter(c.block, iv)
	stream.XORKeyStream(cipherByte, cipherByte)
	return string(cipherByte), nil
}

func NewCryptographer(key string) (Cryptographer, error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, errors.Wrap(err, "aes.NewCipher err")
	}
	return &crypto{
		key:     key,
		macHash: sha512.New,
		macSize: sha512.Size,
		block:   block,
	}, nil
}
