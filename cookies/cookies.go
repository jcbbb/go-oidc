package cookies

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

var (
	ErrInvalidValue = errors.New("invalid value")
)

type SecureCookie struct {
	secretKey []byte
}

func (sc *SecureCookie) WriteSigned(w http.ResponseWriter, cookie http.Cookie) error {
	block, err := aes.NewCipher(sc.secretKey)

	if err != nil {
		return err
	}

	aesGCM, err := cipher.NewGCM(block)

	if err != nil {
		return err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)

	if err != nil {
		return err
	}

	plaintext := fmt.Sprintf("%s:%s", cookie.Name, cookie.Value)

	encryptedValue := aesGCM.Seal(nonce, nonce, []byte(plaintext), nil)

	cookie.Value = string(encryptedValue)

	http.SetCookie(w, &cookie)
	return nil
}

func (sc *SecureCookie) ReadEncrypted(r *http.Request, name string) (string, error) {
	cookie, err := r.Cookie(name)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(sc.secretKey)

	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)

	if err != nil {
		return "", err
	}

	nonceSize := aesGCM.NonceSize()

	if len(cookie.Value) < nonceSize {
		return "", ErrInvalidValue
	}

	nonce := cookie.Value[:nonceSize]
	ciphertext := cookie.Value[nonceSize:]

	plaintext, err := aesGCM.Open(nil, []byte(nonce), []byte(ciphertext), nil)

	if err != nil {
		return "", ErrInvalidValue
	}

	expectedName, value, ok := strings.Cut(string(plaintext), "")

	if !ok {
		return "", ErrInvalidValue
	}

	if expectedName != name {
		return "", ErrInvalidValue
	}

	return value, nil
}
