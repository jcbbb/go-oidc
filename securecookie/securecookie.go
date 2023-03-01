package securecookie

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	_ "github.com/joho/godotenv/autoload"
)

var (
	ErrInvalidValue = errors.New("invalid value")
	sc              SecureCookie
	SidCookieName   string
	SidsCookieName  string
)

type SecureCookie struct {
	secretKey []byte
}

func init() {
	secret, _ := hex.DecodeString(os.Getenv("COOKIE_SECRET"))
	SidCookieName = os.Getenv("SID_COOKIE_NAME")
	SidsCookieName = os.Getenv("SIDS_COOKIE_NAME")
	sc.secretKey = secret
}

func New(secretKey []byte) *SecureCookie {
	return &SecureCookie{
		secretKey: secretKey,
	}
}

func Encode(name, value string) (string, error) {
	block, err := aes.NewCipher(sc.secretKey)

	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)

	if err != nil {
		return "", nil
	}

	nonce := make([]byte, aesGCM.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)

	if err != nil {
		return "", nil
	}

	plaintext := fmt.Sprintf("%s:%s", name, value)

	encryptedValue := aesGCM.Seal(nonce, nonce, []byte(plaintext), nil)

	return base64.StdEncoding.EncodeToString(encryptedValue), nil
}

func Decode(cookie *http.Cookie) (string, error) {
	if len(cookie.Value) == 0 {
		return "", nil
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
	cookieValue, err := base64.StdEncoding.DecodeString(cookie.Value)
	if err != nil {
		return "", ErrInvalidValue
	}

	if len(cookieValue) < nonceSize {
		return "", ErrInvalidValue
	}

	nonce := cookieValue[:nonceSize]
	ciphertext := cookieValue[nonceSize:]

	plaintext, err := aesGCM.Open(nil, []byte(nonce), []byte(ciphertext), nil)

	if err != nil {
		return "", ErrInvalidValue
	}

	expectedName, value, ok := strings.Cut(string(plaintext), ":")

	if !ok {
		return "", ErrInvalidValue
	}

	if expectedName != cookie.Name {
		return "", ErrInvalidValue
	}

	return value, nil
}
