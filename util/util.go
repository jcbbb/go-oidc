package util

import (
	"crypto/rand"
	"encoding/base64"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type FlashMessageKind int

const (
	FlashWarning FlashMessageKind = iota + 1
	FlashSuccess
	FlashError
	flashName = "flash"
)

type FlashMessage struct {
	Value []byte
	Kind  FlashMessageKind
}

func Contains[T any](s []T, test func(T) bool) bool {
	for _, v := range s {
		if test(v) {
			return true
		}
	}
	return false
}

var table = [...]byte{'1', '2', '3', '4', '5', '6', '7', '8', '9', '0'}

func RandN(max uint) string {
	b := make([]byte, 6)
	n, err := io.ReadAtLeast(rand.Reader, b, 6)
	if n != 6 {
		panic(err)
	}

	for i := 0; i < len(b); i++ {
		b[i] = table[int(b[i])%len(table)]
	}

	return string(b)
}

func Filter[T any](slice []T, test func(T) bool) (ret []T) {
	for _, s := range slice {
		if test(s) {
			ret = append(ret, s)
		}
	}
	return
}

func SetFlash(w http.ResponseWriter, flash *FlashMessage) {
	value := append([]byte(strconv.Itoa(int(flash.Kind))+"|"), flash.Value[:]...)
	c := &http.Cookie{Name: flashName, Value: base64.URLEncoding.EncodeToString(value), MaxAge: 1}
	http.SetCookie(w, c)
}

func GetFlash(w http.ResponseWriter, r *http.Request) (*FlashMessage, error) {
	c, err := r.Cookie(flashName)

	if err != nil {
		switch err {
		case http.ErrNoCookie:
			return nil, nil
		default:
			return nil, err
		}
	}

	value, err := base64.URLEncoding.DecodeString(c.Value)

	if err != nil {
		return nil, err
	}

	parts := strings.Split(string(value), "|")

	kind, err := strconv.Atoi(parts[0])
	if err != nil {
		return nil, err
	}

	msg := &FlashMessage{
		Value: []byte(parts[1]),
		Kind:  FlashMessageKind(kind),
	}

	http.SetCookie(w, &http.Cookie{Name: flashName, Expires: time.Unix(0, 0), MaxAge: -1})

	return msg, nil
}
