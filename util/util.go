package util

import (
	"encoding/base64"
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
