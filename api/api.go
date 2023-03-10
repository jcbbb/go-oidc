package api

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/jcbbb/go-oidc/util"
)

type Error struct {
	Message    string `json:"error_description"`
	Code       string `json:"error"`
	URI        string `json:"error_uri"`
	StatusCode int    `json:"-"`
}

func (e Error) Error() string {
	return e.Message
}

type apiFunc func(w http.ResponseWriter, r *http.Request) error

func WriteJSON(w http.ResponseWriter, status int, v any) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(v)
}

func MakeHandlerFuncJSON(f apiFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := f(w, r); err != nil {
			if e, ok := err.(Error); ok {
				WriteJSON(w, e.StatusCode, e)
				return
			}
			WriteJSON(w, http.StatusInternalServerError, Error{StatusCode: http.StatusInternalServerError, Message: "internal server error", Code: "internal_error"})
		}
	}
}

func MakeHandlerFunc(f apiFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := f(w, r); err != nil {
			fmt.Printf("ERROR: %+v\n", err)
			errTo := r.URL.Query().Get("err_to")

			if len(errTo) == 0 {
				errTo = r.Referer()
			}

			if e, ok := err.(Error); ok {
				util.SetFlash(w, &util.FlashMessage{
					Kind:  util.FlashError,
					Value: []byte(e.Message),
				})

				http.Redirect(w, r, errTo, http.StatusFound)
				return
			}

			util.SetFlash(w, &util.FlashMessage{
				Kind:  util.FlashError,
				Value: []byte(err.Error()),
			})

			http.Redirect(w, r, errTo, http.StatusFound)
		}
	}
}

func ErrResourceNotFound(message, uri string) Error {
	return Error{
		StatusCode: http.StatusNotFound,
		Code:       "resource_not_found",
		Message:    message,
		URI:        uri,
	}
}

func ErrBadRequest(message, uri string) Error {
	return Error{
		StatusCode: http.StatusBadRequest,
		Code:       "invalid_request",
		Message:    message,
		URI:        uri,
	}
}

func ErrConflict(message, uri string) Error {
	return Error{
		StatusCode: http.StatusConflict,
		Code:       "conflict",
		Message:    message,
		URI:        uri,
	}
}

func ErrInternal(message, uri string) Error {
	return Error{
		StatusCode: http.StatusInternalServerError,
		Code:       "internal_server",
		Message:    message,
		URI:        uri,
	}
}
