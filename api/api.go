package api

import (
	"encoding/json"
	"net/http"
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

func MakeHandlerFunc(f apiFunc) http.HandlerFunc {
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