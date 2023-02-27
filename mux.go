package main

import (
	"net/http"
)

type Mux struct {
	*http.ServeMux
}

func NewMux() *Mux {
	serveMux := http.NewServeMux()
	return &Mux{
		serveMux,
	}
}

func matchMethod(method string, handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != method {
			w.WriteHeader(405)
			return
		}

		handler(w, r)
	}
}

func (m *Mux) Get(pattern string, handler http.HandlerFunc) {
	m.HandleFunc(pattern, matchMethod(http.MethodGet, handler))
}

func (m *Mux) Post(pattern string, handler http.HandlerFunc) {
	m.HandleFunc(pattern, matchMethod(http.MethodPost, handler))
}

func (m *Mux) Delete(pattern string, handler http.HandlerFunc) {
	m.HandleFunc(pattern, matchMethod(http.MethodDelete, handler))
}

func (m *Mux) Patch(pattern string, handler http.HandlerFunc) {
	m.HandleFunc(pattern, matchMethod(http.MethodPatch, handler))
}
