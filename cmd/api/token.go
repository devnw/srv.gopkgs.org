package main

import (
	"net/http"

	"github.com/lestrrat-go/jwx/jwt"
	"go.devnw.com/event"
)

type token struct {
	c DB
	p *event.Publisher
}

//nolint:dupl
func (t *token) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var err error
	defer func() {
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)

			// Push the error to the publisher for subscribers to pick up.
			t.p.ErrorFunc(r.Context(), func() error {
				return err
			})
		}
	}()

	var jtok jwt.Token
	jtok, err = Token(r.Context())
	if err != nil {
		return
	}

	switch r.Method {
	case http.MethodPost:
		err = t.Post(jtok, w, r)
	case http.MethodDelete:
		err = t.Delete(jtok, w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (t *token) Post(jtok jwt.Token, w http.ResponseWriter, r *http.Request) error {
	return nil
}

func (t *token) Delete(jtok jwt.Token, w http.ResponseWriter, r *http.Request) error {
	return nil
}
