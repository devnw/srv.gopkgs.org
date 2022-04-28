package main

import (
	"net/http"

	"go.devnw.com/event"
)

type token struct {
	c *client
	p *event.Publisher
}

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

	switch r.Method {
	case http.MethodPost:
		err = t.Post(w, r)
	case http.MethodDelete:
		err = t.Delete(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (t *token) Post(w http.ResponseWriter, r *http.Request) error {
	return nil
}

func (t *token) Delete(w http.ResponseWriter, r *http.Request) error {
	return nil
}
