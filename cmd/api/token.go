package main

import (
	"net/http"

	"go.devnw.com/event"
)

type token struct {
	c *client
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

	a, ok := r.Context().Value(authNCtxKey).(auth)
	if !ok {
		err = Err(r, err, "failed to get auth info")
	}

	switch r.Method {
	case http.MethodPost:
		err = t.Post(a, w, r)
	case http.MethodDelete:
		err = t.Delete(a, w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (t *token) Post(a auth, w http.ResponseWriter, r *http.Request) error {
	return nil
}

func (t *token) Delete(a auth, w http.ResponseWriter, r *http.Request) error {
	return nil
}
