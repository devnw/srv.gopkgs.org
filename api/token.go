package api

import (
	"encoding/json"
	"net/http"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/jwt"
	"go.devnw.com/event"
	"go.devnw.com/gois"
)

func Token(c gois.DB, p *event.Publisher) (http.Handler, error) {
	if c == nil {
		return nil, &Error{
			Endpoint: "token",
			Message:  "db is nil",
		}
	}

	if p == nil {
		return nil, &Error{
			Endpoint: "token",
			Message:  "publisher is nil",
		}
	}

	return &token{c, p}, nil
}

type token struct {
	c gois.DB
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
	jtok, err = AuthToken(r.Context())
	if err != nil {
		return
	}

	switch r.Method {
	case http.MethodGet:
		err = t.Get(jtok, w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (t *token) Get(jtok jwt.Token, w http.ResponseWriter, r *http.Request) error {
	id, err := uuid.Parse(r.URL.Query().Get("id"))
	if err != nil {
		return Err(r, err, "invalid id")
	}

	token, err := t.c.NewDomainToken(r.Context(), jtok.Subject(), id.String())
	if err != nil {
		return Err(r, err, "failed to get domain")
	}

	if token == nil {
		return Err(r, err, "no token for domain")
	}

	data, err := json.Marshal(token)
	if err != nil {
		return Err(r, err, "failed to marshal token")
	}

	_, err = w.Write(data)
	return err
}
