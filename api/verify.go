package api

import (
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/jwt"
	"go.devnw.com/dns"
	"go.devnw.com/event"
	"go.devnw.com/gois"
)

func Verify(c gois.DB, p *event.Publisher, r dns.Resolver) (http.Handler, error) {
	if c == nil {
		return nil, &Error{
			Endpoint: "verify",
			Message:  "db is nil",
		}
	}

	if p == nil {
		return nil, &Error{
			Endpoint: "verify",
			Message:  "publisher is nil",
		}
	}

	if r == nil {
		return nil, &Error{
			Endpoint: "verify",
			Message:  "nil resolver",
		}
	}

	return &verify{c, p, r}, nil
}

type verify struct {
	c        gois.DB
	p        *event.Publisher
	resolver dns.Resolver
}

//nolint:dupl
func (v *verify) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var err error
	defer func() {
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)

			// Push the error to the publisher for subscribers to pick up.
			v.p.ErrorFunc(r.Context(), func() error {
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
		err = v.Get(jtok, w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (v *verify) Get(jtok jwt.Token, w http.ResponseWriter, r *http.Request) error {
	id, err := uuid.Parse(r.URL.Query().Get("id"))
	if err != nil {
		return Err(r, err, "invalid id")
	}

	host, err := v.c.GetDomainForUser(r.Context(), jtok.Subject(), id.String())
	if err != nil {
		return Err(r, err, "failed to get domain")
	}

	if host.Token == nil {
		return Err(r, err, "no token for domain")
	}

	if host.Token.Validated != nil {
		return nil
	}

	if host.Token.Updated != nil &&
		!host.Token.Updated.Add(time.Hour).Before(time.Now()) {
		return Err(
			r,
			err,
			"too many verification attempts; limited to 1 per hour",
		)
	}

	if host.Token.ValidateBy.Before(time.Now()) {
		return Err(r, err, "token has expired")
	}

	err = host.Token.Verify(r.Context(), v.resolver)
	if err != nil {
		err2 := v.c.UpdateDomainToken(
			r.Context(),
			jtok.Subject(),
			id.String(),
			nil,
		)
		if err2 != nil {
			return Err(r, Err(r, err, "failed to verify token"), err2.Error())
		}

		return Err(r, err, "failed to verify token")
	}

	validated := time.Now()

	// Update the database
	return v.c.UpdateDomainToken(
		r.Context(),
		jtok.Subject(),
		id.String(),
		&validated,
	)
}
