package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/jwt"
	"go.devnw.com/event"
	"go.devnw.com/gois"
)

type newDomain struct {
	Domain string `json:"domain"`
}

func (d *newDomain) validate() error {
	if d.Domain == "" {
		return errors.New("domain is empty")
	}

	if !gois.DomainReggy.MatchString(d.Domain) {
		return errors.New("domain is invalid")
	}

	return nil
}

func Domain(c gois.DB, p *event.Publisher) (http.Handler, error) {
	if c == nil {
		return nil, &Error{
			Endpoint: "domain",
			Message:  "db is nil",
		}
	}

	if p == nil {
		return nil, &Error{
			Endpoint: "domain",
			Message:  "publisher is nil",
		}
	}

	return &domain{c, p}, nil
}

type domain struct {
	c gois.DB
	p *event.Publisher
}

func (d *domain) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var err error
	defer func() {
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)

			// Push the error to the publisher for subscribers to pick up.
			d.p.ErrorFunc(r.Context(), func() error {
				return err
			})
		}
	}()

	var t jwt.Token
	t, err = AuthToken(r.Context())
	if err != nil {
		return
	}

	switch r.Method {
	case http.MethodGet:
		err = d.Get(t, w, r)
	case http.MethodPut:
		err = d.Put(t, w, r)
	case http.MethodDelete:
		err = d.Delete(t, w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (d *domain) Put(t jwt.Token, w http.ResponseWriter, r *http.Request) error {
	domain, err := Unmarshal[newDomain](r.Body)
	if err != nil {
		return Err(r, err, "failed to unmarshal domain")
	}

	err = domain.validate()
	if err != nil {
		return Err(r, err, "failed to validate domain")
	}

	host, err := d.c.CreateDomain(r.Context(), t.Subject(), domain.Domain)
	if err != nil {
		return Err(r, err, "failed to create domain")
	}

	data, err := json.Marshal(host)
	if err != nil {
		return Err(r, err, "failed to marshal host")
	}

	_, err = w.Write(data)
	if err != nil {
		return Err(r, err, "failed to write data to response")
	}

	return nil
}

func (d *domain) Get(t jwt.Token, w http.ResponseWriter, r *http.Request) error {
	domains, err := d.c.GetDomains(r.Context(), t.Subject())
	if err != nil {
		return Err(r, err, "failed to get domains")
	}

	data, err := json.Marshal(domains)
	if err != nil {
		return Err(r, err, "failed to marshal domains")
	}

	_, err = w.Write(data)
	if err != nil {
		return Err(r, err, "failed to write data to response")
	}

	return nil
}

func (d *domain) Delete(t jwt.Token, w http.ResponseWriter, r *http.Request) error {
	id, err := uuid.Parse(r.URL.Query().Get("id"))
	if err != nil {
		return Err(r, err, "invalid id")
	}

	err = d.c.DeleteDomain(r.Context(), t.Subject(), id.String())
	if err != nil {
		return Err(r, err, "failed to delete domain")
	}

	w.WriteHeader(http.StatusNoContent)
	return nil
}
