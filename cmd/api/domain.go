package main

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/google/uuid"
	"go.devnw.com/dns"
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

	if !DomainReggy.MatchString(d.Domain) {
		return errors.New("domain is invalid")
	}

	return nil
}

type domain struct {
	c *client
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

	a, ok := r.Context().Value(authNCtxKey).(auth)
	if !ok {
		err = Err(r, err, "failed to get auth info")
	}

	switch r.Method {
	case http.MethodGet:
		err = d.Get(a, w, r)
	case http.MethodPut:
		err = d.Put(a, w, r)
	case http.MethodDelete:
		err = d.Delete(a, w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (d *domain) Put(a auth, w http.ResponseWriter, r *http.Request) error {
	domain, err := Unmarshal[newDomain](r.Body)
	if err != nil {
		return Err(r, err, "failed to unmarshal domain")
	}

	err = domain.validate()
	if err != nil {
		return Err(r, err, "failed to validate domain")
	}

	// TODO: set this up so that if a domain exists but is not validated it
	// can be migrated to a new user and be validated.
	// This should happen after the current token is expired or invalidated.
	_, err = d.c.Collection("domains").Doc(domain.Domain).Get(r.Context())
	if err == nil {
		return Err(r, err, "domain already exists")
	}

	// Generate domain challenge token
	token, err := dns.NewToken(domain.Domain, GOPKGSKEY, &timeout)
	if err != nil {
		return Err(r, err, "failed to generate token")
	}

	host := &gois.Host{
		ID:     uuid.New().String(),
		Owner:  a.id,
		Domain: domain.Domain,
		Token:  token,
	}

	_, err = d.c.Collection("domains").Doc(domain.Domain).Create(r.Context(), host)
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

func (d *domain) Get(a auth, w http.ResponseWriter, r *http.Request) error {
	domains, err := d.c.GetDomains(r.Context(), a.id)
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

func (d *domain) Delete(a auth, w http.ResponseWriter, r *http.Request) error {
	id, err := uuid.Parse(r.URL.Query().Get("id"))
	if err != nil {
		return Err(r, err, "invalid id")
	}

	err = d.c.DeleteDomain(r.Context(), a.id, id.String())
	if err != nil {
		return Err(r, err, "failed to delete domain")
	}

	w.WriteHeader(http.StatusNoContent)
	return nil
}
