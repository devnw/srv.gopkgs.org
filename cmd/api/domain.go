package main

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/google/uuid"
	"go.devnw.com/dns"
	"go.devnw.com/event"
	"go.devnw.com/gois"
	"google.golang.org/api/iterator"
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

	switch r.Method {
	case http.MethodGet:
		err = d.Get(w, r)
	case http.MethodPut:
		err = d.Put(w, r)
	case http.MethodDelete:
		err = d.Delete(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (d *domain) Put(w http.ResponseWriter, r *http.Request) error {
	domain, err := Unmarshal[newDomain](r.Body)
	if err != nil {
		return Err(r, err, http.StatusBadRequest, "failed to unmarshal domain")
	}

	ctx := r.Context()
	aInfo, ok := ctx.Value(authNCtxKey).(auth)
	if !ok {
		return Err(r, err, http.StatusUnauthorized, "failed to get auth info")
	}

	err = domain.validate()
	if err != nil {
		return Err(r, err, http.StatusBadRequest, "failed to validate domain")
	}

	// TODO: set this up so that if a domain exists but is not validated it
	// can be migrated to a new user and be validated.
	// This should happen after the current token is expired or invalidated.
	_, err = d.c.Collection("domains").Doc(domain.Domain).Get(ctx)
	if err == nil {
		return Err(r, err, http.StatusBadRequest, "domain already exists")
	}

	// Generate domain challenge token
	token, err := dns.NewToken(domain.Domain, GOPKGSKEY, &timeout)
	if err != nil {
		return Err(r, err, http.StatusInternalServerError, "failed to generate token")
	}

	host := &gois.Host{
		ID:     uuid.New().String(),
		Owner:  aInfo.id,
		Domain: domain.Domain,
		Token:  token,
	}

	_, err = d.c.Collection("domains").Doc(domain.Domain).Create(ctx, host)
	if err != nil {
		return Err(r, err, http.StatusInternalServerError, "failed to create domain")
	}

	data, err := json.Marshal(host)
	if err != nil {
		return Err(r, err, http.StatusInternalServerError, "failed to marshal host")
	}

	// TODO: check err?
	_, _ = w.Write(data)
	return nil
}

func (d *domain) Get(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	aInfo, ok := ctx.Value(authNCtxKey).(auth)
	if !ok {
		return Err(r, nil, http.StatusUnauthorized, "failed to get auth info")
	}

	domains := []*gois.Host{}
	iter := d.c.Domains(ctx, aInfo).Documents(ctx)
	for {
		doc, err := iter.Next()
		if err == iterator.Done {
			break
		}

		if err != nil {
			return Err(r, err, http.StatusInternalServerError, "failed to iterate get domains")
		}

		h := &gois.Host{}
		err = doc.DataTo(h)
		if err != nil {
			d.p.ErrorFunc(r.Context(), func() error {
				return Err(r, err, http.StatusInternalServerError, "failed to unmarshal domain")
			})

			continue
		}

		domains = append(domains, h)
	}

	data, err := json.Marshal(domains)
	if err != nil {
		return Err(r, err, http.StatusInternalServerError, "failed to marshal domains")
	}

	// TODO: check err?
	_, _ = w.Write(data)
	return nil
}

func (d *domain) Delete(w http.ResponseWriter, r *http.Request) error {
	id := r.URL.Query().Get("id")
	if id == "" {
		return Err(r, nil, http.StatusBadRequest, "missing id")
	}

	ctx := r.Context()
	aInfo, ok := ctx.Value(authNCtxKey).(auth)
	if !ok {
		return Err(r, nil, http.StatusUnauthorized, "failed to get auth info")
	}

	domain, err := d.c.Domains(ctx, aInfo).
		Where("ID", "==", id).
		Limit(1).
		Documents(ctx).
		Next()

	if err != nil {
		return Err(r, err, http.StatusInternalServerError, "failed to get domain")
	}

	_, err = domain.Ref.Delete(ctx)
	if err != nil {
		return Err(r, err, http.StatusInternalServerError, "failed to delete domain")
	}

	w.WriteHeader(http.StatusNoContent)
	return nil
}
