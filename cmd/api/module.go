package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/jwt"
	"go.devnw.com/event"
	"go.devnw.com/gois"
)

type moduleData struct {
	ID      string `json:"id"`
	Modules []*gois.Module
}

type module struct {
	c DB
	p *event.Publisher
}


func (m *module) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var err error
	defer func() {
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)

			// Push the error to the publisher for subscribers to pick up.
			m.p.ErrorFunc(r.Context(), func() error {
				return err
			})
		}
	}()

	var t jwt.Token
	t, err = Token(r.Context())
	if err != nil {
		return
	}

	switch r.Method {
	case http.MethodPost:
		err = m.Post(t, w, r)
	case http.MethodDelete:
		err = m.Delete(t, w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (m *module) Post(
	t jwt.Token,
	w http.ResponseWriter,
	r *http.Request,
) error {
	data, err := io.ReadAll(r.Body)
	if err != nil {
		return Err(r, err, "failed to read body")
	}

	mdata := &moduleData{}
	err = json.Unmarshal(data, m)
	if err != nil {
		return Err(r, err, "failed to unmarshal body")
	}

	// Update the domain modules with the modules from the request.
	err = m.c.UpdateModules(r.Context(), t.Subject(), mdata.ID, mdata.Modules...)
	if err != nil {
		return Err(r, err, "failed to update modules")
	}

	data, err = json.Marshal(mdata.Modules)
	if err != nil {
		return Err(
			r,
			err,
			fmt.Sprintf("failed to marshal modules for domain [%s]", mdata.ID),
		)
	}

	_, err = w.Write(data)
	if err != nil {
		return Err(r, err, "failed to write response")
	}

	return nil
}

func (m *module) Delete(
	t jwt.Token,
	w http.ResponseWriter,
	r *http.Request,
) error {
	id, err := uuid.Parse(r.URL.Query().Get("id"))
	if err != nil {
		return Err(r, err, "invalid id")
	}

	mod := r.URL.Query().Get("mod")
	if mod == "" {
		return Err(r, nil, "missing mod")
	}

	err = m.c.DeleteModule(r.Context(), t.Subject(), id.String(), mod)
	if err != nil {
		return Err(
			r,
			err,
			fmt.Sprintf("failed to update domain [%s]", id),
		)
	}

	w.WriteHeader(http.StatusNoContent)
	return nil
}
