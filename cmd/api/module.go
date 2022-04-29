package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/google/uuid"
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

//nolint:dupl
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

	a, ok := r.Context().Value(authNCtxKey).(auth)
	if !ok {
		err = Err(r, err, "failed to get auth info")
	}

	switch r.Method {
	case http.MethodPost:
		err = m.Post(a, w, r)
	case http.MethodDelete:
		err = m.Delete(a, w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (m *module) Post(a auth, w http.ResponseWriter, r *http.Request) error {
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
	err = m.c.UpdateModules(r.Context(), a.id, mdata.ID, mdata.Modules...)
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

func (m *module) Delete(a auth, w http.ResponseWriter, r *http.Request) error {
	id, err := uuid.Parse(r.URL.Query().Get("id"))
	if err != nil {
		return Err(r, err, "invalid id")
	}

	mod := r.URL.Query().Get("mod")
	if mod == "" {
		return Err(r, nil, "missing mod")
	}

	err = m.c.DeleteModule(r.Context(), a.id, id.String(), mod)
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
