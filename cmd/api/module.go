package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"cloud.google.com/go/firestore"
	"go.devnw.com/event"
	"go.devnw.com/gois"
)

type moduleData struct {
	ID      string `json:"id"`
	Modules []*gois.Module
}

type module struct {
	c *client
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

	switch r.Method {
	case http.MethodPost:
		err = m.Post(w, r)
	case http.MethodDelete:
		err = m.Delete(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (m *module) Post(w http.ResponseWriter, r *http.Request) error {
	data, err := io.ReadAll(r.Body)
	if err != nil {
		return Err(r, err, http.StatusBadRequest, "failed to read body")
	}

	mdata := &moduleData{}
	err = json.Unmarshal(data, m)
	if err != nil {
		return Err(r, err, http.StatusBadRequest, "failed to unmarshal body")
	}

	ctx := r.Context()
	aInfo, ok := ctx.Value(authNCtxKey).(auth)
	if !ok {
		return Err(r, err, http.StatusUnauthorized, "failed to get auth info")
	}

	d, err := m.c.Domains(ctx, aInfo).
		Where("ID", "==", mdata.ID).
		Limit(1).
		Documents(ctx).
		Next()

	if err != nil {
		return Err(
			r,
			err,
			http.StatusInternalServerError,
			fmt.Sprintf("failed to get domain [%s]", mdata.ID),
		)
	}

	h := &gois.Host{}
	err = d.DataTo(h)
	if err != nil {
		return Err(
			r,
			err,
			http.StatusInternalServerError,
			fmt.Sprintf(
				"failed to convert data to host for domain [%s]",
				mdata.ID,
			),
		)
	}

	if h.Token.Validated == nil ||
		!h.Token.Validated.Before(h.Token.ValidateBy) {
		return Err(
			r,
			nil,
			http.StatusUnauthorized,
			fmt.Sprintf("domain [%s] not validated", mdata.ID))
	}

	updates := []firestore.Update{}
	for _, mod := range mdata.Modules {
		updates = append(
			updates,
			firestore.Update{
				Path:  fmt.Sprintf("Modules.%s", mod.Path),
				Value: mod,
			},
		)
	}

	_, err = d.Ref.Update(ctx, updates)
	if err != nil {
		return Err(
			r,
			err,
			http.StatusInternalServerError,
			fmt.Sprintf("failed to update domain [%s]", mdata.ID),
		)
	}

	data, err = json.Marshal(mdata.Modules)
	if err != nil {
		return Err(
			r,
			err,
			http.StatusInternalServerError,
			fmt.Sprintf("failed to marshal modules for domain [%s]", mdata.ID),
		)
	}

	_, err = w.Write(data)
	if err != nil {
		return Err(r, err, http.StatusInternalServerError, "failed to write response")
	}

	return nil
}

func (m *module) Delete(w http.ResponseWriter, r *http.Request) error {
	id := r.URL.Query().Get("id")
	if id == "" {
		return Err(r, nil, http.StatusBadRequest, "missing id")
	}

	mod := r.URL.Query().Get("mod")
	if mod == "" {
		return Err(r, nil, http.StatusBadRequest, "missing mod")
	}

	ctx := r.Context()
	aInfo, ok := ctx.Value(authNCtxKey).(auth)
	if !ok {
		return Err(r, nil, http.StatusUnauthorized, "failed to get auth info")
	}

	d, err := m.c.Domains(ctx, aInfo).
		Where("ID", "==", id).
		Limit(1).
		Documents(ctx).
		Next()

	if err != nil {
		return Err(
			r,
			err,
			http.StatusInternalServerError,
			fmt.Sprintf("failed to get domain [%s]", id),
		)
	}

	_, err = d.Ref.Update(ctx, []firestore.Update{
		{Path: fmt.Sprintf("Modules.%s", mod), Value: firestore.Delete},
	})
	if err != nil {
		return Err(
			r,
			err,
			http.StatusInternalServerError,
			fmt.Sprintf("failed to update domain [%s]", id),
		)
	}

	w.WriteHeader(http.StatusNoContent)
	return nil
}
