package main

import (
	"encoding/json"
	"io"
	"net/http"
)

func JSON(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		next.ServeHTTP(rw, req)
	})
}

func Unmarshal[T any](rc io.ReadCloser) (T, error) {
	defer rc.Close()
	var t T

	data, err := io.ReadAll(rc)
	if err != nil {
		return t, err
	}

	err = json.Unmarshal(data, &t)
	if err != nil {
		return t, err
	}

	return t, nil
}
