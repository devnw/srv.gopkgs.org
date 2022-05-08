package api

import (
	"fmt"
	"net/http"

	"go.devnw.com/alog"
)

func PanicHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		defer func() {
			r := recover()
			if r != nil {
				alog.Crit(Err(
					req,
					fmt.Errorf("%s", r),
					"panic while serving request",
				))
				w.WriteHeader(http.StatusInternalServerError)
			}
		}()

		next.ServeHTTP(w, req)
	})
}
