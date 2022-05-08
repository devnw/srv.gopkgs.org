package api

import (
	"net/http"

	"go.devnw.com/alog"
)

// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Origin
func CORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		// Allow-Origin header shall be part of ALL the responses
		rw.Header().Add("Access-Control-Allow-Origin", "*")
		if req.Method != http.MethodOptions {
			next.ServeHTTP(rw, req)
			return
		}

		// process an HTTP OPTIONS preflight request
		rw.Header().Add(
			"Access-Control-Allow-Headers",
			"Authorization,Content-Type",
		)
		rw.WriteHeader(http.StatusNoContent)
		alog.Println("CORS preflight request")
	})
}
