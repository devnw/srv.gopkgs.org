package api

import (
	"net/http"
	"strings"

	"go.devnw.com/alog"
)

var allowed = []string{
	"https://gopkgs.org",
	"http://localhost:3000",
}

var allowedMethods = []string{
	http.MethodGet,
	http.MethodPost,
	http.MethodPut,
	http.MethodDelete,
	http.MethodOptions,
}

// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Origin
func CORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		for _, origin := range allowed {
			o := req.Header.Get("Origin")
			if strings.HasPrefix(o, origin) {
				rw.Header().Add("Access-Control-Allow-Origin", origin)
				alog.Printf("Added CORS Header For: %s", origin)
				break
			}
		}

		if req.Method != http.MethodOptions {
			next.ServeHTTP(rw, req)
			return
		}

		// process an HTTP OPTIONS preflight request
		rw.Header().Add(
			"Access-Control-Allow-Headers",
			"Authorization,Content-Type",
		)

		// add the allowed methods
		rw.Header().Add(
			"Access-Control-Allow-Methods",
			strings.Join(allowedMethods, ","),
		)

		rw.WriteHeader(http.StatusNoContent)
		alog.Printf("CORS preflight request for %s completed", req.Header.Get("Origin"))
	})
}
