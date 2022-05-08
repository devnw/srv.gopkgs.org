package api

import (
	"net/http"

	"go.devnw.com/alog"
)

// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Origin
func CORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		headers := rw.Header()

		// Allow-Origin header shall be part of ALL the responses
		headers.Add("Access-Control-Allow-Origin", "*")
		if req.Method != http.MethodOptions {
			next.ServeHTTP(rw, req)
			return
		}

		// process an HTTP OPTIONS preflight request
		headers.Add("Access-Control-Allow-Headers", "Authorization")
		rw.WriteHeader(http.StatusNoContent)
		_, err := rw.Write(nil)
		if err != nil {
			alog.Println(err, "http response (options) write error")
		}
	})
}
