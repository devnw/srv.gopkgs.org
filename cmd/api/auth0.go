package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	"go.devnw.com/alog"
)

const (
	corsAllowedDomain = "http://localhost:8080"
	authHeader        = "Authorization"
	ctxTokenKey       = "Auth0Token"
	authPrefix        = "Bearer "
)

var (
	tenantKeys jwk.Set
)

type message struct {
	Message string `json:"message"`
}

func sendMessage(rw http.ResponseWriter, data *message) {
	bytes, err := json.Marshal(data)
	if err != nil {
		alog.Print("json conversion error", err)
		return
	}
	_, err = rw.Write(bytes)
	if err != nil {
		alog.Print("http response write error", err)
	}
}

func handleCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		headers := rw.Header()

		// Allow-Origin header shall be part of ALL the responses
		headers.Add("Access-Control-Allow-Origin", corsAllowedDomain)
		if req.Method != http.MethodOptions {
			next.ServeHTTP(rw, req)
			return
		}

		// process an HTTP OPTIONS preflight request
		headers.Add("Access-Control-Allow-Headers", "Authorization")
		headers.Add("Access-Control-Allow-Headers", "Content-Type")
		rw.WriteHeader(http.StatusNoContent)

		_, err := rw.Write(nil)
		if err != nil {
			alog.Print("http response (options) write error", err)
		}
	})
}

// validateToken middleware verifies a valid Auth0 JWT token being present in the request.
func validateToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		token, err := extractToken(req)
		if err != nil {
			fmt.Printf("failed to parse payload: %s\n", err)
			rw.WriteHeader(http.StatusUnauthorized)
			sendMessage(rw, &message{err.Error()})
			return
		}

		next.ServeHTTP(
			rw,
			req.WithContext(
				context.WithValue(
					req.Context(),
					ctxTokenKey,
					token,
				),
			),
		)
	})
}

// extractToken parses the Authorization HTTP header for valid JWT token and
// validates it with AUTH0 JWK keys. Also verifies if the audience present in
// the token matches with the designated audience as per current configuration.
func extractToken(req *http.Request) (jwt.Token, error) {
	authorization := req.Header.Get(authHeader)
	if authorization == "" {
		return nil, errors.New("authorization header missing")
	}

	if !strings.HasPrefix(authorization, authPrefix) {
		return nil, errors.New("malformed authorization header")
	}

	return jwt.Parse(
		[]byte(strings.TrimPrefix(authorization, authPrefix)),
		jwt.WithKeySet(tenantKeys),
		jwt.WithValidate(true),
		jwt.WithAudience(AUDIENCE),
	)
}

// fetchTenantKeys fetch and parse the tenant JSON Web Keys (JWK). The keys
// are used for JWT token validation during requests authorization.
func fetchTenantKeys() {
	set, err := jwk.Fetch(context.Background(),
		fmt.Sprintf("https://%s/.well-known/jwks.json", DOMAIN))
	if err != nil {
		alog.Fatalf(err, "failed to parse tenant json web keys")
	}
	tenantKeys = set
}

type auth struct {
	email string
	id    string
}

func authInfo(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		token, err := extractToken(req)
		if err != nil {
			fmt.Printf("failed to parse payload: %s\n", err)
			rw.WriteHeader(http.StatusUnauthorized)
			sendMessage(rw, &message{err.Error()})
			return
		}

		e, ok := token.PrivateClaims()["https://gopkgs.org/email"]
		if !ok {
			fmt.Printf("failed to find email claim\n")
			rw.WriteHeader(http.StatusUnauthorized)
			sendMessage(rw, &message{"failed to find email claim"})
			return
		}

		ev, ok := token.PrivateClaims()["https://gopkgs.org/email_verified"]
		if !ok {
			fmt.Printf("failed to find email claim\n")
			rw.WriteHeader(http.StatusUnauthorized)
			sendMessage(rw, &message{"failed to find email claim"})
			return
		}

		verified, ok := ev.(bool)
		if !ok || !verified {
			fmt.Printf("email not verified\n")
			rw.WriteHeader(http.StatusUnauthorized)
			sendMessage(rw, &message{"email not verified"})
			return
		}

		email, ok := e.(string)
		if !ok {
			fmt.Printf("failed to convert email claim\n")
			rw.WriteHeader(http.StatusUnauthorized)
			sendMessage(rw, &message{"failed to convert email claim"})
			return
		}

		ctxWithToken := context.WithValue(req.Context(), authNCtxKey, auth{
			email: email,
			id:    token.Subject(),
		})

		next.ServeHTTP(rw, req.WithContext(ctxWithToken))
	})
}
