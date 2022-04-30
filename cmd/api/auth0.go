package main

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	"go.devnw.com/event"
)

type AUTHKEY string

const (
	authHeader  = "Authorization"
	ctxTokenKey = AUTHKEY("Auth0Token")
	authPrefix  = "Bearer "
)

type Authentication struct {
	*event.Publisher
	keys       jwk.Set
	emailClaim string
}

func Authenticator(
	ctx context.Context,
	jwksrc *url.URL,
	emailClaim string,
) (*Authentication, error) {
	// fetch and parse the tenant JSON Web Keys (JWK). The keys are used for JWT
	// token validation during requests authorization.
	jwks, err := jwk.Fetch(context.Background(), jwksrc.String())
	if err != nil {
		return nil, err
	}

	return &Authentication{event.NewPublisher(ctx), jwks, emailClaim}, nil
}

// ValidateToken middleware verifies a valid Auth0 JWT token being present in the request.
func (a *Authentication) ValidateToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		defer func() {
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)

				// Push the error to the publisher for subscribers to pick up.
				a.ErrorFunc(r.Context(), func() error {
					return err
				})
			}
		}()

		var token jwt.Token
		token, err = a.ExtractToken(r)
		if err != nil {
			err = Err(r, err, "AuthN: failed to extract auth token")
			return
		}

		ev, ok := token.PrivateClaims()[a.emailClaim]
		if !ok {
			err = Err(r, err, "AuthN: failed to find email verification claim")
			return
		}

		verified, ok := ev.(bool)
		if !ok || !verified {
			err = Err(r, err, "AuthN: email not verified")
			return
		}

		next.ServeHTTP(
			w,
			r.WithContext(
				context.WithValue(
					r.Context(),
					ctxTokenKey,
					token,
				),
			),
		)
	})
}

func Token(ctx context.Context) (jwt.Token, error) {
	token, ok := ctx.Value(ctxTokenKey).(jwt.Token)
	if !ok {
		return nil, errors.New("failed to get auth token")
	}

	return token, nil
}

// ExtractToken parses the Authorization HTTP header for valid JWT token and
// validates it with AUTH0 JWK keys. Also verifies if the audience present in
// the token matches with the designated audience as per current configuration.
func (a *Authentication) ExtractToken(r *http.Request) (jwt.Token, error) {
	authorization := r.Header.Get(authHeader)
	if authorization == "" {
		return nil, errors.New("authorization header missing")
	}

	if !strings.HasPrefix(authorization, authPrefix) {
		return nil, errors.New("malformed authorization header")
	}

	return jwt.Parse(
		[]byte(strings.TrimPrefix(authorization, authPrefix)),
		jwt.WithKeySet(a.keys),
		jwt.WithValidate(true),
		jwt.WithAudience(AUDIENCE),
	)
}
