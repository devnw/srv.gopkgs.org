package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"go.devnw.com/alog"
	"go.devnw.com/event"
	"go.devnw.com/gois"
	"go.devnw.com/gois/api"
	"go.devnw.com/gois/db"
)

const (
	AUDIENCE = "https://api.gopkgs.org"
	DOMAIN   = "devnw.us.auth0.com"

	PROJECT = "gopkgs-342114"

	//nolint:gosec
	TOKENKEY = "gopkgs_domain_token"

	TOKENTIMEOUT = time.Hour * 24 * 7

	EMAILVERIFICATIONCLAIM = "https://gopkgs.org/email_verified"
)

var JWKs = fmt.Sprintf("https://%s/.well-known/jwks.json", DOMAIN)
var Resolver = net.DefaultResolver

func configLogger(ctx context.Context) error {
	return alog.Global(
		ctx,
		"api.gopkgs.org",
		alog.DEFAULTTIMEFORMAT,
		time.UTC,
		0,
		[]alog.Destination{
			{
				Types:  alog.INFO | alog.DEBUG,
				Format: alog.JSON,
				Writer: os.Stdout,
			},
			{
				Types:  alog.ERROR | alog.CRIT | alog.FATAL,
				Format: alog.JSON,
				Writer: os.Stderr,
			},
		}...,
	)
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p := event.NewPublisher(ctx)

	err := configLogger(ctx)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Subscribe logger to events and errors from default publisher
	alog.Printc(ctx, p.ReadEvents(0).Interface())
	alog.Errorc(ctx, p.ReadErrors(0).Interface())

	jwks, err := url.Parse(JWKs)
	if err != nil {
		alog.Fatalf(err, "failed to parse jwks url")
		return
	}

	auth, err := api.Authenticator(ctx, jwks, EMAILVERIFICATIONCLAIM, AUDIENCE)
	if err != nil {
		alog.Fatalf(err, "failed to create authenticator")
		return
	}

	// Subscribe parent publisher to Authentication events and errors
	err = p.Events(ctx, auth.ReadEvents(0))
	if err != nil {
		alog.Fatalf(err, "failed to subscribe to authentication events")
		return
	}

	err = p.Errors(ctx, auth.ReadErrors(0))
	if err != nil {
		alog.Fatalf(err, "failed to subscribe to authentication errors")
		return
	}

	// Create the database connection
	client, err := db.New(ctx, PROJECT, TOKENKEY, TOKENTIMEOUT)
	if err != nil {
		fmt.Printf("failed to create database client: %s\n", err)
		return
	}

	defer func() {
		_ = client.Close()
	}()

	router, err := registerHandlers(client, p)
	if err != nil {
		alog.Fatalf(err, "failed to register handlers")
		return
	}

	server := &http.Server{
		Addr: ":6060",
		Handler: api.JSON(
			auth.ValidateToken(
				router,
			),
		),
	}

	alog.Printf("API server listening on %s", server.Addr)
	alog.Fatal(server.ListenAndServe())
}

func registerHandlers(client gois.DB, p *event.Publisher) (*http.ServeMux, error) {
	router := http.NewServeMux()
	router.Handle("/", http.NotFoundHandler())

	domainHandler, err := api.Domain(client, p)
	if err != nil {
		return nil, fmt.Errorf("failed to create domain handler: %s", err)
	}

	router.Handle(
		"/domains",
		domainHandler,
	)

	moduleHandler, err := api.Module(client, p)
	if err != nil {
		return nil, fmt.Errorf("failed to create module handler: %s", err)
	}
	router.Handle(
		"/modules",
		moduleHandler,
	)

	tokenHandler, err := api.Token(client, p)
	if err != nil {
		return nil, fmt.Errorf("failed to create token handler: %s", err)
	}
	router.Handle(
		"/token",
		tokenHandler,
	)

	verifyHandler, err := api.Verify(client, p, Resolver)
	if err != nil {
		return nil, fmt.Errorf("failed to create verify handler: %s", err)
	}
	router.Handle(
		"/verify",
		verifyHandler,
	)

	return router, nil
}
