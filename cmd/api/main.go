package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"time"

	"go.devnw.com/alog"
	"go.devnw.com/event"
	"go.devnw.com/gois"
	"go.devnw.com/gois/db"
)

const (
	AUDIENCE = "https://api.gopkgs.org"
	DOMAIN   = "devnw.us.auth0.com"

	//nolint:lll
	DOMAINREGEX = `^(?:(?:[a-zA-Z0-9])(?:[a-zA-Z0-9\-.]){1,61}(?:\.[a-zA-Z]{2,})+|\[(?:(?:(?:[a-fA-F0-9]){1,4})(?::(?:[a-fA-F0-9]){1,4}){7}|::1|::)\]|(?:(?:[0-9]{1,3})(?:\.[0-9]{1,3}){3}))(?::[0-9]{1,5})?$`

	PROJECT = "gopkgs-342114"

	//nolint:gosec
	TOKENKEY = "gopkgs_domain_token"

	TOKENTIMEOUT = time.Hour * 24 * 7
)

type key int

const (
	authNCtxKey key = iota
)

// Compile the regex immediately.
var DomainReggy = regexp.MustCompile(DOMAINREGEX)

type DB interface {
	GetDomains(ctx context.Context, userID string) ([]*gois.Host, error)
	GetDomain(
		ctx context.Context,
		userID string,
		domainID string,
	) (*gois.Host, error)

	CreateDomain(
		ctx context.Context,
		userID string,
		domain string,
	) (*gois.Host, error)

	DeleteDomain(
		ctx context.Context,
		userID string,
		domainID string,
	) error

	UpdateModules(
		ctx context.Context,
		userID string,
		domainID string,
		modules ...*gois.Module,
	) error

	DeleteModule(
		ctx context.Context,
		userID string,
		domainID string,
		path string,
	) error
}

func main() {
	fetchTenantKeys()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := alog.Global(
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
	if err != nil {
		fmt.Println(err)
		return
	}

	client, err := db.New(ctx, PROJECT, TOKENKEY, TOKENTIMEOUT)
	if err != nil {
		fmt.Printf("failed to create database client: %s\n", err)
		return
	}

	p := event.NewPublisher(ctx)

	alog.Printc(ctx, p.ReadEvents(0).Interface())
	alog.Errorc(ctx, p.ReadErrors(0).Interface())

	router := http.NewServeMux()
	router.Handle("/", http.NotFoundHandler())

	router.Handle(
		"/domains",
		&domain{client, p},
	)

	router.Handle(
		"/modules",
		&module{client, p},
	)

	// TODO: Add validation check and new token request
	router.Handle(
		"/token",
		&token{client, p},
	)

	routerWithCORS := JSON(handleCORS(validateToken(authInfo(router)))) // Move validate token and auth info to here

	server := &http.Server{
		Addr:    ":6060",
		Handler: routerWithCORS,
	}

	alog.Printf("API server listening on %s", server.Addr)
	alog.Fatal(server.ListenAndServe())
}
