package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"time"

	"go.devnw.com/alog"
	"go.devnw.com/dns"
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

	EMAILVERIFICATIONCLAIM = "https://gopkgs.org/email_verified"
)

// Compile the regex immediately.
var DomainReggy = regexp.MustCompile(DOMAINREGEX)
var JWKs = fmt.Sprintf("https://%s/.well-known/jwks.json", DOMAIN)
var Resolver = net.DefaultResolver

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

	NewDomainToken(
		ctx context.Context,
		userID string,
		domainID string,
	) (*dns.Token, error)

	UpdateDomainToken(
		ctx context.Context,
		userID string,
		domainID string,
		validated *time.Time,
	) error
}

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

	auth, err := Authenticator(ctx, jwks, EMAILVERIFICATIONCLAIM)
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

	router.Handle(
		"/token",
		&token{client, p},
	)

	router.Handle(
		"/verify",
		&verify{client, p, Resolver},
	)

	server := &http.Server{
		Addr: ":6060",
		Handler: JSON(
			auth.ValidateToken(
				router,
			),
		),
	}

	alog.Printf("API server listening on %s", server.Addr)
	alog.Fatal(server.ListenAndServe())
}
