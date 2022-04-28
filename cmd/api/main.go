package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"time"

	"cloud.google.com/go/firestore"
	"go.devnw.com/alog"
	"go.devnw.com/event"
)

const (
	AUDIENCE = "https://api.gopkgs.org"
	DOMAIN   = "devnw.us.auth0.com"

	//nolint:lll
	DOMAINREGEX = `^(?:(?:[a-zA-Z0-9])(?:[a-zA-Z0-9\-.]){1,61}(?:\.[a-zA-Z]{2,})+|\[(?:(?:(?:[a-fA-F0-9]){1,4})(?::(?:[a-fA-F0-9]){1,4}){7}|::1|::)\]|(?:(?:[0-9]{1,3})(?:\.[0-9]{1,3}){3}))(?::[0-9]{1,5})?$`

	GOPKGSKEY = "gopkgs_domain_token"
)

type key int

const (
	authNCtxKey key = iota
)

var timeout = time.Hour * 24 * 7

// Compile the regex immediately.
var DomainReggy = regexp.MustCompile(DOMAINREGEX)

type client struct {
	*firestore.Client
}

func (c *client) Domains(ctx context.Context, a auth) firestore.Query {
	return c.Collection("domains").Where("Owner", "==", a.id)
}

func createClient(ctx context.Context) (*client, error) {
	// Sets your Google Cloud Platform project ID.
	projectID := "gopkgs-342114"

	c, err := firestore.NewClient(ctx, projectID)
	if err != nil {
		return nil, err
	}
	// Close client when done with
	// defer client.Close()
	return &client{c}, nil
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

	client, err := createClient(ctx)
	if err != nil {
		fmt.Printf("failed to create client: %s\n", err)
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
