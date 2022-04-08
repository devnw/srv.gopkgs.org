package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/spf13/cobra"
	"go.devnw.com/alog"
	"go.devnw.com/event"
	"go.devnw.com/gois"
	"go.devnw.com/gois/api"
	"go.devnw.com/gois/db"
)

const (
	DEFAULTTIMEOUT = time.Hour * 24 * 7
)

var version string
var Resolver = net.DefaultResolver

func configLogger(ctx context.Context, prefix string) error {
	return alog.Global(
		ctx,
		prefix,
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
	var (
		verbose             bool
		gcpProject          string
		dnsChallengeKey     string
		dnsChallengeTimeout time.Duration
		logPrefix           string
		audience            string
		domain              string
		emailClaim          string
	)

	root := &cobra.Command{
		Use:     "import-server [flags]",
		Short:   "import server for gopkgs",
		Version: version,
		Run: exec(
			&verbose,
			&gcpProject,
			&dnsChallengeKey,
			&dnsChallengeTimeout,
			&logPrefix,
			&audience,
			&domain,
			&emailClaim,
		),
	}

	root.PersistentFlags().BoolVarP(
		&verbose,
		"verbose", "v", false, "enable global verbose logging")
	root.PersistentFlags().StringVarP(
		&gcpProject,
		"gcp-project", "p", "", "gcp project id")
	root.PersistentFlags().StringVarP(
		&dnsChallengeKey,
		"dns-key", "k", "gopkgs_domain_token", "dns challenge key prefix")

	root.PersistentFlags().DurationVar(
		&dnsChallengeTimeout,
		"dns-token-timeout", DEFAULTTIMEOUT, "enable global verbose logging")

	root.PersistentFlags().StringVar(
		&logPrefix,
		"log-prefix", "srv.gopkgs.org", "log prefix")

	root.PersistentFlags().StringVar(
		&audience,
		"audience", "https://api.gopkgs.org", "Auth0 Audience")

	root.PersistentFlags().StringVar(
		&domain,
		"domain", "devnw.us.auth0.com", "Auth0 Domain")

	root.PersistentFlags().StringVar(
		&emailClaim,
		"email-claim", "https://gopkgs.org/email_verified", "Email verification claim")

	err := root.Execute()
	if err != nil {
		alog.Fatal(err)
		os.Exit(1)
	}
}

func exec(
	verbose *bool,
	gcpProject *string,
	dnsChallengeKey *string,
	dnsChallengeTimeout *time.Duration,
	logPrefix *string,
	audience *string,
	domain *string,
	emailClaim *string,
) func(cmd *cobra.Command, _ []string) {
	var JWKs = fmt.Sprintf("https://%s/.well-known/jwks.json", *domain)
	return func(cmd *cobra.Command, _ []string) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		p := event.NewPublisher(ctx)

		err := configLogger(ctx, *logPrefix)
		if err != nil {
			fmt.Println(err)
			return
		}

		if *verbose {
			// Subscribe logger to events and errors from default publisher
			alog.Printc(ctx, p.ReadEvents(0).Interface())
		}

		alog.Errorc(ctx, p.ReadErrors(0).Interface())

		jwks, err := url.Parse(JWKs)
		if err != nil {
			alog.Fatalf(err, "failed to parse jwks url")
			return
		}

		auth, err := api.Authenticator(ctx, jwks, *emailClaim, *audience)
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
		client, err := db.New(
			ctx,
			*gcpProject,
			*dnsChallengeKey,
			*dnsChallengeTimeout,
		)
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
