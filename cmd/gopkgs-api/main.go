package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"go.devnw.com/alog"
	"go.devnw.com/event"
	"go.devnw.com/gois"
	"go.devnw.com/gois/api"
	"go.devnw.com/gois/db"
	"go.devnw.com/gois/secrets"
	"golang.org/x/crypto/acme/autocert"
)

const (
	DEFAULTTIMEOUT = time.Hour * 24 * 7
	DEFAULTPORT    = 2096
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
		port                uint16
		verbose             bool
		gcpProject          string
		dnsChallengeKey     string
		dnsChallengeTimeout time.Duration
		logPrefix           string
		audience            string
		domain              string
		emailClaim          string
		certificate         string
		key                 string
	)

	root := &cobra.Command{
		Use:     "gopkgs-api [flags]",
		Short:   "api server for api.gopkgs.org",
		Version: version,
		Run: exec(
			&port,
			&verbose,
			&gcpProject,
			&dnsChallengeKey,
			&dnsChallengeTimeout,
			&logPrefix,
			&audience,
			&domain,
			&emailClaim,
			&certificate,
			&key,
		),
	}

	root.PersistentFlags().Uint16VarP(
		&port,
		"port", "p", DEFAULTPORT, "enable global verbose logging")

	root.PersistentFlags().BoolVarP(
		&verbose,
		"verbose", "v", false, "enable global verbose logging")
	root.PersistentFlags().StringVar(
		&gcpProject,
		"gcp-project", "gopkgs-342114", "gcp project id")
	root.PersistentFlags().StringVarP(
		&dnsChallengeKey,
		"dns-key", "k", "gopkgs_domain_token", "dns challenge key prefix")

	root.PersistentFlags().DurationVar(
		&dnsChallengeTimeout,
		"dns-token-timeout", DEFAULTTIMEOUT, "enable global verbose logging")

	root.PersistentFlags().StringVar(
		&logPrefix,
		"log-prefix", "api.gopkgs.org", "log prefix")

	root.PersistentFlags().StringVar(
		&audience,
		"audience", "https://api.gopkgs.org", "Auth0 Audience")

	root.PersistentFlags().StringVar(
		&domain,
		"domain", "devnw.us.auth0.com", "Auth0 Domain")

	root.PersistentFlags().StringVar(
		&emailClaim,
		"email-claim", "https://gopkgs.org/email_verified", "Email verification claim")

	root.PersistentFlags().StringVar(
		&certificate,
		"cert", "api_gopkgs_org_cert", "x509 Certificate Key Location")
	root.PersistentFlags().StringVar(
		&key,
		"key", "api_gopkgs_org_key", "x509 Certificate Key Location")

	err := root.Execute()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

//nolint:funlen
func exec(
	port *uint16,
	verbose *bool,
	gcpProject *string,
	dnsChallengeKey *string,
	dnsChallengeTimeout *time.Duration,
	logPrefix *string,
	audience *string,
	domain *string,
	emailClaim *string,
	certificate *string,
	key *string,
) func(cmd *cobra.Command, _ []string) {
	return func(cmd *cobra.Command, _ []string) {
		var JWKs = fmt.Sprintf("https://%s/.well-known/jwks.json", *domain)

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
			fmt.Printf("failed to parse jwks url: %s\n", err)
			return
		}

		auth, err := api.Authenticator(ctx, p, jwks, *emailClaim, *audience)
		if err != nil {
			fmt.Printf("failed to create authenticator: %s\n", err)
			return
		}

		// Subscribe parent publisher to Authentication events and errors
		err = p.Events(ctx, auth.ReadEvents(0))
		if err != nil {
			fmt.Printf("failed to subscribe to auth events: %s\n", err)
			return
		}

		err = p.Errors(ctx, auth.ReadErrors(0))
		if err != nil {
			fmt.Printf("failed to subscribe to auth errors: %s\n", err)
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
			fmt.Printf("failed to register handlers: %s\n", err)
			return
		}

		// Create a new secrets manager client.
		sm, err := secrets.NewManager(ctx, *gcpProject)
		if err != nil {
			fmt.Println(err)
			return
		}
		defer func() { _ = sm.Close() }()

		certCache := gois.NewCache(
			sm,
			autocert.DirCache(
				filepath.Join(os.TempDir(), *gcpProject),
			),
		)

		cert, err := certCache.Get(ctx, *certificate)
		if err != nil {
			fmt.Println(err)
			return
		}

		key, err := certCache.Get(ctx, *key)
		if err != nil {
			fmt.Println(err)
			return
		}

		certificate, err := tls.X509KeyPair(cert, key)
		if err != nil {
			fmt.Println(err)
			return
		}

		config := &tls.Config{
			MinVersion:               tls.VersionTLS13,
			Certificates:             []tls.Certificate{certificate},
			PreferServerCipherSuites: true,
		}

		server := &http.Server{
			Addr:      fmt.Sprintf(":%v", *port),
			TLSConfig: config,
			Handler: api.JSON(
				auth.ValidateToken(
					router,
				),
			),
		}

		alog.Printf("API server listening on %s", server.Addr)
		fmt.Println(server.ListenAndServeTLS("", ""))
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
