package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"go.devnw.com/alog"
	"go.devnw.com/dns"
	"go.devnw.com/event"
	"go.devnw.com/gois"
	"go.devnw.com/gois/api"
	"go.devnw.com/gois/db"
	"go.devnw.com/gois/secrets"
	"golang.org/x/crypto/acme/autocert"
)

const DEFAULTTIMEOUT time.Duration = time.Hour * 24 * 7
const CACHETIMEOUT time.Duration = time.Minute * 5

var version string
var resolver dns.Resolver = net.DefaultResolver

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
		cacheTimeout        time.Duration
		logPrefix           string
		redirectURL         string
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
			&cacheTimeout,
			&redirectURL,
		),
	}

	root.PersistentFlags().BoolVarP(
		&verbose,
		"verbose", "v", false, "enable global verbose logging")
	root.PersistentFlags().StringVarP(
		&gcpProject,
		"gcp-project", "p", "gopkgs-342114", "gcp project id")
	root.PersistentFlags().StringVarP(
		&dnsChallengeKey,
		"dns-key", "k", "gopkgs_domain_token", "dns challenge key prefix")

	root.PersistentFlags().DurationVar(
		&dnsChallengeTimeout,
		"dns-token-timeout", DEFAULTTIMEOUT, "dns token timeout")

	root.PersistentFlags().DurationVar(
		&cacheTimeout,
		"cache-timeout", CACHETIMEOUT, "host cache timeout")

	root.PersistentFlags().StringVar(
		&logPrefix,
		"log-prefix", "srv.gopkgs.org", "log prefix")

	root.PersistentFlags().StringVar(
		&redirectURL,
		"redirect-url", "https://gopkgs.org", "redirect URL for errors")

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
	cacheTimeout *time.Duration,
	redirectURL *string,
) func(cmd *cobra.Command, _ []string) {
	return func(cmd *cobra.Command, _ []string) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		p := event.NewPublisher(ctx)

		err := configLogger(ctx, *logPrefix)
		if err != nil {
			fmt.Printf("failed to configure logger: %s\n", err)
			return
		}

		if *verbose {
			// Subscribe logger to events and errors from default publisher
			alog.Printc(ctx, p.ReadEvents(0).Interface())
		}

		alog.Errorc(ctx, p.ReadErrors(0).Interface())

		// Create a new secrets manager client.
		sm, err := secrets.NewManager(ctx, *gcpProject)
		if err != nil {
			alog.Fatal(err)
			return
		}

		defer func() {
			_ = sm.Close()
		}()

		// Create the database connection
		client, err := db.New(
			ctx,
			*gcpProject,
			*dnsChallengeKey,
			*dnsChallengeTimeout,
		)
		if err != nil {
			alog.Fatal(err, "failed to create database client")
			return
		}

		defer func() {
			_ = client.Close()
		}()

		dm, err := api.NewDomainManager(
			ctx,
			p,
			client,
			gois.NewCache(
				sm,
				autocert.DirCache(
					filepath.Join(os.TempDir(), *gcpProject),
				),
			),
			resolver,
			*cacheTimeout,
			*redirectURL,
		)
		if err != nil {
			alog.Fatal(err)
			return
		}

		mux := http.NewServeMux()
		mux.Handle("/", api.PanicHandler(http.HandlerFunc(dm.Handler)))

		err = http.Serve(dm.Listener(ctx), mux)
		if err != nil {
			alog.Fatal(err)
			return
		}
	}
}
