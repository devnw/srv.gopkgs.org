package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"go.devnw.com/alog"
	"go.devnw.com/dns"
	"go.devnw.com/event"
	"go.devnw.com/gois"
	"go.devnw.com/gois/api"
	"go.devnw.com/gois/db"
	"go.devnw.com/gois/secrets"
	"golang.org/x/crypto/acme/autocert"
)

const (
	PROJECT = "gopkgs-342114"

	//nolint:gosec
	TOKENKEY = "gopkgs_domain_token"

	TOKENTIMEOUT = time.Hour * 24 * 7

	logPrefix = "srv.gopkgs.org"
)

var resolver dns.Resolver = net.DefaultResolver

func configLogger(ctx context.Context) error {
	return alog.Global(
		ctx,
		logPrefix,
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

	// Create a new secrets manager client.
	sm, err := secrets.NewManager(ctx, PROJECT)
	if err != nil {
		alog.Fatal(err)
	}

	defer func() {
		_ = sm.Close()
	}()

	// Create the database connection
	client, err := db.New(ctx, PROJECT, TOKENKEY, TOKENTIMEOUT)
	if err != nil {
		fmt.Printf("failed to create database client: %s\n", err)
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
				filepath.Join(os.TempDir(), PROJECT),
			),
		),
		resolver,
	)
	if err != nil {
		alog.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", dm.Handler)

	alog.Fatal(http.Serve(dm.Listener(ctx), mux))
}
