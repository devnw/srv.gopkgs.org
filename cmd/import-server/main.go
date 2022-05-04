package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"go.devnw.com/alog"
	"go.devnw.com/dns"
	"go.devnw.com/gois"
	"go.devnw.com/gois/db"
	"go.devnw.com/gois/secrets"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

type secretManager interface {
	io.Closer
	Get(ctx context.Context, key string) ([]byte, error)
	Put(ctx context.Context, key string, data []byte) error
}

const (
	PROJECT = "gopkgs-342114"

	//nolint:gosec
	TOKENKEY = "gopkgs_domain_token"

	TOKENTIMEOUT = time.Hour * 24 * 7

	logPrefix = "srv.gopkgs.org"
)

var resolver dns.Resolver = net.DefaultResolver

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := alog.Global(
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
	if err != nil {
		fmt.Println(err)
		return
	}

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

	dm, err := New(ctx, client, sm, resolver, PROJECT)
	if err != nil {
		alog.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", dm.Handler)

	alog.Fatal(http.Serve(dm.Listener(ctx), mux))
}

func New(
	ctx context.Context,
	datab gois.DB,
	sm secretManager,
	r dns.Resolver,
	projectID string,
) (*DomainManager, error) {
	return &DomainManager{
		ctx:       ctx,
		projectID: projectID,
		db:        datab,
		secrets:   sm, // pragma: allowlist secret
		dirCache:  autocert.DirCache(filepath.Join(os.TempDir(), projectID)),
		cache:     map[string]*gois.Host{},
	}, nil
}

type DomainManager struct {
	ctx       context.Context
	projectID string
	db        gois.DB
	secrets   secretManager
	dirCache  autocert.DirCache
	resolver  dns.Resolver

	cache   map[string]*gois.Host
	cacheMu sync.RWMutex
}

func (dm *DomainManager) Listener(ctx context.Context) net.Listener {
	m := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: dm.HostPolicy,
		Cache:      dm,
	}

	l := m.Listener()
	go func() {
		<-ctx.Done()
		err := l.Close()
		if err != nil {
			// TODO: log
		}
	}()

	return l
}

// HostPolicy specifies which host names the Manager is allowed to respond to.
// It returns a non-nil error if the host should be rejected.
// The returned error is accessible via tls.Conn.Handshake and its callers.
// See Manager's HostPolicy field and GetCertificate method docs for more details.
func (dm *DomainManager) HostPolicy(ctx context.Context, domain string) error {
	host, err := dm.VerifyHost(ctx, domain)
	if err != nil {
		return err
	}

	// Cache Host
	dm.cacheMu.Lock()
	defer dm.cacheMu.Unlock()

	dm.cache[host.Domain] = host

	return nil
}

func (dm *DomainManager) Handler(w http.ResponseWriter, r *http.Request) {
	alog.Printf("Hello, TLS user! Your config: %+v", r.TLS.ServerName)

	// Check cache
	dm.cacheMu.RLock()
	host, ok := dm.cache[r.TLS.ServerName]
	dm.cacheMu.RUnlock()

	if !ok {
		alog.Printf("No cache for %s; loading from db", r.TLS.ServerName)
		var err error
		host, err = dm.VerifyHost(dm.ctx, r.TLS.ServerName)
		if err != nil {
			alog.Printf("Failed to verify host: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// Add to the cache
		dm.cacheMu.Lock()
		dm.cache[host.Domain] = host
		dm.cacheMu.Unlock()
	}

	modPath := strings.TrimPrefix(r.URL.Path, "/")
	module, ok := host.Modules[modPath]
	if !ok {
		alog.Printf("No module for %s %s", host.Domain, modPath)
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// Execute the module handler
	alog.Printf("Executing module %s/%s", host.Domain, modPath)
	module.Handle(w, r)
}

func (dm *DomainManager) VerifyHost(ctx context.Context, domain string) (host *gois.Host, err error) {
	defer func() {
		if err != nil {
			alog.Printf("[ERROR] %s", err)

			// Override the error to ensure no data leakage to client
			err = &acme.Error{
				StatusCode: http.StatusNotFound,
			}
		}
	}()

	host, err = dm.db.GetDomainByName(ctx, domain)
	if err != nil {
		return nil, err
	}

	if host.Token == nil {
		err = fmt.Errorf(
			"invalid nil token for host [%s]",
			domain,
		)
		return nil, err
	}

	if host.Token.Validated == nil ||
		host.Token.Updated.Before(time.Now().Add(-24*time.Hour)) {
		err = host.Token.Verify(ctx, dm.resolver)
		if err != nil {
			err = fmt.Errorf(
				"unable to resolve host [%s:%s] for DNS verification: %s",
				domain,
				host.Token.String(),
				err,
			)

			return nil, err
		}

		err = dm.db.UpdateDomainToken(ctx, host.Owner, host.ID, host.Token.Validated)
		if err != nil {
			err = fmt.Errorf(
				"failed to update host [%s] record: %s",
				domain,
				err,
			)

			return nil, err
		}
	}

	return host, err
}

func sha(in string) string {
	return fmt.Sprintf("tls_%x", sha256.Sum256([]byte(in)))
}

// Get returns a certificate data for the specified key.
// If there's no such key, Get returns ErrCacheMiss.
func (dm *DomainManager) Get(ctx context.Context, key string) ([]byte, error) {
	alog.Debugf(nil, "Get: %s", key)

	key = sha(key)

	// attempt lookup in local cache
	data, err := dm.dirCache.Get(ctx, key)
	if err == nil {
		return data, nil
	}

	data, err = dm.secrets.Get(ctx, key)
	if err != nil {
		return nil, err
	}

	// Return the certificate data, and add it to the local cache.
	return data, dm.dirCache.Put(ctx, key, data)
}

// Put stores the data in the cache under the specified key.
// Underlying implementations may use any data storage format,
// as long as the reverse operation, Get, results in the original data.
func (dm *DomainManager) Put(ctx context.Context, key string, data []byte) error {
	key = sha(key)

	// Store local cache for quick lookup.
	defer func() {
		_ = dm.dirCache.Put(ctx, key, data)
	}()

	err := dm.secrets.Put(ctx, key, data)
	if err != nil {
		return err
	}

	return nil
}

// Delete removes a certificate data from the cache under the specified key.
// If there's no such key in the cache, Delete returns nil.
func (dm *DomainManager) Delete(ctx context.Context, key string) error {
	key = sha(key)

	// Delete local cache.
	_ = dm.dirCache.Delete(ctx, key)

	return nil
}
