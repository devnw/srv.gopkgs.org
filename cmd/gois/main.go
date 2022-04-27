package main

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"cloud.google.com/go/firestore"
	secrets "cloud.google.com/go/secretmanager/apiv1"
	"github.com/davecgh/go-spew/spew"
	"go.devnw.com/dns"
	"go.devnw.com/gois"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
	secretspb "google.golang.org/genproto/googleapis/cloud/secretmanager/v1"
)

/*
mod.gopkgs.org: [gopkgs_domain_token=4sDoURGUvRex/ZkJXdiOoYu0CmkzwpGcTvnJU1kVm/lyGUuSWmqDeaFuRXIck5Bs3GzrgvEDFlqdk88RCxlUEQ==]
go.devnw.com: [gopkgs_domain_token=6HrW3WRIMWu8JWzlh2pflp4/+RjiiKH3D3dyk3UKAI/zne57d0f9V0gJmqKW918KtCiipUGG+Po/Of65NdUGSA==]
go.atomizer.io: [gopkgs_domain_token=UyKPeIfxt6Aw54wmiKftKS0IOr6A2AMmpJL2d7PK4p8b7aR2T6QIXGnyaoum62jPaHkmr099K0blF0hAh6hQGA==]
go.benjiv.com: [gopkgs_domain_token=uDay4ctb+Q7oGshNvjO1GqjlgDzyo/MjGwJvte8tcaDxorEZ1buauNIMd0iOZpGzv5nwd9c6Bnl3MVECtkYcSw==]
go.structs.dev: [gopkgs_domain_token=D9M2JQYckEphwnCSJUuOLlaOYIso+p4mi/cJdD/Zn3UircW8Cwxc8V0qVPkzt3w5cbtF+yUCVJC0dwkk5YUZoQ==]
*/

func u(path string) *url.URL {
	uuu, _ := url.Parse(path)
	return uuu
}

const TOKENKEY = "gopkgs_domain_token"

func domains() gois.Records {
	exp := time.Hour * 24 * 7

	pkgs, err := dns.NewToken("mod.gopkgs.org", TOKENKEY, &exp)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("mod.gopkgs.org: [%s]\n", pkgs.String())

	devnw, err := dns.NewToken("go.devnw.com", TOKENKEY, &exp)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("go.devnw.com: [%s]\n", devnw.String())

	atom, err := dns.NewToken("go.atomizer.io", TOKENKEY, &exp)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("go.atomizer.io: [%s]\n", atom.String())

	bv, err := dns.NewToken("go.benjiv.com", TOKENKEY, &exp)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("go.benjiv.com: [%s]\n", bv.String())

	sd, err := dns.NewToken("go.structs.dev", TOKENKEY, &exp)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("go.structs.dev: [%s]\n", sd.String())

	return []*gois.Host{
		{
			Domain: "mod.gopkgs.org",
			Token:  pkgs,
		},
		{
			Domain: "go.devnw.com",
			Token:  devnw,
			Modules: map[string]*gois.Module{
				"alog": {
					Domain: "go.devnw.com",
					Path:   "alog",
					Proto:  "git",
					Repo:   u("https://github.com/devnw/alog"),
					Docs:   u("https://pkg.go.dev/go.devnw.com/alog"),
				},
				"ttl": {
					Domain: "go.devnw.com",
					Path:   "ttl",
					Proto:  "git",
					Repo:   u("https://github.com/devnw/ttl"),
					Docs:   u("https://pkg.go.dev/go.devnw.com/ttl"),
				},
				"validator": {
					Domain: "go.devnw.com",
					Path:   "validator",
					Proto:  "git",
					Repo:   u("https://github.com/devnw/validator"),
					Docs:   u("https://pkg.go.dev/go.devnw.com/validator"),
				},
				"graph-cli": {
					Domain: "go.devnw.com",
					Path:   "graph-cli",
					Proto:  "git",
					Repo:   u("https://github.com/devnw/graph-cli"),
					Docs:   u("https://pkg.go.dev/go.devnw.com/graph-cli"),
				},
				"graph": {
					Domain: "go.devnw.com",
					Path:   "graph",
					Proto:  "git",
					Repo:   u("https://github.com/devnw/graph"),
					Docs:   u("https://pkg.go.dev/go.devnw.com/graph"),
				},
				"bridgekeeper": {
					Domain: "go.devnw.com",
					Path:   "bridgekeeper",
					Proto:  "git",
					Repo:   u("https://github.com/devnw/bridgekeeper"),
					Docs:   u("https://pkg.go.dev/go.devnw.com/bridgekeeper"),
				},
				"syncer": {
					Domain: "go.devnw.com",
					Path:   "syncer",
					Proto:  "git",
					Repo:   u("https://github.com/devnw/syncer"),
					Docs:   u("https://pkg.go.dev/go.devnw.com/syncer"),
				},
				"copy": {
					Domain: "go.devnw.com",
					Path:   "copy",
					Proto:  "git",
					Repo:   u("https://github.com/devnw/copy"),
					Docs:   u("https://pkg.go.dev/go.devnw.com/copy"),
				},
				"ctx": {
					Domain: "go.devnw.com",
					Path:   "ctx",
					Proto:  "git",
					Repo:   u("https://github.com/devnw/ctx"),
					Docs:   u("https://pkg.go.dev/go.devnw.com/ctx"),
				},
				"event": {
					Domain: "go.devnw.com",
					Path:   "event",
					Proto:  "git",
					Repo:   u("https://github.com/devnw/event"),
					Docs:   u("https://pkg.go.dev/go.devnw.com/event"),
				},
				"api": {
					Domain: "go.devnw.com",
					Path:   "api",
					Proto:  "git",
					Repo:   u("https://github.com/devnw/api"),
					Docs:   u("https://pkg.go.dev/go.devnw.com/api"),
				},
				"dns": {
					Domain: "go.devnw.com",
					Path:   "dns",
					Proto:  "git",
					Repo:   u("https://github.com/devnw/dns"),
					Docs:   u("https://pkg.go.dev/go.devnw.com/dns"),
				},
				"gois": {
					Domain: "go.devnw.com",
					Path:   "gois",
					Proto:  "git",
					Repo:   u("https://github.com/devnw/gois"),
					Docs:   u("https://pkg.go.dev/go.devnw.com/gois"),
				},
				"seo": {
					Domain: "go.devnw.com",
					Path:   "seo",
					Proto:  "git",
					Repo:   u("https://github.com/devnw/seo"),
					Docs:   u("https://pkg.go.dev/go.devnw.com/seo"),
				},
			},
		},
		{
			Domain: "go.atomizer.io",
			Token:  atom,
			Modules: map[string]*gois.Module{
				"engine": {
					Domain: "go.atomizer.io",
					Path:   "engine",
					Proto:  "git",
					Repo:   u("https://github.com/devnw/atomizer"),
					Docs:   u("https://pkg.go.dev/go.atomizer.io/engine"),
				},
				"amqp": {
					Domain: "go.atomizer.io",
					Path:   "amqp",
					Proto:  "git",
					Repo:   u("https://github.com/devnw/amqp"),
					Docs:   u("https://pkg.go.dev/go.atomizer.io/amqp"),
				},
				"synapse": {
					Domain: "go.atomizer.io",
					Path:   "synapse",
					Proto:  "git",
					Repo:   u("https://github.com/devnw/synapse"),
					Docs:   u("https://pkg.go.dev/go.atomizer.io/synapse"),
				},
				"cmd": {
					Domain: "go.atomizer.io",
					Path:   "cmd",
					Proto:  "git",
					Repo:   u("https://github.com/devnw/atomizer-cmd"),
					Docs:   u("https://pkg.go.dev/go.atomizer.io/cmd"),
				},
				"test-console": {
					Domain: "go.atomizer.io",
					Path:   "test-console",
					Proto:  "git",
					Repo:   u("https://github.com/devnw/atomizer-test-console"),
					Docs:   u("https://pkg.go.dev/go.atomizer.io/test-console"),
				},
				"montecarlopi": {
					Domain: "go.atomizer.io",
					Path:   "montecarlopi",
					Proto:  "git",
					Repo:   u("https://github.com/devnw/montecarlopi"),
					Docs:   u("https://pkg.go.dev/go.atomizer.io/montecarlopi"),
				},
				"base": {
					Domain: "go.atomizer.io",
					Path:   "base",
					Proto:  "git",
					Repo:   u("https://github.com/devnw/atomizer-base"),
					Docs:   u("https://pkg.go.dev/go.atomizer.io/base"),
				},
				"test-agent": {
					Domain: "go.atomizer.io",
					Path:   "test-agent",
					Proto:  "git",
					Repo:   u("https://github.com/devnw/atomizer-test-agent"),
					Docs:   u("https://pkg.go.dev/go.atomizer.io/test-agent"),
				},
				"plex": {
					Domain: "go.atomizer.io",
					Path:   "plex",
					Proto:  "git",
					Repo:   u("https://github.com/devnw/plex"),
					Docs:   u("https://pkg.go.dev/go.atomizer.io/plex"),
				},
				"stream": {
					Domain: "go.atomizer.io",
					Path:   "stream",
					Proto:  "git",
					Repo:   u("https://github.com/devnw/stream"),
					Docs:   u("https://pkg.go.dev/go.atomizer.io/stream"),
				},
			},
		},
		{
			Domain: "go.benjiv.com",
			Token:  bv,
			Modules: map[string]*gois.Module{
				"hammer": {
					Domain: "go.benjiv.com",
					Path:   "hammer",
					Proto:  "git",
					Repo:   u("https://github.com/benjivesterby/hammer"),
					Docs:   u("https://pkg.go.dev/go.benjiv.com/hammer"),
				},
			},
		},
		{
			Domain: "go.structs.dev",
			Token:  sd,
			Modules: map[string]*gois.Module{
				"gen": {
					Domain: "go.structs.dev",
					Path:   "gen",
					Proto:  "git",
					Repo:   u("https://github.com/structsdev/gen"),
				},
			},
		},
	}
}

// var cfg =
// 	"vpn.benjiv.com": {
// 		"hammer": {
// 			Host:  "vpn.benjiv.com",
// 			Path:  "hammer",
// 			Proto: "git",
// 			Repo:  u("https://benjiv.com/hammer"),
// 			Site:  u("https://benjiv.com/"),
// 			Docs:  u("https://benjiv.com/"),
// 		},
// 		"demo": {
// 			Host:  "vpn.benjiv.com",
// 			Path:  "demo",
// 			Proto: "git",
// 			Repo:  u("https://benjiv.com/demo"),
// 		},
// 	},
// 	"i.devnw.com": {
// 		"alog": {
// 			Host:  "i.devnw.com",
// 			Path:  "alog",
// 			Proto: "git",
// 			Repo:  u("https://devnw.com"),
// 			Docs:  u("https://devnw.com/alog/docs"),
// 		},
// 		"dns": {
// 			Host:  "i.devnw.com",
// 			Path:  "dns",
// 			Proto: "git",
// 			Repo:  u("https://devnw.com/"),
// 			Docs:  u("https://devnw.com/docs"),
// 		},
// 	},
// 	"i.atomizer.io": {
// 		"engine": {
// 			Host:  "i.atomizer.io",
// 			Path:  "engine",
// 			Proto: "git",
// 			Repo:  u("https://atomizer.io/engine"),
// 			Docs:  u("https://atomizer.io/docs"),
// 		},
// 		"amqp": {
// 			Host:  "i.atomizer.io",
// 			Path:  "amqp",
// 			Proto: "git",
// 			Repo:  u("https://atomizer.io"),
// 			Docs:  u("https://atomizer.io/docs"),
// 		},
// 	},
// }

// go:embed example.json
// var cfg []byte

func createClient(ctx context.Context) (*firestore.Client, error) {
	// Sets your Google Cloud Platform project ID.
	projectID := "gopkgs-342114"

	client, err := firestore.NewClient(ctx, projectID)
	if err != nil {
		return nil, err
	}
	// Close client when done with
	// defer client.Close()
	return client, nil
}

func addDomains(ctx context.Context) {
	c, err := createClient(ctx)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer c.Close()

	col := c.Collection("domains")
	d := domains()

	for _, h := range d {
		col.Doc(h.Domain).Set(ctx, h)
	}

	return
}

func serve(ctx context.Context) {
	dm, err := New(ctx, "gopkgs-342114")
	if err != nil {
		panic(err)
	}
	defer dm.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/", dm.Handler)

	log.Fatal(http.Serve(dm.Listener(ctx), mux))
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// dm, err := New(ctx, "gopkgs-342114")
	// if err != nil {
	// 	panic(err)
	// }
	// defer dm.Close()

	// s, err := dm.getSecret(ctx, "tls_f9c68a72f34e46ec08c1dde20bdf8323dfc910bac117afd9ce888a493291a429")
	// if err != nil {
	// 	panic(err)
	// }

	// spew.Dump(s)
	// mod := &gois.Module{
	// 	Domain: "i.atomizer.io",
	// 	Path:   "engine",
	// 	Proto:  "git",
	// 	Repo:   u("https://github.com/devnw/atomizer"),
	// 	// Docs:   u("https://atomizer.io/docs"),
	// }

	// http.ListenAndServe(":80", http.HandlerFunc(mod.Handle))

	// addDomains(ctx)
	serve(ctx)

	// c, err := createClient(ctx)
	// if err != nil {
	// 	log.Fatalf("Failed to create client: %v", err)
	// }
	// defer c.Close()

	// d, err := c.Collection("domains").Doc("i.devnw.com").Get(ctx)
	// if err != nil {
	// 	log.Fatalf("Failed to get document: %v", err)
	// 	// log.Printf("Failed to get document: %v", err)
	// 	// // return fmt.Errorf("failed to lookup host: %v", err)
	// 	// return &acme.Error{
	// 	// 	StatusCode: http.StatusNotFound,
	// 	// }
	// }

	// h := gois.Host{}
	// err = d.DataTo(&h)
	// if err != nil {
	// 	log.Fatalf("Failed to get document: %v", err)
	// }

	// if h.Token == nil {
	// 	// TODO: domain token invalidated
	// }

	// if h.Token.Validated == nil ||
	// 	h.Token.Updated.Before(time.Now().Add(-24*time.Hour)) {

	// 	err = h.Token.Verify(ctx, net.DefaultResolver)
	// 	if err != nil {
	// 		log.Fatalf("unable to resolve host: %v", err)
	// 	}

	// 	t := time.Now()
	// 	if h.Token.Validated == nil {
	// 		h.Token.Validated = &t
	// 	}

	// 	h.Token.Updated = &t

	// 	_, err = c.Collection("domains").Doc("i.devnw.com").Set(ctx, h)
	// 	if err != nil {
	// 		log.Fatalf("failed to update host record: %v", err)
	// 	}

	// 	if h.Token.Validated == nil {
	// 		log.Fatalf("Token not validated")
	// 	}
	// }

	// spew.Dump(h)

	// doc, err := c.Collection("records").Doc("i.atomizer.io").Get(ctx)
	// if err != nil {
	// 	log.Fatalf("Failed to retrieve document: %v", err)
	// }

	// mods := map[string]gois.Module{}
	// err = doc.DataTo(&mods)
	// if err != nil {
	// 	log.Fatalf("Failed to decode document: %v", err)
	// }

	// spew.Dump(mods)
	// os.Exit(1)

	// // r := gois.Records{}
	// // err := json.Unmarshal(cfg, &r)
	// // if err != nil {
	// // 	panic(err)
	// // }

	// // output, err := json.Marshal(cfg)
	// // if err != nil {
	// // 	panic(err)
	// // }

	// // fmt.Println(string(output))

	// client, err := createClient(ctx)
	// if err != nil {
	// 	panic(err)
	// }
	// defer client.Close()

	// domains := []string{}
	// records := client.Collection("records").Documents(ctx)
	// hosts := gois.Records{}
	// for {
	// 	doc, err := records.Next()
	// 	if err != nil && err != iterator.Done {
	// 		panic(err)
	// 	}
	// 	if doc == nil {
	// 		break
	// 	}

	// 	v := map[string]gois.Module{}

	// 	err = doc.DataTo(&v)
	// 	if err != nil {
	// 		panic(err)
	// 	}

	// 	hosts[doc.Ref.ID] = v
	// 	domains = append(domains, doc.Ref.ID)

	// 	spew.Dump(hosts[doc.Ref.ID])
	// }

	// for host, record := range r {
	// 	_, err := records.Doc(host).Set(ctx, record)
	// 	if err != nil {
	// 		panic(err)
	// 	}
	// }

	// http.ListenAndServe(":80", http.HandlerFunc(r.Handle))
	// http.ListenAndServe(":9999", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	// 	fmt.Printf("Request URI: %s\n", r.RequestURI)
	// 	fmt.Printf("Remote Address: %s\n", r.RemoteAddr)

	// 	h := strings.Split(r.Host, ":")
	// 	if len(h) == 0 {
	// 		panic("no host")
	// 	}

	// 	fmt.Println(h[0])

	// 	w.Write([]byte("Hello World"))
	// }))
}

func New(ctx context.Context, projectID string) (*DomainManager, error) {
	// Create the secrets Client.
	secretsClient, err := secrets.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to setup client: %v", err)
	}

	firestoreClient, err := firestore.NewClient(ctx, projectID)
	if err != nil {
		return nil, err
	}

	return &DomainManager{
		ctx:       ctx,
		projectID: projectID,
		firestore: firestoreClient,
		secrets:   secretsClient,
		dirCache:  autocert.DirCache(filepath.Join(os.TempDir(), projectID)),
		cache:     map[string]*gois.Host{},
	}, nil
}

type DomainManager struct {
	ctx       context.Context
	projectID string
	firestore *firestore.Client
	secrets   *secrets.Client
	dirCache  autocert.DirCache

	cache   map[string]*gois.Host
	cacheMu sync.RWMutex
}

func (dm *DomainManager) Close() {
	err := dm.firestore.Close()
	if err != nil {
		panic(err)
	}

	err = dm.secrets.Close()
	if err != nil {
		panic(err)
	}
}

func (dc *DomainManager) Listener(ctx context.Context) net.Listener {
	m := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: dc.HostPolicy,
		Cache:      dc,
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
func (dc *DomainManager) HostPolicy(ctx context.Context, domain string) error {
	host, err := dc.VerifyHost(ctx, domain)
	if err != nil {
		return err
	}

	// Cache Host
	dc.cacheMu.Lock()
	defer dc.cacheMu.Unlock()

	dc.cache[host.Domain] = host

	return nil
}

func (dc *DomainManager) Handler(w http.ResponseWriter, r *http.Request) {
	log.Printf("Hello, TLS user! Your config: %+v", r.TLS.ServerName)

	// Check cache
	dc.cacheMu.RLock()
	host, ok := dc.cache[r.TLS.ServerName]
	dc.cacheMu.RUnlock()

	if !ok {
		log.Printf("No cache for %s; loading from db", r.TLS.ServerName)
		var err error
		host, err = dc.VerifyHost(dc.ctx, r.TLS.ServerName)
		if err != nil {
			log.Printf("Failed to verify host: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// Add to the cache
		dc.cacheMu.Lock()
		dc.cache[host.Domain] = host
		dc.cacheMu.Unlock()
	}

	modPath := strings.TrimPrefix(r.URL.Path, "/")
	module, ok := host.Modules[modPath]
	if !ok {
		log.Printf("No module for %s %s", host.Domain, modPath)
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// Execute the module handler
	log.Printf("Executing module %s/%s", host.Domain, modPath)
	module.Handle(w, r)
}

func (dc *DomainManager) VerifyHost(ctx context.Context, domain string) (host *gois.Host, err error) {
	defer func() {
		if err != nil {
			log.Printf("[ERROR] %s", err)

			// Override the error to ensure no data leakage to client
			err = &acme.Error{
				StatusCode: http.StatusNotFound,
			}
		}
	}()

	var d *firestore.DocumentSnapshot
	d, err = dc.firestore.Collection("domains").Doc(domain).Get(ctx)
	if err != nil {
		err = fmt.Errorf(
			"failed to lookup host [%s] in firestore: %s",
			domain,
			err,
		)
		return nil, err
	}

	h := &gois.Host{}
	err = d.DataTo(h)
	if err != nil {
		err = fmt.Errorf(
			"failed to map host [%s] to object: %s",
			domain,
			err,
		)
		return nil, err
	}

	if h.Token == nil {
		err = fmt.Errorf(
			"invalid nil token for host [%s]",
			domain,
		)
		return nil, err
	}

	if h.Token.Validated == nil ||
		h.Token.Updated.Before(time.Now().Add(-24*time.Hour)) {
		err = h.Token.Verify(ctx, net.DefaultResolver)
		if err != nil {
			err = fmt.Errorf(
				"unable to resolve host [%s:%s] for DNS verification: %s",
				domain,
				h.Token.String(),
				err,
			)

			return nil, err
		}

		t := time.Now()
		if h.Token.Validated == nil {
			h.Token.Validated = &t
		}

		h.Token.Updated = &t

		_, err = dc.firestore.Collection("domains").Doc(domain).Set(ctx, h)
		if err != nil {
			err = fmt.Errorf(
				"failed to update host [%s] record: %s",
				domain,
				err,
			)

			return nil, err
		}
	}

	return h, err
}

func sha(in string) string {
	return fmt.Sprintf("tls_%x", sha256.Sum256([]byte(in)))
}

// Get returns a certificate data for the specified key.
// If there's no such key, Get returns ErrCacheMiss.
func (dc *DomainManager) Get(ctx context.Context, key string) ([]byte, error) {
	log.Printf("[DEBUG] Get: %s", key)
	// 	if !strings.HasPrefix(key, "acme_account")

	// }

	key = sha(key)

	// attempt lookup in local cache
	data, err := dc.dirCache.Get(ctx, key)
	if err == nil {
		return data, nil
	}

	result, err := dc.getSecret(ctx, key)
	if err != nil {
		return nil, err
	}

	// Return the certificate data, and add it to the local cache.
	return result.Payload.Data, dc.dirCache.Put(ctx, key, result.Payload.Data)
}

func (dc *DomainManager) getSecret(ctx context.Context, key string) (*secretspb.AccessSecretVersionResponse, error) {
	log.Printf("[DEBUG] getSecret: %s", key)

	// Lookup the latest secret for this key in secrets manager.
	accessRequest := &secretspb.AccessSecretVersionRequest{
		Name: fmt.Sprintf(
			"projects/%s/secrets/%s/versions/latest",
			dc.projectID,
			key,
		),
	}

	// Execute the request
	result, err := dc.secrets.AccessSecretVersion(ctx, accessRequest)
	if err != nil {
		log.Printf("[DEBUG] getSecret: Unable to find %s at %s", key, accessRequest.Name)
		return nil, autocert.ErrCacheMiss
	}

	log.Printf("[DEBUG] getSecret: FOUND %s", key)
	return result, nil
}

// Put stores the data in the cache under the specified key.
// Underlying implementations may use any data storage format,
// as long as the reverse operation, Get, results in the original data.
func (dc *DomainManager) Put(ctx context.Context, key string, data []byte) error {
	key = sha(key)

	var name string

	// Only add to secrets manager if the key doesn't already exist
	result, err := dc.getSecret(ctx, key)
	if err == nil {
		log.Printf("[INFO] key [%s] already exists in secrets manager", key)
		name = result.Name
	} else {
		log.Printf("[INFO] Put %s; result %s", key, spew.Sdump(result))

		// push to secret manager
		// Create the request to create the secret.
		createSecretReq := &secretspb.CreateSecretRequest{
			Parent:   fmt.Sprintf("projects/%s", dc.projectID),
			SecretId: key,
			Secret: &secretspb.Secret{
				Replication: &secretspb.Replication{
					Replication: &secretspb.Replication_Automatic_{
						Automatic: &secretspb.Replication_Automatic{},
					},
				},
			},
		}

		log.Printf("[INFO] Put Secret Request%s", spew.Sdump(createSecretReq))

		secret, err := dc.secrets.CreateSecret(ctx, createSecretReq)
		if err != nil {
			log.Fatalf("failed to create secret: %v", err)
		}

		name = secret.Name
	}

	// Update the version of the secret
	addSecretVersionReq := &secretspb.AddSecretVersionRequest{
		Parent: name,
		Payload: &secretspb.SecretPayload{
			Data: data,
		},
	}

	// Call the API.
	_, err = dc.secrets.AddSecretVersion(ctx, addSecretVersionReq)
	if err != nil {
		log.Fatalf("failed to add secret version: %v", err)
	}

	// Store local cache for quick lookup.
	_ = dc.dirCache.Put(ctx, key, data)

	return nil
}

// Delete removes a certificate data from the cache under the specified key.
// If there's no such key in the cache, Delete returns nil.
func (dc *DomainManager) Delete(ctx context.Context, key string) error {
	key = sha(key)

	// Delete secret in secrets manager.

	// Delete local cache.
	_ = dc.dirCache.Delete(ctx, key)

	return nil
}
