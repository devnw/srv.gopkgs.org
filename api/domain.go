package api

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/jwt"
	"go.devnw.com/dns"
	"go.devnw.com/event"
	"go.devnw.com/gois"
	"go.devnw.com/ttl"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

type newDomain struct {
	Domain string `json:"domain"`
}

func (d *newDomain) validate() error {
	if d.Domain == "" {
		return errors.New("domain is empty")
	}

	if !gois.DomainReggy.MatchString(d.Domain) {
		return errors.New("domain is invalid")
	}

	return nil
}

func Domain(c gois.DB, p *event.Publisher) (http.Handler, error) {
	if c == nil {
		return nil, &Error{
			Endpoint: "domain",
			Message:  "db is nil",
		}
	}

	if p == nil {
		return nil, &Error{
			Endpoint: "domain",
			Message:  "publisher is nil",
		}
	}

	return &domain{c, p}, nil
}

type domain struct {
	c gois.DB
	p *event.Publisher
}

func (d *domain) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var err error
	defer func() {
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)

			// Push the error to the publisher for subscribers to pick up.
			d.p.ErrorFunc(r.Context(), func() error {
				return err
			})
		}
	}()

	var t jwt.Token
	t, err = AuthToken(r.Context())
	if err != nil {
		return
	}

	switch r.Method {
	case http.MethodGet:
		err = d.Get(t, w, r)
	case http.MethodPut:
		err = d.Put(t, w, r)
	case http.MethodDelete:
		err = d.Delete(t, w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (d *domain) Put(t jwt.Token, w http.ResponseWriter, r *http.Request) error {
	domain, err := Unmarshal[newDomain](r.Body)
	if err != nil {
		return Err(r, err, "failed to unmarshal domain")
	}

	// Clean up the domain a bit.
	domain.Domain = strings.ToLower(strings.TrimSpace(domain.Domain))

	err = domain.validate()
	if err != nil {
		return Err(r, err, "failed to validate domain")
	}

	host, err := d.c.CreateDomain(r.Context(), t.Subject(), domain.Domain)
	if err != nil {
		return Err(r, err, "failed to create domain")
	}

	data, err := json.Marshal(host)
	if err != nil {
		return Err(r, err, "failed to marshal host")
	}

	_, err = w.Write(data)
	if err != nil {
		return Err(r, err, "failed to write data to response")
	}

	return nil
}

func (d *domain) Get(t jwt.Token, w http.ResponseWriter, r *http.Request) error {
	domains, err := d.c.GetDomains(r.Context(), t.Subject())
	if err != nil {
		return Err(r, err, "failed to get domains")
	}

	data, err := json.Marshal(domains)
	if err != nil {
		return Err(r, err, "failed to marshal domains")
	}

	_, err = w.Write(data)
	if err != nil {
		return Err(r, err, "failed to write data to response")
	}

	return nil
}

func (d *domain) Delete(t jwt.Token, w http.ResponseWriter, r *http.Request) error {
	id, err := uuid.Parse(r.URL.Query().Get("id"))
	if err != nil {
		return Err(r, err, "invalid id")
	}

	err = d.c.DeleteDomain(r.Context(), t.Subject(), id.String())
	if err != nil {
		return Err(r, err, "failed to delete domain")
	}

	w.WriteHeader(http.StatusNoContent)
	return nil
}

func NewDomainManager(
	ctx context.Context,
	p *event.Publisher,
	datab gois.DB,
	certs gois.KVStore,
	r dns.Resolver,
	cacheTimeout time.Duration,
	redirectURL string,
) (*DomainManager, error) {
	return &DomainManager{
		ctx:         ctx,
		p:           p,
		db:          datab,
		certs:       certs, // pragma: allowlist secret
		cache:       ttl.NewCache[string, *gois.Host](ctx, cacheTimeout, true),
		resolver:    r,
		redirectURL: redirectURL,
	}, nil
}

type DomainManager struct {
	ctx         context.Context
	p           *event.Publisher
	db          gois.DB
	certs       gois.KVStore
	resolver    dns.Resolver
	redirectURL string

	cache *ttl.Cache[string, *gois.Host]
}

func (dm *DomainManager) Listener(ctx context.Context) net.Listener {
	m := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: dm.HostPolicy,
		Cache:      &cacheWrapper{dm.certs},
	}

	l := m.Listener()
	go func() {
		<-ctx.Done()
		_ = l.Close()
	}()

	return l
}

// HostPolicy specifies which host names the Manager is allowed to respond to.
// It returns a non-nil error if the host should be rejected.
// The returned error is accessible via tls.Conn.Handshake and its callers.
// See Manager's HostPolicy field and GetCertificate method docs for more details.
func (dm *DomainManager) HostPolicy(ctx context.Context, domain string) error {
	ip := net.ParseIP(domain)
	if ip != nil {
		return errors.New("domain is an IP address")
	}

	host, err := dm.VerifyHost(ctx, domain)
	if err != nil {
		return err
	}

	err = dm.cache.Set(ctx, host.Domain, host)
	if err != nil {
		return err
	}

	return nil
}

func (dm *DomainManager) refreshHost(ctx context.Context, domain string) (*gois.Host, error) {
	host, err := dm.VerifyHost(dm.ctx, domain)
	if err != nil {
		return nil, err
	}

	// Set the host in the cache.
	err = dm.cache.Set(ctx, host.Domain, host)
	if err != nil {
		return nil, err
	}

	return host, nil
}

func (dm *DomainManager) Handler(w http.ResponseWriter, r *http.Request) {
	var err error
	defer func() {
		if err != nil {
			http.Redirect(w, r, dm.redirectURL, http.StatusSeeOther)
		}
	}()
	// Check cache
	host, ok := dm.cache.Get(r.Context(), r.TLS.ServerName)
	if !ok {
		host, err = dm.refreshHost(dm.ctx, r.TLS.ServerName)
		if err != nil {
			dm.p.ErrorFunc(dm.ctx, func() error {
				return fmt.Errorf(
					"Error while verifying/refreshing host: %v",
					err,
				)
			})
			return
		}
	}

	modPath := strings.TrimPrefix(r.URL.Path, "/")
	module, ok := host.Modules[modPath]
	if !ok {
		host, err = dm.refreshHost(dm.ctx, r.TLS.ServerName)
		if err != nil {
			dm.p.ErrorFunc(dm.ctx, func() error {
				return fmt.Errorf(
					"Error while verifying/refreshing host: %v",
					err,
				)
			})
			return
		}

		module, ok = host.Modules[modPath]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			dm.p.ErrorFunc(dm.ctx, func() error {
				return fmt.Errorf(
					"Module not found for path %s/%s",
					host.Domain,
					modPath,
				)
			})
			return
		}
	}

	// Execute the module handler
	err = module.Handle(w, r, host.Domain)
	if err != nil {
		dm.p.ErrorFunc(dm.ctx, func() error {
			return err
		})
	}
}

func (dm *DomainManager) VerifyHost(
	ctx context.Context,
	domain string,
) (host *gois.Host, err error) {
	defer func() {
		if err != nil {
			dm.p.ErrorFunc(dm.ctx, func() error {
				return err
			})

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

// cacheWrapper is a wrapper around the gois.KVStore interface that sha256
// hashes the key before passing it to the underlying KVStore.
type cacheWrapper struct {
	gois.KVStore
}

func (w *cacheWrapper) Get(ctx context.Context, key string) ([]byte, error) {
	return w.KVStore.Get(ctx, sha(key))
}

func (w *cacheWrapper) Put(ctx context.Context, key string, data []byte) error {
	return w.KVStore.Put(ctx, sha(key), data)
}

func (w *cacheWrapper) Delete(ctx context.Context, key string) error {
	return w.KVStore.Delete(ctx, sha(key))
}
