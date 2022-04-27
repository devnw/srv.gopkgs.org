package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"time"

	"cloud.google.com/go/firestore"
	"github.com/google/uuid"
	"go.devnw.com/dns"
	"go.devnw.com/gois"
	"google.golang.org/api/iterator"
)

const (
	AUDIENCE    = "https://api.gopkgs.org"
	DOMAIN      = "devnw.us.auth0.com"
	DOMAINREGEX = `^(?:(?:(?:[a-zA-z-]+):\/{1,3})?(?:[a-zA-Z0-9])(?:[a-zA-Z0-9\-.]){1,61}(?:\.[a-zA-Z]{2,})+|\[(?:(?:(?:[a-fA-F0-9]){1,4})(?::(?:[a-fA-F0-9]){1,4}){7}|::1|::)\]|(?:(?:[0-9]{1,3})(?:\.[0-9]{1,3}){3}))(?::[0-9]{1,5})?$`
	GOPKGSKEY   = "gopkgs_domain_token"
)

var timeout = time.Hour * 24 * 7

func u(path string) *url.URL {
	uuu, _ := url.Parse(path)
	return uuu
}

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
	ctx := context.Background()

	client, err := createClient(ctx)
	if err != nil {
		fmt.Printf("failed to create client: %s\n", err)
		return
	}

	api := &api{
		c: client,
	}

	router := http.NewServeMux()
	router.Handle("/", http.NotFoundHandler())

	router.Handle(
		"/domains",
		http.HandlerFunc(api.domainsHandler),
	)

	router.Handle(
		"/modules",
		http.HandlerFunc(api.modulesHandler),
	)

	routerWithCORS := handleCORS(validateToken(authInfo(JSON(router)))) // Move validate token and auth info to here

	server := &http.Server{
		Addr:    ":6060",
		Handler: routerWithCORS,
	}

	log.Printf("API server listening on %s", server.Addr)
	log.Fatal(server.ListenAndServe())
}

type auth struct {
	email string
	id    string
}

const ainfo = "AUTHINFO"

func authInfo(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		token, err := extractToken(req)
		if err != nil {
			fmt.Printf("failed to parse payload: %s\n", err)
			rw.WriteHeader(http.StatusUnauthorized)
			sendMessage(rw, &message{err.Error()})
			return
		}

		e, ok := token.PrivateClaims()["https://gopkgs.org/email"]
		if !ok {
			fmt.Printf("failed to find email claim\n")
			rw.WriteHeader(http.StatusUnauthorized)
			sendMessage(rw, &message{"failed to find email claim"})
			return
		}

		ev, ok := token.PrivateClaims()["https://gopkgs.org/email_verified"]
		if !ok {
			fmt.Printf("failed to find email claim\n")
			rw.WriteHeader(http.StatusUnauthorized)
			sendMessage(rw, &message{"failed to find email claim"})
			return
		}

		verified, ok := ev.(bool)
		if !ok || !verified {
			fmt.Printf("email not verified\n")
			rw.WriteHeader(http.StatusUnauthorized)
			sendMessage(rw, &message{"email not verified"})
			return
		}

		email, ok := e.(string)
		if !ok {
			fmt.Printf("failed to convert email claim\n")
			rw.WriteHeader(http.StatusUnauthorized)
			sendMessage(rw, &message{"failed to convert email claim"})
			return
		}

		ctxWithToken := context.WithValue(req.Context(), ainfo, auth{
			email: email,
			id:    token.Subject(),
		})

		next.ServeHTTP(rw, req.WithContext(ctxWithToken))
	})
}

func JSON(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		next.ServeHTTP(rw, req)
	})
}

type api struct {
	c *client
}

func (a *api) domainsHandler(rw http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		log.Printf("GET %s\n", r.URL.Path)
		a.domainsHandlerGet(rw, r)
	case http.MethodPut:
		log.Printf("PUT %s\n", r.URL.Path)
		a.domainsHandlerPut(rw, r)
	case http.MethodPost:
		log.Printf("POST %s\n", r.URL.Path)
		a.domainsHandlerPost(rw, r)
	case http.MethodDelete:
		log.Printf("DELETE %s\n", r.URL.Path)
		a.domainsHandlerDelete(rw, r)
	default:
		rw.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (a *api) modulesHandler(rw http.ResponseWriter, r *http.Request) {
	switch r.Method {
	// case http.MethodGet:
	// 	log.Printf("GET %s\n", r.URL.Path)
	// 	a.domainsHandlerGet(rw, r)
	case http.MethodPost:
		log.Printf("POST %s\n", r.URL.Path)
		a.moduleHandlerPost(rw, r)
	case http.MethodDelete:
		log.Printf("DELETE %s\n", r.URL.Path)
		a.moduleHandlerDelete(rw, r)
	default:
		rw.WriteHeader(http.StatusMethodNotAllowed)
	}
}

type mod struct {
	ID      string `json:"id"`
	Modules []*gois.Module
}

func (a *api) moduleHandlerPost(rw http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	aInfo, ok := ctx.Value(ainfo).(auth)
	if !ok {
		fmt.Printf("failed to get auth info\n")
		rw.WriteHeader(http.StatusUnauthorized)
		sendMessage(rw, &message{"failed to get auth info"})
		return
	}

	log.Printf("POST %s\n", r.URL.Path)

	data, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("failed to read body: %s\n", err)
		rw.WriteHeader(http.StatusBadRequest)
		sendMessage(rw, &message{err.Error()})
		return
	}

	m := &mod{}
	err = json.Unmarshal(data, m)
	if err != nil {
		log.Printf("failed to unmarshal body: %s\n", err)
		rw.WriteHeader(http.StatusBadRequest)
		sendMessage(rw, &message{err.Error()})
		return
	}

	d, err := a.c.Domains(ctx, aInfo).Where("ID", "==", m.ID).Limit(1).Documents(ctx).Next()

	if err != nil {
		fmt.Printf("failed to get domain: %s\n", err)
		rw.WriteHeader(http.StatusInternalServerError)
		sendMessage(rw, &message{err.Error()})
		return
	}

	updates := []firestore.Update{}
	for _, mod := range m.Modules {
		updates = append(
			updates,
			firestore.Update{
				Path:  fmt.Sprintf("Modules.%s", mod.Path),
				Value: mod,
			},
		)
	}

	_, err = d.Ref.Update(ctx, updates)
	if err != nil {
		fmt.Printf("failed to update domain: %s\n", err)
		rw.WriteHeader(http.StatusInternalServerError)
		sendMessage(rw, &message{err.Error()})
		return
	}

	data, err = json.Marshal(m.Modules)
	if err != nil {
		fmt.Printf("failed to marshal modules: %s\n", err)
		rw.WriteHeader(http.StatusInternalServerError)
		sendMessage(rw, &message{err.Error()})
		return
	}

	rw.Write(data)
}

func (a *api) moduleHandlerDelete(rw http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	aInfo, ok := ctx.Value(ainfo).(auth)
	if !ok {
		fmt.Printf("failed to get auth info\n")
		rw.WriteHeader(http.StatusUnauthorized)
		sendMessage(rw, &message{"failed to get auth info"})
		return
	}

	log.Printf("DELETE %s\n", r.URL.Path)

	id := r.URL.Query().Get("id")
	if id == "" {
		rw.WriteHeader(http.StatusBadRequest)
		sendMessage(rw, &message{"missing ID"})
		return
	}

	mod := r.URL.Query().Get("mod")
	if mod == "" {
		rw.WriteHeader(http.StatusBadRequest)
		sendMessage(rw, &message{"missing mod"})
		return
	}

	d, err := a.c.Domains(ctx, aInfo).Where("ID", "==", id).Limit(1).Documents(ctx).Next()

	if err != nil {
		fmt.Printf("failed to get domain: %s\n", err)
		rw.WriteHeader(http.StatusInternalServerError)
		sendMessage(rw, &message{err.Error()})
		return
	}

	_, err = d.Ref.Update(ctx, []firestore.Update{
		{Path: fmt.Sprintf("Modules.%s", mod), Value: firestore.Delete},
	})
	if err != nil {
		fmt.Printf("failed to update domain: %s\n", err)
		rw.WriteHeader(http.StatusInternalServerError)
		sendMessage(rw, &message{err.Error()})
		return
	}
}

func (a *api) domainsHandlerPost(rw http.ResponseWriter, r *http.Request) {
	log.Printf("POST %s\n", r.URL.Path)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		fmt.Printf("failed to read body: %s\n", err)
		rw.WriteHeader(http.StatusBadRequest)
		sendMessage(rw, &message{err.Error()})
		return
	}

	fmt.Printf("%s\n", string(body))
}

type newDomain struct {
	Domain string `json:"domain"`
}

func (d *newDomain) validate() error {
	if d.Domain == "" {
		return errors.New("domain is empty")
	}

	if !DomainReggy.MatchString(d.Domain) {
		return errors.New("domain is invalid")
	}

	return nil
}

func Unmarshal[T any](rc io.ReadCloser) (T, error) {
	defer rc.Close()
	var t T

	data, err := io.ReadAll(rc)
	if err != nil {
		return t, err
	}

	err = json.Unmarshal(data, &t)
	if err != nil {
		return t, err
	}

	return t, nil
}

func (a *api) domainsHandlerPut(rw http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	aInfo, ok := ctx.Value(ainfo).(auth)
	if !ok {
		fmt.Printf("failed to get auth info\n")
		rw.WriteHeader(http.StatusUnauthorized)
		sendMessage(rw, &message{"failed to get auth info"})
		return
	}

	log.Printf("PUT %s\n", r.URL.Path)

	domain, err := Unmarshal[newDomain](r.Body)
	if err != nil {
		fmt.Printf("failed to unmarshal body: %s\n", err)
		rw.WriteHeader(http.StatusBadRequest)
		sendMessage(rw, &message{err.Error()})
		return
	}

	err = domain.validate()
	if err != nil {
		fmt.Printf("failed to validate domain: %s\n", err)
		rw.WriteHeader(http.StatusBadRequest)
		sendMessage(rw, &message{err.Error()})
		return
	}

	// client, err := createClient(ctx)
	// if err != nil {
	// 	fmt.Printf("failed to create client: %s\n", err)
	// 	rw.WriteHeader(http.StatusInternalServerError)
	// 	sendMessage(rw, &message{err.Error()})
	// 	return
	// }

	// TODO: set this up so that if a domain exists but is not validated it
	// can be migrated to a new user and be validated.
	// This should happen after the current token is expired or invalidated.
	_, err = a.c.Collection("domains").Doc(domain.Domain).Get(ctx)
	if err == nil {
		fmt.Printf("domain %s already exists\n", domain.Domain)
		rw.WriteHeader(http.StatusBadRequest)
		sendMessage(rw, &message{"domain already exists"})
		return
	}

	// Generate domain challenge token
	token, err := dns.NewToken(domain.Domain, GOPKGSKEY, &timeout)
	if err != nil {
		fmt.Printf("failed to create token: %s\n", err)
		rw.WriteHeader(http.StatusInternalServerError)
		sendMessage(rw, &message{err.Error()})
		return
	}

	host := &gois.Host{
		ID:     uuid.New().String(),
		Owner:  aInfo.id,
		Domain: domain.Domain,
		Token:  token,
	}

	_, err = a.c.Collection("domains").Doc(domain.Domain).Create(ctx, host)
	if err != nil {
		fmt.Printf("failed to create domain: %s\n", err)
		rw.WriteHeader(http.StatusInternalServerError)
		sendMessage(rw, &message{err.Error()})
		return
	}

	data, err := json.Marshal(host)
	if err != nil {
		fmt.Printf("failed to marshal host: %s\n", err)
		rw.WriteHeader(http.StatusInternalServerError)
		sendMessage(rw, &message{err.Error()})
		return
	}

	rw.Write(data)
}

func (a *api) domainsHandlerDelete(rw http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	aInfo, ok := ctx.Value(ainfo).(auth)
	if !ok {
		fmt.Printf("failed to get auth info\n")
		rw.WriteHeader(http.StatusUnauthorized)
		sendMessage(rw, &message{"failed to get auth info"})
		return
	}

	log.Printf("DELETE %s\n", r.URL.Path)
	id := r.URL.Query().Get("id")
	if id == "" {
		rw.WriteHeader(http.StatusBadRequest)
		sendMessage(rw, &message{"missing ID"})
		return
	}

	// client, err := createClient(ctx)
	// if err != nil {
	// 	fmt.Printf("failed to create client: %s\n", err)
	// 	rw.WriteHeader(http.StatusInternalServerError)
	// 	sendMessage(rw, &message{err.Error()})
	// 	return
	// }

	// var d *firestore.DocumentSnapshot
	d, err := a.c.Domains(ctx, aInfo).Where("ID", "==", id).Limit(1).Documents(ctx).Next()

	if err != nil {
		fmt.Printf("failed to get domain: %s\n", err)
		rw.WriteHeader(http.StatusInternalServerError)
		sendMessage(rw, &message{err.Error()})
		return
	}

	_, err = d.Ref.Delete(ctx)
	if err != nil {
		fmt.Printf("failed to delete domain: %s\n", err)
		rw.WriteHeader(http.StatusInternalServerError)
		sendMessage(rw, &message{err.Error()})
		return
	}
}

func (a *api) domainsHandlerGet(rw http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	aInfo, ok := ctx.Value(ainfo).(auth)
	if !ok {
		fmt.Printf("failed to get auth info\n")
		rw.WriteHeader(http.StatusUnauthorized)
		sendMessage(rw, &message{"failed to get auth info"})
		return
	}

	// aInfo, ok := ctx.Value(ainfo).(auth)
	// if !ok {
	// 	fmt.Printf("failed to get auth info\n")
	// 	rw.WriteHeader(http.StatusUnauthorized)
	// 	sendMessage(rw, &message{"failed to get auth info"})
	// 	return
	// }

	// fmt.Printf(
	// 	"email: %s; auth provider: %s; auth ID: %s\n",
	// 	aInfo.email,
	// 	aInfo.provider,
	// 	aInfo.id,
	// )

	// client, err := createClient(ctx)
	// if err != nil {
	// 	fmt.Printf("failed to create client: %s\n", err)
	// 	rw.WriteHeader(http.StatusInternalServerError)
	// 	sendMessage(rw, &message{err.Error()})
	// 	return
	// }

	domains := []*gois.Host{}

	// var d *firestore.DocumentSnapshot
	iter := a.c.Domains(ctx, aInfo).Documents(ctx)

	for {
		d, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			fmt.Printf("failed to get domain: %s\n", err)
			rw.WriteHeader(http.StatusInternalServerError)
			sendMessage(rw, &message{err.Error()})
			return
		}

		h := &gois.Host{}
		err = d.DataTo(h)
		if err != nil {
			fmt.Printf("failed to unmarshal host: %s\n", err)
			rw.WriteHeader(http.StatusInternalServerError)
			sendMessage(rw, &message{err.Error()})
			return
		}

		domains = append(domains, h)
	}

	data, err := json.Marshal(domains)
	if err != nil {
		fmt.Printf("failed to marshal host: %s\n", err)
		rw.WriteHeader(http.StatusInternalServerError)
		sendMessage(rw, &message{err.Error()})
		return
	}

	rw.Write(data)
}
