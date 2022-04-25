package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"cloud.google.com/go/firestore"
	"github.com/google/uuid"
	"go.devnw.com/dns"
	"go.devnw.com/gois"
	. "go.structs.dev/gen"
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

func main() {
	fetchTenantKeys()

	router := http.NewServeMux()
	router.Handle("/", http.NotFoundHandler())
	// router.Handle("/api/messages/public", http.HandlerFunc(publicApiHandler))
	router.Handle(
		"/domains",
		// validateToken(
		// authInfo(
		http.HandlerFunc(domainsHandler),
		// ),
		// ),
	)
	// router.Handle("/domains/go.devnw.com/", validateToken(http.HandlerFunc(domainHandler)))
	routerWithCORS := handleCORS(router)

	server := &http.Server{
		Addr:    ":6060",
		Handler: routerWithCORS,
	}

	log.Printf("API server listening on %s", server.Addr)
	log.Fatal(server.ListenAndServe())
}

type auth struct {
	email    string
	provider string
	id       string
}

const ainfo = "AUTHINFO"

func authInfo(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		fmt.Printf("[%s]\n", req.Header.Get("Authorization"))

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

		subjs := strings.Split(token.Subject(), "|")
		if len(subjs) != 2 {
			fmt.Printf("failed to parse subject\n")
			rw.WriteHeader(http.StatusUnauthorized)
			sendMessage(rw, &message{"failed to parse subject"})
			return
		}

		ctxWithToken := context.WithValue(req.Context(), ainfo, auth{
			email:    email,
			provider: subjs[0],
			id:       subjs[1],
		})

		next.ServeHTTP(rw, req.WithContext(ctxWithToken))
	})
}

func domainsHandler(rw http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		log.Printf("GET %s\n", r.URL.Path)
		domainsHandlerGet(rw, r)
	case http.MethodPut:
		log.Printf("PUT %s\n", r.URL.Path)
		domainsHandlerPut(rw, r)
	case http.MethodPost:
		log.Printf("POST %s\n", r.URL.Path)
		domainsHandlerPost(rw, r)
	case http.MethodDelete:
		log.Printf("DELETE %s\n", r.URL.Path)
		domainsHandlerDelete(rw, r)
	default:
		rw.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func domainsHandlerPost(rw http.ResponseWriter, r *http.Request) {
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

func domainsHandlerPut(rw http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	log.Printf("PUT %s\n", r.URL.Path)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		fmt.Printf("failed to read body: %s\n", err)
		rw.WriteHeader(http.StatusBadRequest)
		sendMessage(rw, &message{err.Error()})
		return
	}

	domain := &newDomain{}
	err = json.Unmarshal(body, domain)
	if err != nil {
		fmt.Printf("failed to unmarshal body: %s\n", err)
		rw.WriteHeader(http.StatusBadRequest)
		sendMessage(rw, &message{err.Error()})
		return
	}

	if !DomainReggy.MatchString(domain.Domain) {
		fmt.Printf("domain %s is invalid\n", domain.Domain)
		rw.WriteHeader(http.StatusBadRequest)
		sendMessage(rw, &message{"domain is invalid"})
		return
	}

	client, err := createClient(ctx)
	if err != nil {
		fmt.Printf("failed to create client: %s\n", err)
		rw.WriteHeader(http.StatusInternalServerError)
		sendMessage(rw, &message{err.Error()})
		return
	}

	_, err = client.Collection("domains").Doc(domain.Domain).Get(ctx)
	if err == nil {
		fmt.Printf("domain %s already exists\n", domain.Domain)
		rw.WriteHeader(http.StatusBadRequest)
		sendMessage(rw, &message{"domain already exists"})
		return
	}

	token, err := dns.NewToken(domain.Domain, GOPKGSKEY, &timeout)
	if err != nil {
		fmt.Printf("failed to create token: %s\n", err)
		rw.WriteHeader(http.StatusInternalServerError)
		sendMessage(rw, &message{err.Error()})
		return
	}

	host := &gois.Host{
		ID:     uuid.New().String(),
		Owner:  "benji@devnw.com",
		Domain: domain.Domain,
		Token:  token,
	}

	_, err = client.Collection("domains").Doc(domain.Domain).Create(ctx, host)
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

func domainsHandlerDelete(rw http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	// aInfo, ok := ctx.Value(ainfo).(auth)
	// if !ok {
	// 	fmt.Printf("failed to get auth info\n")
	// 	rw.WriteHeader(http.StatusUnauthorized)
	// 	sendMessage(rw, &message{"failed to get auth info"})
	// 	return
	// }

	log.Printf("DELETE %s\n", r.URL.Path)
	id := r.URL.Query().Get("id")
	if id == "" {
		rw.WriteHeader(http.StatusBadRequest)
		sendMessage(rw, &message{"missing ID"})
		return
	}

	client, err := createClient(ctx)
	if err != nil {
		fmt.Printf("failed to create client: %s\n", err)
		rw.WriteHeader(http.StatusInternalServerError)
		sendMessage(rw, &message{err.Error()})
		return
	}

	// var d *firestore.DocumentSnapshot
	d, err := client.Collection("domains").Where("ID", "==", id).Limit(1).Documents(ctx).Next()
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

func domainsHandlerGet(rw http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	aInfo, ok := ctx.Value(ainfo).(auth)
	if !ok {
		fmt.Printf("failed to get auth info\n")
		rw.WriteHeader(http.StatusUnauthorized)
		sendMessage(rw, &message{"failed to get auth info"})
		return
	}

	fmt.Printf(
		"email: %s; auth provider: %s; auth ID: %s\n",
		aInfo.email,
		aInfo.provider,
		aInfo.id,
	)

	client, err := createClient(ctx)
	if err != nil {
		fmt.Printf("failed to create client: %s\n", err)
		rw.WriteHeader(http.StatusInternalServerError)
		sendMessage(rw, &message{err.Error()})
		return
	}

	domain := "go.devnw.com"

	// var d *firestore.DocumentSnapshot
	d, err := client.Collection("domains").Doc(domain).Get(ctx)
	if err != nil {
		fmt.Printf("failed to get domain: %s\n", err)
		err = fmt.Errorf(
			"failed to lookup host [%s] in firestore: %s",
			domain,
			err,
		)
		rw.WriteHeader(http.StatusInternalServerError)
		sendMessage(rw, &message{err.Error()})
		return
	}

	// fmt.Printf("collection data from firebase: %s\n", spew.Sdump(d))

	h := &gois.Host{}
	err = d.DataTo(h)
	if err != nil {
		fmt.Printf("failed to convert data to host: %s\n", err)
		err = fmt.Errorf(
			"failed to map host [%s] to object: %s",
			domain,
			err,
		)
		rw.WriteHeader(http.StatusInternalServerError)
		sendMessage(rw, &message{err.Error()})
		return
	}

	// h.Modules["bk"] = &gois.Module{
	// 	Domain: "go.devnw.com",
	// 	Path:   "bk",
	// 	Proto:  "git",
	// 	Repo:   u("https://github.com/devnw/bridgekeeper"),
	// 	Docs:   u("https://pkg.go.dev/go.devnw.com/bk"),
	// }

	// _, err = client.Collection("domains").Doc(domain).Set(ctx, h)
	// if err != nil {
	// 	err = fmt.Errorf(
	// 		"failed to update host [%s] record: %s",
	// 		domain,
	// 		err,
	// 	)
	// 	fmt.Printf("%s\n", err)
	// 	rw.WriteHeader(http.StatusUnauthorized)
	// 	sendMessage(rw, &message{fmt.Sprintf("%s\n", err)})
	// 	return
	// }

	// return

	if h.Token.Validated == nil {
		// TODO: Set this up to attempt validation
		fmt.Printf("Awaiting Validation\n")
		rw.WriteHeader(http.StatusUnauthorized)
		sendMessage(rw, &message{"Token not yet validated"})
		return
	}

	data, err := json.Marshal(struct {
		Domain      string
		Owner       string
		Maintainers []string
		ValidateBy  time.Time
		Validated   *time.Time
		Updated     *time.Time
		Token       string
		Modules     []*gois.Module
	}{
		Domain: domain,
		Owner:  "benji@devnw.com",
		Maintainers: []string{
			"benji.vesterby@gmail.com",
			"benji@benjiv.com",
		},
		ValidateBy: h.Token.ValidateBy,
		Validated:  nil,
		Token:      h.Token.String(),
		Modules:    Map[string, *gois.Module](h.Modules).Values(),
	})
	if err != nil {
		fmt.Printf("failed to marshal host: %s\n", err)
		err = fmt.Errorf(
			"failed to marshal host [%s] to JSON: %s",
			domain,
			err,
		)
		rw.WriteHeader(http.StatusInternalServerError)
		sendMessage(rw, &message{err.Error()})
		return
	}

	// defer fmt.Printf("wrote host data: %s\n", string(data))
	rw.Write(data)
}

func publicApiHandler(rw http.ResponseWriter, _ *http.Request) {
	sendMessage(rw, publicMessage)
}

func protectedApiHandler(rw http.ResponseWriter, _ *http.Request) {
	sendMessage(rw, protectedMessage)
}

func adminApiHandler(rw http.ResponseWriter, _ *http.Request) {
	sendMessage(rw, adminMessage)
}
