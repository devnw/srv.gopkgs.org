package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"cloud.google.com/go/firestore"
	"go.devnw.com/gois"
	. "go.structs.dev/gen"
)

const (
	AUDIENCE    = "https://api.gopkgs.org"
	DOMAIN      = "devnw.us.auth0.com"
	DOMAINREGEX = `^((?!-))(xn--)?[a-z0-9][a-z0-9-_]{0,61}[a-z0-9]{0,1}\.(xn--)?([a-z0-9\-]{1,61}|[a-z0-9-]{1,30}\.[a-z]{2,})$`
)

func u(path string) *url.URL {
	uuu, _ := url.Parse(path)
	return uuu
}

// Compile the regex immediately.
// var DomainReggy = regexp.MustCompile(DOMAINREGEX)

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
		validateToken(
			authInfo(
				http.HandlerFunc(domainsHandler),
			),
		),
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
	case http.MethodPost:
		domainsHandlerPost(rw, r)
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
