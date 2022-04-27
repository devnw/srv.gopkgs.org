package gois

import (
	"embed"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"text/template"
	"time"

	"github.com/google/uuid"
	"go.devnw.com/dns"
)

const GOPKGS = "https://gopkgs.org"

type Protocol string

const (
	// Mod is the indicator that the module is being provided through
	// a different module proxy versus a direct version control system.
	Mod Protocol = "mod"

	// Git VCS support
	Git Protocol = "git"

	// Subversion VCS support
	Subversion Protocol = "svn"

	// Mercurial VCS support
	Mercurial Protocol = "hg"

	// Fossil VCS support
	Fossil Protocol = "fossil"

	// Bazaar VCS support
	Bazaar Protocol = "bzr"
)

type Records []*Host

type Host struct {
	ID          string
	Domain      string
	Owner       string
	Maintainers map[string]bool
	Token       *dns.Token
	Modules     map[string]*Module
}

func (h Host) MarshalJSON() ([]byte, error) {
	out := struct {
		ID          string    `json:"id"`
		Domain      string    `json:"domain"`
		Owner       string    `json:"owner"`
		Maintainers []string  `json:"maintainers"`
		Token       string    `json:"token"`
		Validated   bool      `json:"validated"`
		ValidateBy  time.Time `json:"validate_by"`
		Modules     []*Module
	}{
		ID:          h.ID,
		Domain:      h.Domain,
		Owner:       h.Owner,
		Maintainers: []string{},
		Token:       h.Token.String(),
		Validated:   h.Token.Validated != nil,
		ValidateBy:  h.Token.ValidateBy,
		Modules:     make([]*Module, 0, len(h.Modules)),
	}

	// Append the maintainers
	for k, v := range h.Maintainers {
		if v {
			out.Maintainers = append(out.Maintainers, k)
		}
	}

	// Append the modules
	for _, m := range h.Modules {
		out.Modules = append(out.Modules, m)
	}

	data, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}

	return data, nil
}

// func (r Records) Handle(w http.ResponseWriter, req *http.Request) {
// 	h := strings.Split(req.Host, ":")
// 	if len(h) == 0 {
// 		panic("no host")
// 	}

// 	host := h[0]
// 	_, ok := r[host]
// 	if !ok {
// 		w.WriteHeader(http.StatusNotFound)
// 	}

// 	fmt.Printf("Serving Host: %+v\n", host)

// 	module, ok := r[host][strings.TrimPrefix(req.URL.Path, "/")]
// 	if !ok {
// 		w.WriteHeader(http.StatusNotFound)
// 		return
// 	}

// 	// Ensure the host is updated
// 	module.Host = host
// 	module.Handle(w, req)
// }

// func (r Records) UnmarshalJSON(data []byte) error {
// 	var hosts []Host

// 	err := json.Unmarshal(data, &hosts)
// 	if err != nil {
// 		return err
// 	}

// 	for _, h := range hosts {
// 		r[h.Domain] = h
// 	}

// 	return nil
// }

// type Host struct {
// 	Domain  string
// 	Modules map[string]Module
// }

// func (h Host) Handle(w http.ResponseWriter, r *http.Request) {
// 	module, ok := h.Modules[strings.TrimPrefix(r.URL.Path, "/")]
// 	if !ok {
// 		w.WriteHeader(http.StatusNotFound)
// 		return
// 	}

// 	fmt.Printf("Serving Module: %+v\n", module)

// 	module.Handle(w, r)
// }

type Module struct {
	Domain string `firestore:"-"`
	ID     string
	Path   string
	Proto  Protocol
	Repo   *url.URL
	Docs   *url.URL
}

//go:embed template.go.html
var fs embed.FS

var tmpl = template.Must(template.ParseFS(fs, "template.go.html"))

func (m *Module) Handle(w http.ResponseWriter, r *http.Request) {
	log.Printf("Serving Module: %+v\n", m)

	// Redirect the user to the documentation address if available
	if r.URL.Query().Get("go-get") == "1" {
		log.Printf("Serving Module: %+v; GO-GET\n", m)
		tmpl.Execute(w, m)
	} else {
		redirectURL := m.Docs
		if redirectURL == nil {
			u, _ := url.Parse(GOPKGS)
			redirectURL = u
		}
		log.Printf("Serving Module: %+v; REDIRECT\n", m)

		if redirectURL == nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		http.Redirect(w, r, redirectURL.String(), http.StatusSeeOther)
	}
}

func (m *Module) ModImport() string {
	return fmt.Sprintf("%s/%s", m.Domain, m.Path)
}

func (m Module) MarshalJSON() ([]byte, error) {
	var docs string
	if m.Docs != nil {
		docs = m.Docs.String()
	}

	out := struct {
		ID    string `json:"id"`
		Path  string `json:"path"`
		Proto string `json:"type"`
		Repo  string `json:"repo"`
		Docs  string `json:"docs,omitempty"`
	}{
		ID:    m.ID,
		Path:  m.Path,
		Proto: string(m.Proto),
		Repo:  m.Repo.String(),
		Docs:  docs,
	}

	data, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func (m *Module) UnmarshalJSON(data []byte) error {
	mod := struct {
		ID    string `json:"id"`
		Path  string `json:"path"`
		Proto string `json:"type"`
		Repo  string `json:"repo"`
		Docs  string `json:"docs,omitempty"`
	}{}

	err := json.Unmarshal(data, &mod)
	if err != nil {
		return err
	}

	m.Path = mod.Path
	m.Proto = Protocol(mod.Proto)
	m.Repo, err = url.Parse(mod.Repo)
	if err != nil {
		return err
	}

	if mod.Docs != "" {
		m.Docs, err = url.Parse(mod.Docs)
		if err != nil {
			return err
		}
	}

	m.ID = mod.ID
	if m.ID == "" {
		m.ID = uuid.New().String()
	}

	return nil
}
