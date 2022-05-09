package gois

import (
	"embed"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"text/template"
	"time"

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

func (p Protocol) Valid() bool {
	switch p {
	case Git, Subversion, Mercurial, Fossil, Bazaar, Mod:
		return true
	}

	return false
}

type Records []*Host

type Host struct {
	ID      string
	Domain  string
	Owner   string
	Created time.Time
	Token   *dns.Token
	Modules map[string]*Module
}

func (h *Host) MarshalJSON() ([]byte, error) {
	out := struct {
		ID         string    `json:"id"`
		Domain     string    `json:"domain"`
		Owner      string    `json:"owner"`
		Created    time.Time `json:"created"`
		Token      string    `json:"token"`
		Validated  bool      `json:"validated"`
		ValidateBy time.Time `json:"validate_by"`
		Modules    []*Module `json:"modules"`
	}{
		ID:         h.ID,
		Domain:     h.Domain,
		Owner:      h.Owner,
		Created:    h.Created,
		Token:      h.Token.String(),
		Validated:  h.Token.Validated != nil,
		ValidateBy: h.Token.ValidateBy,
		Modules:    make([]*Module, 0, len(h.Modules)),
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

type Module struct {
	Domain string `firestore:"-"`
	Path   string
	Proto  Protocol
	Repo   *url.URL
	Docs   *url.URL
}

//go:embed template.go.html
var fs embed.FS

var tmpl = template.Must(template.ParseFS(fs, "template.go.html"))

func (m *Module) Handle(w http.ResponseWriter, r *http.Request) error {
	// Redirect the user to the documentation address if available
	if r.URL.Query().Get("go-get") == "1" {
		err := tmpl.Execute(w, m)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return fmt.Errorf("error serving module: %+v", err)
		}
	} else {
		redirectURL := m.Docs
		if redirectURL == nil {
			u, _ := url.Parse(GOPKGS)
			redirectURL = u
		}

		if redirectURL == nil {
			w.WriteHeader(http.StatusNotFound)
			return fmt.Errorf("no redirect URL found for module: %+v", m)
		}

		http.Redirect(w, r, redirectURL.String(), http.StatusSeeOther)
	}

	return nil
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
		Path  string `json:"path"`
		Proto string `json:"type"`
		Repo  string `json:"repo"`
		Docs  string `json:"docs,omitempty"`
	}{
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
		Path  string `json:"path"`
		Proto string `json:"type"`
		Repo  string `json:"repo"`
		Docs  string `json:"docs,omitempty"`
	}{}

	err := json.Unmarshal(data, &mod)
	if err != nil {
		return err
	}

	m.Path = url.PathEscape(mod.Path)

	m.Proto = Protocol(mod.Proto)
	if !m.Proto.Valid() {
		return fmt.Errorf("invalid protocol: %s", mod.Proto)
	}

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

	return nil
}
