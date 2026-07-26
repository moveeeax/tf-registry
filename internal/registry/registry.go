// Package registry implements the read-only half of the Terraform module
// registry protocol.
//
// Three endpoints do the whole job:
//
//	GET /.well-known/terraform.json                                 discovery
//	GET /v1/modules/{ns}/{name}/{system}/versions                   version list
//	GET /v1/modules/{ns}/{name}/{system}/{version}/download         204 + X-Terraform-Get
//
// Everything else here — the artifact endpoint and the counts page — exists to
// serve those three. Publishing is not an HTTP API in v1: modules land in the
// catalog directory from CI, and the server is reloaded.
package registry

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/moveeeax/tf-registry/internal/auth"
	"github.com/moveeeax/tf-registry/internal/catalog"
	"github.com/moveeeax/tf-registry/internal/counter"
	"github.com/moveeeax/tf-registry/internal/storage"
)

// Config wires the server's collaborators. Every field except Logger and Now is
// required.
type Config struct {
	Catalog  *catalog.Catalog
	Auth     *auth.Store
	Signer   *storage.Signer
	Counter  *counter.Counter
	BaseURL  string // external origin, e.g. https://registry.example.com
	Logger   *slog.Logger
	Now      func() time.Time // injectable clock, for tests
	Requires bool             // signatures were required at load time (reported on /counts)
}

// Server is an http.Handler serving the registry protocol.
type Server struct {
	mu  sync.RWMutex
	cat *catalog.Catalog

	auth     *auth.Store
	signer   *storage.Signer
	counter  *counter.Counter
	baseURL  string
	log      *slog.Logger
	now      func() time.Time
	requires bool
}

// New validates the config and returns a Server.
func New(cfg Config) (*Server, error) {
	switch {
	case cfg.Catalog == nil:
		return nil, errors.New("registry: catalog is required")
	case cfg.Auth == nil:
		return nil, errors.New("registry: auth store is required")
	case cfg.Signer == nil:
		return nil, errors.New("registry: url signer is required")
	case cfg.Counter == nil:
		return nil, errors.New("registry: counter is required")
	case cfg.BaseURL == "":
		return nil, errors.New("registry: base url is required")
	}
	s := &Server{
		cat:      cfg.Catalog,
		auth:     cfg.Auth,
		signer:   cfg.Signer,
		counter:  cfg.Counter,
		baseURL:  strings.TrimRight(cfg.BaseURL, "/"),
		log:      cfg.Logger,
		now:      cfg.Now,
		requires: cfg.Requires,
	}
	if s.log == nil {
		s.log = slog.Default()
	}
	if s.now == nil {
		s.now = time.Now
	}
	return s, nil
}

// SetCatalog swaps in a freshly loaded catalog, for reload-on-SIGHUP.
func (s *Server) SetCatalog(c *catalog.Catalog) {
	s.mu.Lock()
	s.cat = c
	s.mu.Unlock()
}

func (s *Server) catalogRef() *catalog.Catalog {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cat
}

// Handler returns the routed handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/terraform.json", s.handleDiscovery)
	mux.HandleFunc("GET /v1/modules/{namespace}/{name}/{system}/versions", s.handleVersions)
	mux.HandleFunc("GET /v1/modules/{namespace}/{name}/{system}/{version}/download", s.handleDownload)
	mux.HandleFunc("GET /v1/modules/{namespace}/{name}/{system}/download", s.handleLatestDownload)
	mux.HandleFunc("GET /artifacts/{namespace}/{name}/{system}/{version}/"+catalog.ArchiveName, s.handleArtifact)
	mux.HandleFunc("GET /counts", s.handleCounts)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintln(w, "ok")
	})
	return mux
}

// handleDiscovery answers the service discovery document. Terraform fetches it
// before anything else, unauthenticated — it must not require a token, or
// `terraform login` style flows break before they start.
func (s *Server) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"modules.v1": "/v1/modules/"})
}

type versionsResponse struct {
	Modules []moduleVersions `json:"modules"`
}

type moduleVersions struct {
	Versions []versionEntry `json:"versions"`
}

type versionEntry struct {
	Version string `json:"version"`
}

func (s *Server) handleVersions(w http.ResponseWriter, r *http.Request) {
	mod, ok := s.resolve(w, r)
	if !ok {
		return
	}
	resp := versionsResponse{Modules: []moduleVersions{{Versions: make([]versionEntry, 0, len(mod.Versions))}}}
	for _, v := range mod.Versions {
		resp.Modules[0].Versions = append(resp.Modules[0].Versions, versionEntry{Version: v.Version})
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleDownload answers with 204 and an X-Terraform-Get header, as the
// protocol requires. The header points at a short-lived signed URL because
// Terraform does not forward the Authorization header when it follows it.
func (s *Server) handleDownload(w http.ResponseWriter, r *http.Request) {
	mod, ok := s.resolve(w, r)
	if !ok {
		return
	}
	version := r.PathValue("version")
	v := mod.Find(version)
	if v == nil {
		writeError(w, http.StatusNotFound, "version not found")
		return
	}

	p := path.Join("/artifacts", mod.Namespace, mod.Name, mod.System, v.Version, catalog.ArchiveName)
	w.Header().Set("X-Terraform-Get", s.signer.Sign(s.baseURL, p, s.now()))
	// Not part of the protocol, but it lets a client pin what it is about to
	// fetch without unpacking the archive first.
	w.Header().Set("X-Module-SHA256", v.SHA256)
	w.WriteHeader(http.StatusNoContent)
}

// handleLatestDownload redirects to the newest stable version's download
// endpoint, which is what Terraform asks for when no version is pinned.
func (s *Server) handleLatestDownload(w http.ResponseWriter, r *http.Request) {
	mod, ok := s.resolve(w, r)
	if !ok {
		return
	}
	latest := mod.Latest()
	if latest == nil {
		writeError(w, http.StatusNotFound, "module has no published versions")
		return
	}
	target := path.Join("/v1/modules", mod.Namespace, mod.Name, mod.System, latest.Version, "download")
	http.Redirect(w, r, target, http.StatusFound)
}

// handleArtifact serves the tarball itself. Authorisation here comes from the
// signed URL, not from a bearer token.
func (s *Server) handleArtifact(w http.ResponseWriter, r *http.Request) {
	namespace := r.PathValue("namespace")
	name := r.PathValue("name")
	system := r.PathValue("system")
	version := r.PathValue("version")

	if err := s.signer.Verify(r.URL.Path, r.URL.Query(), s.now()); err != nil {
		s.log.Warn("rejected artifact request",
			"path", r.URL.Path, "reason", err, "remote", r.RemoteAddr)
		// Deliberately identical response for expired and forged links.
		writeError(w, http.StatusForbidden, "invalid or expired download link")
		return
	}

	mod := s.catalogRef().Module(namespace, name, system)
	if mod == nil {
		writeError(w, http.StatusNotFound, "module not found")
		return
	}
	v := mod.Find(version)
	if v == nil {
		writeError(w, http.StatusNotFound, "version not found")
		return
	}

	key := counter.Key(namespace, name, system, v.Version)
	if err := s.counter.Inc(key); err != nil {
		// A counter that cannot persist must not block a download.
		s.log.Error("failed to record download", "key", key, "err", err)
	}

	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("X-Module-SHA256", v.SHA256)
	w.Header().Set("Content-Disposition",
		fmt.Sprintf("attachment; filename=%q", fmt.Sprintf("%s-%s-%s-%s.tar.gz", namespace, name, system, v.Version)))
	http.ServeFile(w, r, v.Archive)
}

// handleCounts is the single page of download numbers v1 promises. Plain text,
// token-authenticated, scoped to the caller's namespaces.
func (s *Server) handleCounts(w http.ResponseWriter, r *http.Request) {
	org, ok := s.authenticate(w, r)
	if !ok {
		return
	}

	cat := s.catalogRef()
	var b strings.Builder
	fmt.Fprintf(&b, "# tf-registry download counts for %s\n", org.Name)
	fmt.Fprintf(&b, "# signatures required: %v\n\n", s.requires)
	fmt.Fprintf(&b, "%-40s %10s %8s\n", "MODULE/VERSION", "DOWNLOADS", "SIGNED")
	for _, mod := range cat.Modules() {
		if !org.CanRead(mod.Namespace) {
			continue
		}
		for _, v := range mod.Versions {
			key := counter.Key(mod.Namespace, mod.Name, mod.System, v.Version)
			fmt.Fprintf(&b, "%-40s %10d %8v\n", key, s.counter.Total(key), v.Signed)
		}
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprint(w, b.String())
}

// resolve authenticates the caller, checks namespace access and looks the
// module up. It writes the error response itself and reports whether the
// handler should continue.
func (s *Server) resolve(w http.ResponseWriter, r *http.Request) (*catalog.Module, bool) {
	org, ok := s.authenticate(w, r)
	if !ok {
		return nil, false
	}
	namespace := r.PathValue("namespace")
	name := r.PathValue("name")
	system := r.PathValue("system")

	mod := s.catalogRef().Module(namespace, name, system)
	// A token that may not read the namespace gets the same 404 as a module
	// that does not exist: the catalog is not an enumeration oracle.
	if mod == nil || !org.CanRead(namespace) {
		writeError(w, http.StatusNotFound, "module not found")
		return nil, false
	}
	return mod, true
}

func (s *Server) authenticate(w http.ResponseWriter, r *http.Request) (*auth.Org, bool) {
	token := auth.BearerToken(r)
	org, ok := s.auth.Lookup(token)
	if !ok {
		w.Header().Set("WWW-Authenticate", `Bearer realm="tf-registry"`)
		writeError(w, http.StatusUnauthorized, "a valid bearer token is required")
		return nil, false
	}
	return org, true
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		slog.Default().Error("failed to encode response", "err", err)
	}
}

// writeError uses the errors array shape the registry protocol specifies, so
// Terraform surfaces the message instead of "unexpected response".
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string][]string{"errors": {msg}})
}
