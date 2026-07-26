package registry

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/moveeeax/tf-registry/internal/auth"
	"github.com/moveeeax/tf-registry/internal/catalog"
	"github.com/moveeeax/tf-registry/internal/counter"
	"github.com/moveeeax/tf-registry/internal/signature"
	"github.com/moveeeax/tf-registry/internal/storage"
)

const (
	acmeToken   = "tfr_test_acme_token"
	globexToken = "tfr_test_globex_token"
	baseURL     = "https://registry.example.com"
)

var testNow = time.Unix(1_700_000_000, 0)

func newTestServer(t *testing.T) http.Handler {
	t.Helper()

	cat, issues, err := catalog.Load("../../examples/catalog")
	if err != nil {
		t.Fatalf("catalog.Load: %v", err)
	}
	if len(issues) != 0 {
		t.Fatalf("example catalog has issues: %v", issues)
	}
	verifier, err := signature.LoadPublicKeyFile("../../examples/keys/cosign.pub")
	if err != nil {
		t.Fatal(err)
	}
	cat.CheckSignatures(verifier, true)

	store, err := auth.NewStore([]auth.Org{
		{Name: "acme", Namespaces: []string{"acme"}, TokenSHA256: auth.Digest(acmeToken)},
		{Name: "globex", Namespaces: []string{"globex"}, TokenSHA256: auth.Digest(globexToken)},
	})
	if err != nil {
		t.Fatal(err)
	}
	signer, err := storage.NewSigner([]byte("test-signing-key-please-rotate-me"), 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	counts, err := counter.New(filepath.Join(t.TempDir(), "counts.json"))
	if err != nil {
		t.Fatal(err)
	}

	srv, err := New(Config{
		Catalog: cat, Auth: store, Signer: signer, Counter: counts,
		BaseURL:  baseURL,
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now:      func() time.Time { return testNow },
		Requires: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return srv.Handler()
}

func get(t *testing.T, h http.Handler, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, path, nil)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestDiscoveryIsUnauthenticated(t *testing.T) {
	h := newTestServer(t)
	w := get(t, h, "/.well-known/terraform.json", "")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var doc map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Fatalf("discovery document is not JSON: %v", err)
	}
	if doc["modules.v1"] != "/v1/modules/" {
		t.Errorf("modules.v1 = %q, want /v1/modules/", doc["modules.v1"])
	}
}

func TestVersionsEndpoint(t *testing.T) {
	h := newTestServer(t)
	w := get(t, h, "/v1/modules/acme/vpc/aws/versions", acmeToken)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", w.Code, w.Body)
	}

	var resp versionsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("body is not the protocol shape: %v", err)
	}
	if len(resp.Modules) != 1 {
		t.Fatalf("modules = %d, want 1", len(resp.Modules))
	}
	got := make([]string, 0, len(resp.Modules[0].Versions))
	for _, v := range resp.Modules[0].Versions {
		got = append(got, v.Version)
	}
	// 2.0.0-rc.1 is unsigned, so with signatures required it is not advertised.
	if want := []string{"1.2.0", "1.10.0"}; strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("versions = %v, want %v", got, want)
	}
}

func TestAuthIsEnforced(t *testing.T) {
	h := newTestServer(t)

	t.Run("no token", func(t *testing.T) {
		w := get(t, h, "/v1/modules/acme/vpc/aws/versions", "")
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", w.Code)
		}
		if got := w.Header().Get("WWW-Authenticate"); !strings.HasPrefix(got, "Bearer ") {
			t.Errorf("WWW-Authenticate = %q, want a Bearer challenge", got)
		}
	})

	t.Run("wrong token", func(t *testing.T) {
		w := get(t, h, "/v1/modules/acme/vpc/aws/versions", "tfr_not_a_real_token")
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", w.Code)
		}
	})

	t.Run("cross-tenant read is a 404, not a 403", func(t *testing.T) {
		w := get(t, h, "/v1/modules/acme/vpc/aws/versions", globexToken)
		if w.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404 so the catalog cannot be enumerated", w.Code)
		}
		w = get(t, h, "/v1/modules/globex/object-store/oci/versions", globexToken)
		if w.Code != http.StatusOK {
			t.Fatalf("globex reading its own namespace: status = %d, want 200", w.Code)
		}
	})
}

func TestUnknownModuleAndVersion(t *testing.T) {
	h := newTestServer(t)
	for _, p := range []string{
		"/v1/modules/acme/nope/aws/versions",
		"/v1/modules/acme/vpc/gcp/versions",
		"/v1/modules/acme/vpc/aws/9.9.9/download",
		"/v1/modules/acme/vpc/aws/2.0.0-rc.1/download", // unsigned, dropped
	} {
		w := get(t, h, p, acmeToken)
		if w.Code != http.StatusNotFound {
			t.Errorf("GET %s: status = %d, want 404", p, w.Code)
		}
		var body map[string][]string
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || len(body["errors"]) == 0 {
			t.Errorf("GET %s: body %s is not the protocol error shape", p, w.Body)
		}
	}
}

// TestDownloadFlow walks the exact sequence Terraform performs: ask for a
// version's download, follow X-Terraform-Get, get the tarball.
func TestDownloadFlow(t *testing.T) {
	h := newTestServer(t)

	w := get(t, h, "/v1/modules/acme/vpc/aws/1.10.0/download", acmeToken)
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204 (body: %s)", w.Code, w.Body)
	}
	loc := w.Header().Get("X-Terraform-Get")
	if loc == "" {
		t.Fatal("X-Terraform-Get header is empty")
	}
	if !strings.HasPrefix(loc, baseURL+"/artifacts/acme/vpc/aws/1.10.0/module.tar.gz?") {
		t.Fatalf("X-Terraform-Get = %q, want a signed artifact URL", loc)
	}
	digest := w.Header().Get("X-Module-SHA256")
	if len(digest) != 64 {
		t.Errorf("X-Module-SHA256 = %q, want a hex digest", digest)
	}

	u, err := url.Parse(loc)
	if err != nil {
		t.Fatal(err)
	}
	// The artifact URL carries its own authorisation: no bearer token here,
	// because Terraform does not forward one.
	dl := get(t, h, u.Path+"?"+u.RawQuery, "")
	if dl.Code != http.StatusOK {
		t.Fatalf("artifact status = %d, want 200 (body: %s)", dl.Code, dl.Body)
	}
	if got := dl.Header().Get("Content-Type"); got != "application/gzip" {
		t.Errorf("Content-Type = %q, want application/gzip", got)
	}
	if body := dl.Body.Bytes(); len(body) < 2 || body[0] != 0x1f || body[1] != 0x8b {
		t.Error("response body is not a gzip stream")
	}
	if got := dl.Header().Get("X-Module-SHA256"); got != digest {
		t.Errorf("digest changed between the two responses: %q vs %q", got, digest)
	}
}

func TestArtifactRequiresAValidSignedLink(t *testing.T) {
	h := newTestServer(t)
	p := "/artifacts/acme/vpc/aws/1.10.0/module.tar.gz"

	t.Run("unsigned request", func(t *testing.T) {
		if w := get(t, h, p, acmeToken); w.Code != http.StatusForbidden {
			t.Errorf("status = %d, want 403 even with a valid bearer token", w.Code)
		}
	})

	t.Run("forged signature", func(t *testing.T) {
		w := get(t, h, p+"?exp=9999999999&sig="+strings.Repeat("a", 64), "")
		if w.Code != http.StatusForbidden {
			t.Errorf("status = %d, want 403", w.Code)
		}
	})

	t.Run("link minted for another artifact", func(t *testing.T) {
		w := get(t, h, "/v1/modules/acme/aks/azurerm/0.3.1/download", acmeToken)
		u, err := url.Parse(w.Header().Get("X-Terraform-Get"))
		if err != nil {
			t.Fatal(err)
		}
		replayed := get(t, h, p+"?"+u.RawQuery, "")
		if replayed.Code != http.StatusForbidden {
			t.Errorf("status = %d, want 403 when replaying a link at another path", replayed.Code)
		}
	})
}

func TestLatestDownloadRedirects(t *testing.T) {
	h := newTestServer(t)
	w := get(t, h, "/v1/modules/acme/vpc/aws/download", acmeToken)
	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", w.Code)
	}
	if got, want := w.Header().Get("Location"), "/v1/modules/acme/vpc/aws/1.10.0/download"; got != want {
		t.Errorf("Location = %q, want %q", got, want)
	}
}

func TestCountsPage(t *testing.T) {
	h := newTestServer(t)

	// Two downloads of one version, one of another.
	for _, spec := range []struct {
		path  string
		times int
	}{
		{"/v1/modules/acme/vpc/aws/1.10.0/download", 2},
		{"/v1/modules/acme/aks/azurerm/0.3.1/download", 1},
	} {
		for i := 0; i < spec.times; i++ {
			w := get(t, h, spec.path, acmeToken)
			u, err := url.Parse(w.Header().Get("X-Terraform-Get"))
			if err != nil {
				t.Fatal(err)
			}
			if dl := get(t, h, u.Path+"?"+u.RawQuery, ""); dl.Code != http.StatusOK {
				t.Fatalf("download failed: %d", dl.Code)
			}
		}
	}

	w := get(t, h, "/counts", acmeToken)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{
		"acme/vpc/aws/1.10.0",
		"acme/aks/azurerm/0.3.1",
		"acme/vpc/aws/1.2.0",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("counts page is missing %s:\n%s", want, body)
		}
	}
	if strings.Contains(body, "globex/") {
		t.Errorf("counts page leaked another tenant's modules:\n%s", body)
	}

	countFor := func(key string) string {
		for _, line := range strings.Split(body, "\n") {
			if strings.HasPrefix(line, key+" ") {
				return strings.Join(strings.Fields(line)[1:], " ")
			}
		}
		return ""
	}
	if got := countFor("acme/vpc/aws/1.10.0"); got != "2 true" {
		t.Errorf("counts for 1.10.0 = %q, want \"2 true\"", got)
	}
	if got := countFor("acme/vpc/aws/1.2.0"); got != "0 true" {
		t.Errorf("counts for the never-downloaded 1.2.0 = %q, want \"0 true\"", got)
	}

	if w := get(t, h, "/counts", ""); w.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated /counts = %d, want 401", w.Code)
	}
}

func TestExpiredLinkIsRejected(t *testing.T) {
	h := newTestServer(t)
	w := get(t, h, "/v1/modules/acme/vpc/aws/1.10.0/download", acmeToken)
	u, err := url.Parse(w.Header().Get("X-Terraform-Get"))
	if err != nil {
		t.Fatal(err)
	}

	// The server's clock is pinned to testNow; craft a request as if the link
	// were fetched an hour later by rebuilding it against a past clock.
	signer, err := storage.NewSigner([]byte("test-signing-key-please-rotate-me"), 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	old, err := url.Parse(signer.Sign(baseURL, u.Path, testNow.Add(-time.Hour)))
	if err != nil {
		t.Fatal(err)
	}
	if dl := get(t, h, old.Path+"?"+old.RawQuery, ""); dl.Code != http.StatusForbidden {
		t.Errorf("expired link status = %d, want 403", dl.Code)
	}
}

func TestHealthz(t *testing.T) {
	h := newTestServer(t)
	w := get(t, h, "/healthz", "")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "ok") {
		t.Errorf("healthz = %d %q", w.Code, w.Body.String())
	}
}

func TestNewValidatesConfig(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Error("New with an empty config: want error")
	}
}
