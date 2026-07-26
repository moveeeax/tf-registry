package auth

import (
	"net/http"
	"strings"
	"testing"
)

func TestGenerateTokenRoundTrip(t *testing.T) {
	token, digest, err := GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	if !strings.HasPrefix(token, TokenPrefix) {
		t.Errorf("token %q does not carry the %q prefix", token, TokenPrefix)
	}
	if len(digest) != 64 {
		t.Errorf("digest = %q, want 64 hex chars", digest)
	}
	if Digest(token) != digest {
		t.Error("Digest(token) disagrees with GenerateToken")
	}

	other, _, err := GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	if other == token {
		t.Error("two generated tokens collided")
	}

	store, err := NewStore([]Org{{Name: "acme", Namespaces: []string{"acme"}, TokenSHA256: digest}})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	org, ok := store.Lookup(token)
	if !ok {
		t.Fatal("Lookup with the generated token failed")
	}
	if org.Name != "acme" {
		t.Errorf("org = %q, want acme", org.Name)
	}
	if _, ok := store.Lookup(other); ok {
		t.Error("Lookup accepted an unrelated token")
	}
	if _, ok := store.Lookup(""); ok {
		t.Error("Lookup accepted an empty token")
	}
	if _, ok := store.Lookup(strings.ToUpper(token)); ok {
		t.Error("Lookup should be case-sensitive on the token itself")
	}
}

func TestNewStoreRejectsBadConfig(t *testing.T) {
	good := Digest("tfr_one")
	cases := map[string][]Org{
		"no name":       {{Namespaces: []string{"acme"}, TokenSHA256: good}},
		"short digest":  {{Name: "acme", Namespaces: []string{"acme"}, TokenSHA256: "deadbeef"}},
		"not hex":       {{Name: "acme", Namespaces: []string{"acme"}, TokenSHA256: strings.Repeat("z", 64)}},
		"no namespaces": {{Name: "acme", TokenSHA256: good}},
		"shared token": {
			{Name: "acme", Namespaces: []string{"acme"}, TokenSHA256: good},
			{Name: "globex", Namespaces: []string{"globex"}, TokenSHA256: good},
		},
	}
	for name, orgs := range cases {
		if _, err := NewStore(orgs); err == nil {
			t.Errorf("NewStore(%s): want error", name)
		}
	}
}

func TestNewStoreNormalisesDigestCase(t *testing.T) {
	digest := Digest("tfr_upper")
	store, err := NewStore([]Org{{
		Name: "acme", Namespaces: []string{"acme"}, TokenSHA256: "  " + strings.ToUpper(digest) + "  ",
	}})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if _, ok := store.Lookup("tfr_upper"); !ok {
		t.Error("an upper-case, padded digest in config should still match")
	}
}

func TestCanRead(t *testing.T) {
	scoped := &Org{Name: "acme", Namespaces: []string{"acme", "acme-labs"}}
	if !scoped.CanRead("acme") || !scoped.CanRead("acme-labs") {
		t.Error("org should read its own namespaces")
	}
	if scoped.CanRead("globex") {
		t.Error("org must not read another namespace")
	}

	admin := &Org{Name: "ops", Namespaces: []string{"*"}}
	if !admin.CanRead("anything") {
		t.Error("wildcard namespace should grant everything")
	}
}

func TestBearerToken(t *testing.T) {
	cases := map[string]string{
		"Bearer tfr_abc":    "tfr_abc",
		"bearer tfr_abc":    "tfr_abc",
		"BEARER  tfr_abc  ": "tfr_abc",
		"Basic tfr_abc":     "",
		"tfr_abc":           "",
		"":                  "",
		"Bearer":            "",
	}
	for header, want := range cases {
		r, err := http.NewRequest(http.MethodGet, "http://example.invalid/", nil)
		if err != nil {
			t.Fatal(err)
		}
		if header != "" {
			r.Header.Set("Authorization", header)
		}
		if got := BearerToken(r); got != want {
			t.Errorf("BearerToken(%q) = %q, want %q", header, got, want)
		}
	}
}
