// Package auth implements the one thing v1 promises: a single bearer token per
// org, compatible with `terraform login` credentials blocks.
//
// No SSO, no OIDC, no RBAC. Tokens are stored as SHA-256 digests, so the config
// file on the box is not itself a set of credentials: losing it does not hand
// anyone a working token.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// TokenPrefix marks our tokens in logs and issue reports so a leaked one is
// recognisable on sight.
const TokenPrefix = "tfr_"

// Org is a tenant. Namespaces are the catalog namespaces its token may read.
type Org struct {
	Name        string   `json:"name"`
	Namespaces  []string `json:"namespaces"`
	TokenSHA256 string   `json:"token_sha256"`
}

// CanRead reports whether the org may read the given catalog namespace. A
// literal "*" grants every namespace, which is what the operator's own
// break-glass token uses.
func (o *Org) CanRead(namespace string) bool {
	for _, ns := range o.Namespaces {
		if ns == "*" || ns == namespace {
			return true
		}
	}
	return false
}

// Store resolves bearer tokens to orgs.
type Store struct {
	byDigest map[string]*Org
}

// NewStore indexes orgs by token digest. It rejects configs that would silently
// misbehave: a missing or malformed digest, or two orgs sharing one token.
func NewStore(orgs []Org) (*Store, error) {
	s := &Store{byDigest: make(map[string]*Org, len(orgs))}
	for i := range orgs {
		o := orgs[i]
		if o.Name == "" {
			return nil, errors.New("auth: org with no name")
		}
		digest := strings.ToLower(strings.TrimSpace(o.TokenSHA256))
		if len(digest) != 64 {
			return nil, fmt.Errorf("auth: org %q: token_sha256 must be a 64-character hex digest", o.Name)
		}
		if _, err := hex.DecodeString(digest); err != nil {
			return nil, fmt.Errorf("auth: org %q: token_sha256 is not hex: %w", o.Name, err)
		}
		if prev, dup := s.byDigest[digest]; dup {
			return nil, fmt.Errorf("auth: orgs %q and %q share a token", prev.Name, o.Name)
		}
		if len(o.Namespaces) == 0 {
			return nil, fmt.Errorf("auth: org %q has no namespaces and could never read anything", o.Name)
		}
		s.byDigest[digest] = &o
	}
	return s, nil
}

// Lookup resolves a presented token. The token is hashed before it is used as a
// map key, so lookup time does not leak the secret.
func (s *Store) Lookup(token string) (*Org, bool) {
	if token == "" {
		return nil, false
	}
	sum := sha256.Sum256([]byte(token))
	o, ok := s.byDigest[hex.EncodeToString(sum[:])]
	return o, ok
}

// Len is the number of configured orgs.
func (s *Store) Len() int { return len(s.byDigest) }

// BearerToken extracts a token from the Authorization header. Terraform sends
// "Authorization: Bearer <token>" for both the registry protocol and the
// credentials block, and the scheme is case-insensitive per RFC 7235.
func BearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	const scheme = "bearer "
	if len(h) < len(scheme) || !strings.EqualFold(h[:len(scheme)], scheme) {
		return ""
	}
	return strings.TrimSpace(h[len(scheme):])
}

// GenerateToken mints a token and returns it with its digest. Only the digest
// belongs in a config file; the token itself is shown once and never stored.
func GenerateToken() (token, digest string, err error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", "", fmt.Errorf("auth: generate token: %w", err)
	}
	token = TokenPrefix + base64.RawURLEncoding.EncodeToString(buf)
	sum := sha256.Sum256([]byte(token))
	return token, hex.EncodeToString(sum[:]), nil
}

// Digest hashes a token the same way the store does, for `tf-registry token
// --hash` on a token the operator already holds.
func Digest(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
