// Package storage issues and validates short-lived download URLs.
//
// Terraform follows the X-Terraform-Get header without carrying the
// Authorization header to the target, which is exactly why the reference
// registries hand out presigned object-store URLs. This package is the local
// equivalent: an HMAC-signed, expiring URL served by the registry itself. It is
// the same shape as an S3 presign, so swapping in a real bucket later is a
// backend change, not a protocol change.
package storage

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Errors returned by Verify. Callers map all of them to 403: telling a client
// which of the two failed is free information for someone probing.
var (
	ErrExpired      = errors.New("storage: download link has expired")
	ErrBadSignature = errors.New("storage: download link signature is invalid")
)

// Signer mints and checks expiring download links.
type Signer struct {
	key []byte
	ttl time.Duration
}

// NewSigner returns a Signer. An empty key is rejected rather than quietly
// producing forgeable links.
func NewSigner(key []byte, ttl time.Duration) (*Signer, error) {
	if len(key) < 16 {
		return nil, errors.New("storage: signing key must be at least 16 bytes")
	}
	if ttl <= 0 {
		return nil, errors.New("storage: link ttl must be positive")
	}
	return &Signer{key: append([]byte(nil), key...), ttl: ttl}, nil
}

// RandomKey generates an ephemeral signing key, used when the operator has not
// supplied one. Links minted with it die with the process, which is acceptable
// for a single-box deployment and is logged loudly at startup.
func RandomKey() ([]byte, error) {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, fmt.Errorf("storage: generate signing key: %w", err)
	}
	return k, nil
}

// TTL is the lifetime of minted links.
func (s *Signer) TTL() time.Duration { return s.ttl }

// Sign returns baseURL + path with expiry and signature query parameters
// attached. path must be the absolute request path the client will fetch.
func (s *Signer) Sign(baseURL, path string, now time.Time) string {
	exp := now.Add(s.ttl).Unix()
	q := url.Values{}
	q.Set("exp", strconv.FormatInt(exp, 10))
	q.Set("sig", s.mac(path, exp))
	return strings.TrimRight(baseURL, "/") + path + "?" + q.Encode()
}

// Verify checks the query parameters attached to a request for path.
func (s *Signer) Verify(path string, q url.Values, now time.Time) error {
	exp, err := strconv.ParseInt(q.Get("exp"), 10, 64)
	if err != nil {
		return ErrBadSignature
	}
	want := s.mac(path, exp)
	got := q.Get("sig")
	// Compare before checking expiry so an attacker cannot use the error to
	// distinguish "wrong signature" from "right signature, too late".
	if !hmac.Equal([]byte(want), []byte(got)) {
		return ErrBadSignature
	}
	if now.Unix() > exp {
		return ErrExpired
	}
	return nil
}

func (s *Signer) mac(path string, exp int64) string {
	m := hmac.New(sha256.New, s.key)
	// Length-prefix-free but unambiguous: the path cannot contain a newline
	// because it came out of a URL.
	fmt.Fprintf(m, "%s\n%d", path, exp)
	return hex.EncodeToString(m.Sum(nil))
}

// DecodeKey accepts a signing key as raw text or standard base64, so operators
// can paste whatever their secret store gives them.
func DecodeKey(s string) []byte {
	s = strings.TrimSpace(s)
	if raw, err := base64.StdEncoding.DecodeString(s); err == nil && len(raw) >= 16 {
		return raw
	}
	return []byte(s)
}
