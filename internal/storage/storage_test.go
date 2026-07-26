package storage

import (
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"
)

func newSigner(t *testing.T, ttl time.Duration) *Signer {
	t.Helper()
	s, err := NewSigner([]byte("0123456789abcdef0123456789abcdef"), ttl)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	return s
}

func TestSignVerifyRoundTrip(t *testing.T) {
	s := newSigner(t, 5*time.Minute)
	now := time.Unix(1_700_000_000, 0)
	path := "/artifacts/acme/vpc/aws/1.2.0/module.tar.gz"

	link := s.Sign("https://registry.example.com/", path, now)
	if !strings.HasPrefix(link, "https://registry.example.com"+path+"?") {
		t.Fatalf("link = %q, want it to start with the base URL and path", link)
	}

	u, err := url.Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Verify(u.Path, u.Query(), now); err != nil {
		t.Errorf("Verify immediately after signing: %v", err)
	}
	if err := s.Verify(u.Path, u.Query(), now.Add(4*time.Minute)); err != nil {
		t.Errorf("Verify inside the ttl: %v", err)
	}
}

func TestVerifyExpiry(t *testing.T) {
	s := newSigner(t, time.Minute)
	now := time.Unix(1_700_000_000, 0)
	path := "/artifacts/acme/vpc/aws/1.2.0/module.tar.gz"
	u, err := url.Parse(s.Sign("https://registry.example.com", path, now))
	if err != nil {
		t.Fatal(err)
	}

	if err := s.Verify(u.Path, u.Query(), now.Add(time.Minute)); err != nil {
		t.Errorf("Verify exactly at expiry should still pass: %v", err)
	}
	if err := s.Verify(u.Path, u.Query(), now.Add(time.Minute+time.Second)); !errors.Is(err, ErrExpired) {
		t.Errorf("Verify after expiry = %v, want ErrExpired", err)
	}
}

func TestVerifyRejectsTampering(t *testing.T) {
	s := newSigner(t, time.Hour)
	now := time.Unix(1_700_000_000, 0)
	path := "/artifacts/acme/vpc/aws/1.2.0/module.tar.gz"
	u, err := url.Parse(s.Sign("https://registry.example.com", path, now))
	if err != nil {
		t.Fatal(err)
	}

	t.Run("different path", func(t *testing.T) {
		other := "/artifacts/globex/object-store/oci/1.0.0/module.tar.gz"
		if err := s.Verify(other, u.Query(), now); !errors.Is(err, ErrBadSignature) {
			t.Errorf("replaying a link against another artifact = %v, want ErrBadSignature", err)
		}
	})

	t.Run("extended expiry", func(t *testing.T) {
		q := u.Query()
		q.Set("exp", "9999999999")
		if err := s.Verify(u.Path, q, now); !errors.Is(err, ErrBadSignature) {
			t.Errorf("stretching exp = %v, want ErrBadSignature", err)
		}
	})

	t.Run("garbage parameters", func(t *testing.T) {
		for _, q := range []url.Values{
			{},
			{"exp": {"not-a-number"}, "sig": {"deadbeef"}},
			{"exp": {"1700000000"}},
		} {
			if err := s.Verify(u.Path, q, now); !errors.Is(err, ErrBadSignature) {
				t.Errorf("Verify(%v) = %v, want ErrBadSignature", q, err)
			}
		}
	})

	t.Run("different key", func(t *testing.T) {
		other, err := NewSigner([]byte("ffffffffffffffffffffffffffffffff"), time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if err := other.Verify(u.Path, u.Query(), now); !errors.Is(err, ErrBadSignature) {
			t.Errorf("Verify with another key = %v, want ErrBadSignature", err)
		}
	})
}

func TestNewSignerValidation(t *testing.T) {
	if _, err := NewSigner([]byte("too short"), time.Minute); err == nil {
		t.Error("NewSigner with a short key: want error")
	}
	if _, err := NewSigner(make([]byte, 32), 0); err == nil {
		t.Error("NewSigner with zero ttl: want error")
	}
}

func TestRandomKeyAndDecodeKey(t *testing.T) {
	k, err := RandomKey()
	if err != nil {
		t.Fatal(err)
	}
	if len(k) != 32 {
		t.Fatalf("RandomKey length = %d, want 32", len(k))
	}
	k2, err := RandomKey()
	if err != nil {
		t.Fatal(err)
	}
	if string(k) == string(k2) {
		t.Error("RandomKey returned the same key twice")
	}

	if got := DecodeKey("  a-plain-text-secret-value  "); string(got) != "a-plain-text-secret-value" {
		t.Errorf("DecodeKey(plain) = %q", got)
	}
	if got := DecodeKey("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="); len(got) != 32 {
		t.Errorf("DecodeKey(base64) length = %d, want 32", len(got))
	}
}
