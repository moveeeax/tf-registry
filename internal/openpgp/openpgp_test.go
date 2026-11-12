package openpgp

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The fixtures were made with GnuPG 2.5 and only the public halves were kept:
//
//	rsa.asc        RSA-3072 certify-only primary with an RSA-3072 signing subkey,
//	               the shape of HashiCorp's own release key
//	ed25519.asc    Ed25519 primary that signs directly
//	revoked.asc    Ed25519 primary with a signing subkey that was revoked after
//	               it signed SHA256SUMS.revoked.sig (rev-before.asc is the same
//	               key exported before the revocation)
//	other.asc      an unrelated key
//
// SHA256SUMS.*.sig are detached signatures over SHA256SUMS: binary unless
// named .asc, .text.sig in text mode, .expiring.sig with a one-day expiry.

func load(t *testing.T, names ...string) *KeyRing {
	t.Helper()
	kr := &KeyRing{}
	for _, n := range names {
		b, err := os.ReadFile(filepath.Join("testdata", n))
		if err != nil {
			t.Fatal(err)
		}
		if err := kr.AddArmored(b); err != nil {
			t.Fatalf("AddArmored(%s): %v", n, err)
		}
	}
	return kr
}

func read(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

var now = time.Date(2026, 11, 12, 13, 0, 0, 0, time.UTC)

func TestVerifyFixtures(t *testing.T) {
	sums := read(t, "SHA256SUMS")
	cases := []struct {
		key, sig, wantKeyID, wantAlgo string
	}{
		{"rsa.asc", "SHA256SUMS.rsa.sig", "7957AC75E1DB1A9C", "rsa-3072"}, // the subkey, not the primary
		{"rsa.asc", "SHA256SUMS.rsa.asc", "7957AC75E1DB1A9C", "rsa-3072"},
		{"ed25519.asc", "SHA256SUMS.ed25519.sig", "4851632BE35BD5D7", "ed25519"},
		{"ed25519.asc", "SHA256SUMS.text.sig", "4851632BE35BD5D7", "ed25519"},
		{"ed25519.asc", "SHA256SUMS.expiring.sig", "4851632BE35BD5D7", "ed25519"},
		{"rev-before.asc", "SHA256SUMS.revoked.sig", "", "ed25519"},
	}
	for _, c := range cases {
		t.Run(c.sig, func(t *testing.T) {
			kr := load(t, c.key)
			k, err := kr.Verify(sums, read(t, c.sig), now)
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if c.wantKeyID != "" && k.KeyID() != c.wantKeyID {
				t.Errorf("signer = %s, want %s", k.KeyID(), c.wantKeyID)
			}
			if k.Algo != c.wantAlgo {
				t.Errorf("algo = %s, want %s", k.Algo, c.wantAlgo)
			}
		})
	}
}

func TestKeyRingHoldsSeveralKeys(t *testing.T) {
	// The registry returns one armored block per key; a ring built from the
	// concatenation must find the right signer in either order.
	both := append(read(t, "other.asc"), read(t, "rsa.asc")...)
	kr, err := ReadArmoredKeyRing(both)
	if err != nil {
		t.Fatal(err)
	}
	if kr.Len() != 3 {
		t.Errorf("Len = %d, want 3 (two primaries and one subkey)", kr.Len())
	}
	if _, err := kr.Verify(read(t, "SHA256SUMS"), read(t, "SHA256SUMS.rsa.sig"), now); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestVerifyRejectsTamperedDocument(t *testing.T) {
	kr := load(t, "rsa.asc", "ed25519.asc")
	sums := read(t, "SHA256SUMS")
	tampered := bytes.Replace(sums, []byte("1111"), []byte("1112"), 1)
	for _, sig := range []string{"SHA256SUMS.rsa.sig", "SHA256SUMS.ed25519.sig", "SHA256SUMS.text.sig"} {
		if _, err := kr.Verify(tampered, read(t, sig), now); !errors.Is(err, ErrInvalidSignature) {
			t.Errorf("%s over a tampered document: err = %v, want ErrInvalidSignature", sig, err)
		}
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	kr := load(t, "other.asc")
	_, err := kr.Verify(read(t, "SHA256SUMS"), read(t, "SHA256SUMS.rsa.sig"), now)
	if !errors.Is(err, ErrUnknownSigner) {
		t.Fatalf("err = %v, want ErrUnknownSigner", err)
	}
}

func TestVerifyRejectsRevokedSubkey(t *testing.T) {
	kr := load(t, "revoked.asc")
	_, err := kr.Verify(read(t, "SHA256SUMS"), read(t, "SHA256SUMS.revoked.sig"), now)
	if !errors.Is(err, ErrInvalidSignature) || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("err = %v, want a revocation error", err)
	}
}

func TestVerifyRejectsExpiredSignature(t *testing.T) {
	kr := load(t, "ed25519.asc")
	later := now.Add(72 * time.Hour)
	_, err := kr.Verify(read(t, "SHA256SUMS"), read(t, "SHA256SUMS.expiring.sig"), later)
	if !errors.Is(err, ErrInvalidSignature) || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("err = %v, want an expiry error", err)
	}
}

// A subkey whose binding signature is missing is not part of the primary's
// identity, so its signatures must not be attributed to that key.
func TestUnboundSubkeyIsIgnored(t *testing.T) {
	blocks, err := decodeArmor(read(t, "rsa.asc"), "PGP PUBLIC KEY BLOCK")
	if err != nil {
		t.Fatal(err)
	}
	pkts, err := readPackets(blocks[0])
	if err != nil {
		t.Fatal(err)
	}
	var stripped []byte
	afterSubkey := false
	for _, p := range pkts {
		if p.tag == tagSubkey {
			afterSubkey = true
		} else if p.tag == tagSignature && afterSubkey {
			continue // drop the binding signature
		}
		stripped = append(stripped, serialize(p)...)
	}
	kr := &KeyRing{}
	if err := kr.addPackets(stripped); err != nil {
		t.Fatal(err)
	}
	if kr.Len() != 1 {
		t.Fatalf("Len = %d, want 1: the unbound subkey must be dropped", kr.Len())
	}
	if _, err := kr.Verify(read(t, "SHA256SUMS"), read(t, "SHA256SUMS.rsa.sig"), now); !errors.Is(err, ErrUnknownSigner) {
		t.Fatalf("err = %v, want ErrUnknownSigner", err)
	}
}

// The RSA primary is certify-only, so only its subkey may sign: the flags come
// from the self-certification, and the subkey's from its binding plus the
// embedded back-signature.
func TestCertifyOnlyPrimaryCannotSign(t *testing.T) {
	kr := load(t, "rsa.asc")
	for _, k := range kr.keys {
		if k.primary == nil && k.canSign {
			t.Errorf("primary %s has flags C only, but canSign = true", k.KeyID())
		}
		if k.primary != nil && !k.canSign {
			t.Errorf("subkey %s has flag S and a back-signature, but canSign = false", k.KeyID())
		}
	}
}

func TestArmorChecksum(t *testing.T) {
	armored := string(read(t, "ed25519.asc"))
	i := strings.LastIndex(armored, "\n=")
	bad := armored[:i+2] + "AAAA" + armored[i+6:]
	if _, err := ReadArmoredKeyRing([]byte(bad)); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("err = %v, want a checksum error", err)
	}
	if _, err := ReadArmoredKeyRing([]byte("not a key")); err == nil {
		t.Fatal("ReadArmoredKeyRing accepted input with no key block")
	}
}

func TestRejectsGarbage(t *testing.T) {
	kr := load(t, "ed25519.asc")
	for _, sig := range [][]byte{nil, {0x00}, {0x88, 0x05, 0x04}, []byte("-----BEGIN PGP SIGNATURE-----\n\nAAAA\n")} {
		if _, err := kr.Verify([]byte("x"), sig, now); err == nil {
			t.Errorf("Verify accepted %q", sig)
		}
	}
}

func serialize(p packet) []byte {
	n := len(p.body)
	hdr := []byte{0xc0 | p.tag, 0xff, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
	return append(hdr, p.body...)
}
