package signature

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The fixtures in testdata are a real detached signature in cosign sign-blob
// format: base64 of an ASN.1 ECDSA signature over the SHA-256 digest of the
// tarball. Only the public half of the key is committed.
func TestVerifyFixture(t *testing.T) {
	v, err := LoadPublicKeyFile(filepath.Join("testdata", "cosign.pub"))
	if err != nil {
		t.Fatalf("LoadPublicKeyFile: %v", err)
	}
	if got := v.KeyType(); got != "ecdsa-P-256" {
		t.Errorf("KeyType() = %q, want ecdsa-P-256", got)
	}
	if err := v.VerifyFile(filepath.Join("testdata", "module.tar.gz"), filepath.Join("testdata", "module.tar.gz.sig")); err != nil {
		t.Fatalf("VerifyFile on good fixture: %v", err)
	}
}

func TestVerifyRejectsTamperedBlob(t *testing.T) {
	v, err := LoadPublicKeyFile(filepath.Join("testdata", "cosign.pub"))
	if err != nil {
		t.Fatalf("LoadPublicKeyFile: %v", err)
	}
	blob, err := os.ReadFile(filepath.Join("testdata", "module.tar.gz"))
	if err != nil {
		t.Fatal(err)
	}
	sig, err := os.ReadFile(filepath.Join("testdata", "module.tar.gz.sig"))
	if err != nil {
		t.Fatal(err)
	}

	// Flip one byte deep inside the compressed stream.
	tampered := append([]byte(nil), blob...)
	tampered[len(tampered)/2] ^= 0x01

	err = v.VerifyBlob(bytes.NewReader(tampered), sig)
	if !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("VerifyBlob on tampered blob = %v, want ErrInvalidSignature", err)
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	v, err := LoadPublicKeyFile(filepath.Join("testdata", "other.pub"))
	if err != nil {
		t.Fatalf("LoadPublicKeyFile: %v", err)
	}
	err = v.VerifyFile(filepath.Join("testdata", "module.tar.gz"), filepath.Join("testdata", "module.tar.gz.sig"))
	if !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("VerifyFile with wrong key = %v, want ErrInvalidSignature", err)
	}
}

func TestVerifyRoundTrip(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	v, err := ParsePublicKey(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	if err != nil {
		t.Fatalf("ParsePublicKey: %v", err)
	}

	payload := []byte("module bytes that will be signed\n")
	sum := sha256.Sum256(payload)
	raw, err := ecdsa.SignASN1(rand.Reader, key, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	b64 := []byte(base64.StdEncoding.EncodeToString(raw) + "\n")

	if err := v.VerifyBlob(bytes.NewReader(payload), b64); err != nil {
		t.Errorf("VerifyBlob with base64 signature: %v", err)
	}
	if err := v.VerifyBlob(bytes.NewReader(payload), raw); err != nil {
		t.Errorf("VerifyBlob with raw signature bytes: %v", err)
	}
	if err := v.VerifyBlob(bytes.NewReader([]byte("different payload")), b64); !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("VerifyBlob with wrong payload = %v, want ErrInvalidSignature", err)
	}
}

func TestParsePublicKeyErrors(t *testing.T) {
	if _, err := ParsePublicKey([]byte("not a pem file")); err == nil {
		t.Error("ParsePublicKey on garbage: want error")
	}
	if _, err := ParsePublicKey(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("nope")})); err == nil {
		t.Error("ParsePublicKey on bad DER: want error")
	}
	if _, err := LoadPublicKeyFile(filepath.Join("testdata", "does-not-exist.pub")); err == nil {
		t.Error("LoadPublicKeyFile on missing file: want error")
	}
}

func TestVerifyEmptySignature(t *testing.T) {
	v, err := LoadPublicKeyFile(filepath.Join("testdata", "cosign.pub"))
	if err != nil {
		t.Fatal(err)
	}
	err = v.VerifyBlob(strings.NewReader("payload"), []byte("  \n"))
	if err == nil || !strings.Contains(err.Error(), "empty signature") {
		t.Fatalf("VerifyBlob with empty signature = %v, want an empty-signature error", err)
	}
}
