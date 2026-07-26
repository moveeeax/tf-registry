// Package signature verifies detached cosign signatures over module tarballs.
//
// A `cosign sign-blob --key cosign.key module.tar.gz` produces a base64
// signature over the SHA-256 digest of the blob. With a key pair (as opposed to
// keyless/Fulcio signing) that is plain ECDSA or RSA, so verification needs
// nothing but the standard library and the public half of the key. That matters
// here: the registry verifies every artifact it serves on startup, and it must
// be able to do that on a box with no network and no sigstore toolchain.
//
// Keyless signatures (Fulcio certificate + Rekor inclusion proof) are out of
// scope; they need a transparency-log lookup, which is a different trust model
// and a different failure mode for a serving path.
package signature

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// ErrInvalidSignature is returned when the key is fine but the signature does
// not match the blob. Callers use it to tell tampering from misconfiguration.
var ErrInvalidSignature = errors.New("signature: verification failed")

// Verifier holds a parsed public key.
type Verifier struct {
	pub     crypto.PublicKey
	keyType string
}

// KeyType names the algorithm of the loaded key, for log lines and CLI output.
func (v *Verifier) KeyType() string { return v.keyType }

// LoadPublicKeyFile reads a PEM public key from disk, e.g. a `cosign.pub`.
func LoadPublicKeyFile(path string) (*Verifier, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("signature: read public key: %w", err)
	}
	return ParsePublicKey(b)
}

// ParsePublicKey parses a PEM-encoded PKIX public key.
func ParsePublicKey(pemBytes []byte) (*Verifier, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("signature: no PEM block in public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("signature: parse public key: %w", err)
	}
	v := &Verifier{pub: pub}
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		v.keyType = "ecdsa-" + k.Curve.Params().Name
	case *rsa.PublicKey:
		v.keyType = fmt.Sprintf("rsa-%d", k.N.BitLen())
	case ed25519.PublicKey:
		v.keyType = "ed25519"
	default:
		return nil, fmt.Errorf("signature: unsupported public key type %T", pub)
	}
	return v, nil
}

// VerifyBlob checks a detached signature over the bytes read from r. sig is the
// raw content of a `.sig` file: base64 as cosign writes it, or the raw
// signature bytes if it has already been decoded.
func (v *Verifier) VerifyBlob(r io.Reader, sig []byte) error {
	raw, err := decodeSignature(sig)
	if err != nil {
		return err
	}

	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return fmt.Errorf("signature: read blob: %w", err)
	}
	digest := h.Sum(nil)

	switch pub := v.pub.(type) {
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(pub, digest, raw) {
			return ErrInvalidSignature
		}
	case *rsa.PublicKey:
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest, raw); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidSignature, err)
		}
	case ed25519.PublicKey:
		// ed25519ph: cosign pre-hashes with SHA-512 for this curve, which we do
		// not implement. Reject loudly rather than silently accepting.
		return errors.New("signature: ed25519 keys are not supported; use the cosign default ECDSA P-256")
	default:
		return fmt.Errorf("signature: unsupported public key type %T", v.pub)
	}
	return nil
}

// VerifyFile is the file-path convenience wrapper used by the CLI.
func (v *Verifier) VerifyFile(blobPath, sigPath string) error {
	sig, err := os.ReadFile(sigPath)
	if err != nil {
		return fmt.Errorf("signature: read signature: %w", err)
	}
	f, err := os.Open(blobPath)
	if err != nil {
		return fmt.Errorf("signature: open blob: %w", err)
	}
	defer f.Close()
	return v.VerifyBlob(f, sig)
}

func decodeSignature(sig []byte) ([]byte, error) {
	trimmed := strings.TrimSpace(string(sig))
	if trimmed == "" {
		return nil, errors.New("signature: empty signature")
	}
	raw, err := base64.StdEncoding.DecodeString(trimmed)
	if err != nil {
		// Not base64: assume the caller already handed us raw bytes.
		return sig, nil
	}
	return raw, nil
}
