// Package openpgp verifies the detached OpenPGP signature a provider registry
// publishes over a release's SHA256SUMS file.
//
// The provider registry protocol hands out, for every provider package, the
// URL of a SHA256SUMS document, the URL of a detached signature over it, and
// the publisher's public keys in ASCII armor. Checking that chain is what
// `terraform init` does before it trusts a package it has no lock-file hash
// for. Go's standard library has no OpenPGP, and the project keeps to the
// standard library, so this package implements the slice of RFC 4880 that the
// check needs and nothing more:
//
//   - ASCII armor with its CRC-24 checksum;
//   - version 4 public keys and subkeys: RSA (algorithms 1 and 3), EdDSA over
//     Ed25519 in the legacy encoding (22) and in the RFC 9580 encoding (27);
//   - version 4 signatures over binary (0x00) and text (0x01) documents,
//     hashed with SHA-224/256/384/512. MD5 and SHA-1 are refused;
//   - subkey binding signatures (0x18), so a signature from a signing subkey
//     is accepted only when the primary key vouches for that subkey;
//   - key and subkey revocations (0x20, 0x28), signature expiry, and subkey
//     expiry relative to the signature's creation time.
//
// Self-certifications of user IDs are read only for the primary key's flags
// and expiry. Third-party certifications and the web of trust are not
// evaluated: the trust anchor is the key the registry returns, exactly as for
// Terraform itself.
package openpgp

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/big"
	"strings"
	"time"

	_ "crypto/sha256" // register SHA-224/256 for crypto.Hash.New
	_ "crypto/sha512" // register SHA-384/512 for crypto.Hash.New
)

// ErrInvalidSignature means a signature was parsed and a matching key found,
// but the signature does not verify, has expired, or comes from a key that is
// revoked or not entitled to sign.
var ErrInvalidSignature = errors.New("openpgp: signature verification failed")

// ErrUnknownSigner means no key in the ring issued the signature.
var ErrUnknownSigner = errors.New("openpgp: signature was not made by any key in the key ring")

const (
	tagSignature = 2
	tagPublicKey = 6
	tagUserID    = 13
	tagSubkey    = 14
	tagUserAttr  = 17

	sigBinary         = 0x00
	sigText           = 0x01
	sigSubkeyBinding  = 0x18
	sigPrimaryBinding = 0x19
	sigKeyRevocation  = 0x20
	sigSubkeyRevoke   = 0x28

	flagSign = 0x02
)

// ed25519OID is the curve OID used by the legacy EdDSA (22) key encoding.
var ed25519OID = []byte{0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01}

// Key is one public key or subkey from a key ring.
type Key struct {
	Fingerprint [20]byte
	Created     time.Time
	Algo        string // "rsa-4096", "ed25519"

	pub     crypto.PublicKey
	body    []byte // the packet body, as hashed into fingerprints and bindings
	primary *Key   // nil for a primary key

	revoked bool
	canSign bool
	expires time.Time // zero means never
}

// KeyID is the 64-bit key ID in the usual upper-case hex form.
func (k *Key) KeyID() string { return strings.ToUpper(hex.EncodeToString(k.Fingerprint[12:])) }

// KeyRing holds the public keys signatures are checked against.
type KeyRing struct {
	keys []*Key // primaries and subkeys, flattened
}

// Len is the number of keys and subkeys in the ring.
func (kr *KeyRing) Len() int { return len(kr.keys) }

// ReadArmoredKeyRing parses one or more ASCII-armored public key blocks. Blocks
// may be concatenated; anything outside them is ignored.
func ReadArmoredKeyRing(data []byte) (*KeyRing, error) {
	kr := &KeyRing{}
	if err := kr.AddArmored(data); err != nil {
		return nil, err
	}
	return kr, nil
}

// AddArmored adds the keys from ASCII-armored public key blocks to the ring.
func (kr *KeyRing) AddArmored(data []byte) error {
	blocks, err := decodeArmor(data, "PGP PUBLIC KEY BLOCK")
	if err != nil {
		return err
	}
	if len(blocks) == 0 {
		return errors.New("openpgp: no PGP PUBLIC KEY BLOCK found")
	}
	for _, b := range blocks {
		if err := kr.addPackets(b); err != nil {
			return err
		}
	}
	return nil
}

// pending collects the packets that follow one primary key until the next
// primary key starts, so the bindings can be checked once all are known.
type pending struct {
	primary *Key
	subkeys []*Key
	sigs    []*signature
}

func (kr *KeyRing) addPackets(data []byte) error {
	pkts, err := readPackets(data)
	if err != nil {
		return err
	}
	var cur *pending
	var target *Key // the key the next signature packet is about
	var uid []byte  // the user ID the next certification is about
	flush := func() {
		if cur != nil {
			kr.keys = append(kr.keys, cur.finalize()...)
		}
	}
	for _, p := range pkts {
		switch p.tag {
		case tagPublicKey:
			flush()
			k, err := parseKey(p.body)
			if err != nil {
				return err
			}
			cur, target, uid = &pending{primary: k}, k, nil
		case tagSubkey:
			if cur == nil {
				return errors.New("openpgp: subkey before any primary key")
			}
			k, err := parseKey(p.body)
			if err != nil {
				return err
			}
			k.primary = cur.primary
			cur.subkeys = append(cur.subkeys, k)
			target, uid = k, nil
		case tagUserID:
			if cur == nil {
				return errors.New("openpgp: user ID before any primary key")
			}
			target, uid = cur.primary, p.body
		case tagUserAttr:
			// Photo IDs carry nothing this package uses; their
			// certifications are skipped.
			target, uid = nil, nil
		case tagSignature:
			if cur == nil {
				return errors.New("openpgp: signature before any key")
			}
			if target == nil {
				continue
			}
			s, err := parseSignature(p.body)
			if err != nil {
				// A signature we cannot parse (say, a v5 signature from a
				// newer tool) must not make the whole key unusable; it simply
				// does not count.
				continue
			}
			s.target, s.uid = target, uid
			cur.sigs = append(cur.sigs, s)
		}
	}
	flush()
	return nil
}

// finalize checks the self-signatures collected for one primary key and
// returns the primary plus every subkey that has a valid binding.
func (p *pending) finalize() []*Key {
	primary := p.primary
	primary.canSign = true // unless a self-certification says otherwise
	var certAt time.Time
	bound := map[*Key]time.Time{}

	for _, s := range p.sigs {
		if s.issuer != nil && !bytes.Equal(s.issuer, primary.Fingerprint[12:]) {
			continue // a third-party certification: not evaluated
		}
		switch {
		case s.sigType >= 0x10 && s.sigType <= 0x13 && s.target == primary && s.uid != nil:
			h := keyHash(s, primary, nil)
			if h == nil {
				continue
			}
			var hdr [5]byte
			hdr[0] = 0xb4
			binary.BigEndian.PutUint32(hdr[1:], uint32(len(s.uid)))
			h.Write(hdr[:])
			h.Write(s.uid)
			if primary.verifyHash(s, h) != nil {
				continue
			}
			if !certAt.IsZero() && !s.created.After(certAt) {
				continue
			}
			// The newest valid self-certification sets the primary key's
			// capabilities and expiry, as in GnuPG.
			certAt = s.created
			primary.applySelfSig(s)
		case s.sigType == sigKeyRevocation && s.target == primary:
			if primary.verifyHash(s, keyHash(s, primary, nil)) == nil {
				primary.revoked = true
			}
		case s.sigType == sigSubkeyBinding && s.target != primary:
			if primary.verifyHash(s, keyHash(s, primary, s.target)) != nil {
				continue
			}
			if at, ok := bound[s.target]; ok && !s.created.After(at) {
				continue
			}
			bound[s.target] = s.created
			s.target.applySelfSig(s)
			// A signing subkey must cross-certify its primary with an
			// embedded back-signature (RFC 4880 §5.2.1, 0x19). Without it,
			// anyone could bind somebody else's signing key to their own
			// primary and claim its signatures.
			if s.target.canSign {
				back := s.embedded
				s.target.canSign = back != nil && back.sigType == sigPrimaryBinding &&
					s.target.verifyHash(back, keyHash(back, primary, s.target)) == nil
			}
		case s.sigType == sigSubkeyRevoke && s.target != primary:
			if primary.verifyHash(s, keyHash(s, primary, s.target)) == nil {
				s.target.revoked = true
			}
		}
	}

	out := []*Key{primary}
	for _, k := range p.subkeys {
		if _, ok := bound[k]; !ok {
			continue
		}
		k.revoked = k.revoked || primary.revoked
		if !primary.expires.IsZero() && (k.expires.IsZero() || primary.expires.Before(k.expires)) {
			k.expires = primary.expires
		}
		out = append(out, k)
	}
	return out
}

// applySelfSig takes the key flags and key expiry from a valid self-signature.
// A signature without a key flags subpacket predates them and grants signing.
func (k *Key) applySelfSig(s *signature) {
	k.canSign = s.flags == nil || (*s.flags)&flagSign != 0
	k.expires = time.Time{}
	if s.keyExpiry > 0 {
		k.expires = k.Created.Add(time.Duration(s.keyExpiry) * time.Second)
	}
}

// Verify checks a detached signature (binary or ASCII-armored) over signed and
// returns the key that made it. now is used for signature expiry.
func (kr *KeyRing) Verify(signed, sig []byte, now time.Time) (*Key, error) {
	raw := sig
	if bytes.Contains(sig, []byte("-----BEGIN PGP SIGNATURE-----")) {
		blocks, err := decodeArmor(sig, "PGP SIGNATURE")
		if err != nil {
			return nil, err
		}
		raw = bytes.Join(blocks, nil)
	}
	pkts, err := readPackets(raw)
	if err != nil {
		return nil, err
	}
	var lastErr error = errors.New("openpgp: no signature packet found")
	for _, p := range pkts {
		if p.tag != tagSignature {
			continue
		}
		s, err := parseSignature(p.body)
		if err != nil {
			lastErr = err
			continue
		}
		k, err := kr.verifyOne(s, signed, now)
		if err == nil {
			return k, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func (kr *KeyRing) verifyOne(s *signature, signed []byte, now time.Time) (*Key, error) {
	if s.sigType != sigBinary && s.sigType != sigText {
		return nil, fmt.Errorf("openpgp: signature type 0x%02x is not a document signature", s.sigType)
	}
	var candidates []*Key
	for _, k := range kr.keys {
		if s.issuer == nil || bytes.Equal(k.Fingerprint[12:], s.issuer) {
			candidates = append(candidates, k)
		}
	}
	if len(candidates) == 0 {
		return nil, fmt.Errorf("%w (issuer %X)", ErrUnknownSigner, s.issuer)
	}

	doc := signed
	if s.sigType == sigText {
		doc = canonicalText(signed)
	}
	h := s.hash.New()
	h.Write(doc)
	digest := s.finish(h)

	var lastErr error
	for _, k := range candidates {
		if err := k.verifyDigest(s, digest); err != nil {
			lastErr = err
			continue
		}
		switch {
		case k.revoked:
			return nil, fmt.Errorf("%w: key %s is revoked", ErrInvalidSignature, k.KeyID())
		case !k.canSign:
			return nil, fmt.Errorf("%w: key %s is not a signing key", ErrInvalidSignature, k.KeyID())
		case !k.expires.IsZero() && s.created.After(k.expires):
			return nil, fmt.Errorf("%w: key %s expired on %s, before the signature was made",
				ErrInvalidSignature, k.KeyID(), k.expires.UTC().Format(time.DateOnly))
		case s.sigExpiry > 0 && now.After(s.created.Add(time.Duration(s.sigExpiry)*time.Second)):
			return nil, fmt.Errorf("%w: signature expired", ErrInvalidSignature)
		}
		return k, nil
	}
	return nil, lastErr
}

// ---------------------------------------------------------------- keys

func parseKey(body []byte) (*Key, error) {
	if len(body) < 6 {
		return nil, errors.New("openpgp: truncated public key packet")
	}
	if body[0] != 4 {
		return nil, fmt.Errorf("openpgp: version %d public keys are not supported", body[0])
	}
	k := &Key{
		Created: time.Unix(int64(binary.BigEndian.Uint32(body[1:5])), 0),
		body:    body,
	}
	r := &reader{b: body[6:]}
	switch algo := body[5]; algo {
	case 1, 3: // RSA (Encrypt or Sign), RSA Sign-Only
		n, e := r.mpi(), r.mpi()
		if r.err != nil {
			return nil, r.err
		}
		E := new(big.Int).SetBytes(e)
		if !E.IsInt64() || E.Int64() > 1<<31-1 || E.Int64() < 3 {
			return nil, errors.New("openpgp: unsupported RSA public exponent")
		}
		pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(E.Int64())}
		if pub.N.BitLen() < 2048 {
			return nil, fmt.Errorf("openpgp: RSA key of %d bits is too small", pub.N.BitLen())
		}
		k.pub, k.Algo = pub, fmt.Sprintf("rsa-%d", pub.N.BitLen())
	case 22: // EdDSA (legacy)
		oidLen := int(r.byte())
		oid := r.bytes(oidLen)
		point := r.mpi()
		if r.err != nil {
			return nil, r.err
		}
		if !bytes.Equal(oid, ed25519OID) {
			return nil, errors.New("openpgp: EdDSA key on a curve other than Ed25519")
		}
		if len(point) != 33 || point[0] != 0x40 {
			return nil, errors.New("openpgp: malformed Ed25519 public point")
		}
		k.pub, k.Algo = ed25519.PublicKey(point[1:]), "ed25519"
	case 27: // Ed25519 (RFC 9580)
		pt := r.bytes(ed25519.PublicKeySize)
		if r.err != nil {
			return nil, r.err
		}
		k.pub, k.Algo = ed25519.PublicKey(pt), "ed25519"
	default:
		// Keep the key so its fingerprint matches, but it can verify nothing.
		k.Algo = fmt.Sprintf("algo-%d", algo)
	}

	h := sha1.New()
	h.Write([]byte{0x99, byte(len(body) >> 8), byte(len(body))})
	h.Write(body)
	copy(k.Fingerprint[:], h.Sum(nil))
	return k, nil
}

func (k *Key) verifyHash(s *signature, h hash.Hash) error {
	if h == nil {
		return ErrInvalidSignature
	}
	return k.verifyDigest(s, s.finish(h))
}

func (k *Key) verifyDigest(s *signature, digest []byte) error {
	if digest[0] != s.left16[0] || digest[1] != s.left16[1] {
		return ErrInvalidSignature
	}
	switch pub := k.pub.(type) {
	case *rsa.PublicKey:
		if s.algo != 1 && s.algo != 3 {
			return ErrInvalidSignature
		}
		if err := rsa.VerifyPKCS1v15(pub, s.hash, digest, s.rsaSig); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidSignature, err)
		}
	case ed25519.PublicKey:
		if s.algo != 22 && s.algo != 27 {
			return ErrInvalidSignature
		}
		if !ed25519.Verify(pub, digest, s.edSig) {
			return ErrInvalidSignature
		}
	default:
		return fmt.Errorf("%w: key %s uses unsupported algorithm %s", ErrInvalidSignature, k.KeyID(), k.Algo)
	}
	return nil
}

// keyHash starts the hash for a signature over a primary key, or over a
// primary key and one of its subkeys.
func keyHash(s *signature, primary, subkey *Key) hash.Hash {
	if s.hash == 0 {
		return nil
	}
	h := s.hash.New()
	for _, k := range []*Key{primary, subkey} {
		if k == nil {
			continue
		}
		h.Write([]byte{0x99, byte(len(k.body) >> 8), byte(len(k.body))})
		h.Write(k.body)
	}
	return h
}

// ---------------------------------------------------------------- signatures

type signature struct {
	sigType byte
	algo    byte
	hash    crypto.Hash
	hashed  []byte // version through the end of the hashed subpackets
	left16  [2]byte
	rsaSig  []byte
	edSig   []byte

	created   time.Time
	sigExpiry uint32
	keyExpiry uint32
	flags     *byte
	issuer    []byte // 8-byte key ID, nil if the signature names no issuer
	embedded  *signature

	// For key-ring parsing: the key and user ID this signature follows.
	target *Key
	uid    []byte
}

var hashes = map[byte]crypto.Hash{
	8:  crypto.SHA256,
	9:  crypto.SHA384,
	10: crypto.SHA512,
	11: crypto.SHA224,
}

// understood lists the subpacket types this package either interprets or can
// safely ignore. RFC 4880 §5.2.3.1 requires a signature carrying a critical
// subpacket outside that set to be treated as invalid.
var understood = map[byte]bool{
	2: true, 3: true, 4: true, 5: true, 7: true, 9: true, 11: true, 12: true,
	16: true, 20: true, 21: true, 22: true, 23: true, 24: true, 25: true,
	26: true, 27: true, 28: true, 29: true, 30: true, 31: true, 32: true,
	33: true, 34: true, 35: true, 37: true, 39: true,
}

func parseSignature(body []byte) (*signature, error) {
	if len(body) < 1 || body[0] != 4 {
		return nil, errors.New("openpgp: only version 4 signatures are supported")
	}
	r := &reader{b: body[1:]}
	s := &signature{}
	s.sigType, s.algo = r.byte(), r.byte()
	hashAlgo := r.byte()
	hashedLen := int(r.uint16())
	hashedArea := r.bytes(hashedLen)
	unhashedLen := int(r.uint16())
	unhashedArea := r.bytes(unhashedLen)
	copy(s.left16[:], r.bytes(2))
	if r.err != nil {
		return nil, r.err
	}
	h, ok := hashes[hashAlgo]
	if !ok {
		return nil, fmt.Errorf("openpgp: hash algorithm %d is not accepted", hashAlgo)
	}
	s.hash = h
	s.hashed = body[:1+5+hashedLen]

	switch s.algo {
	case 1, 3:
		s.rsaSig = r.mpi()
	case 22:
		rr, ss := r.mpi(), r.mpi()
		if len(rr) > 32 || len(ss) > 32 {
			return nil, errors.New("openpgp: malformed EdDSA signature")
		}
		s.edSig = make([]byte, 64)
		copy(s.edSig[32-len(rr):32], rr)
		copy(s.edSig[64-len(ss):], ss)
	case 27:
		s.edSig = r.bytes(ed25519.SignatureSize)
	default:
		return nil, fmt.Errorf("openpgp: signature algorithm %d is not supported", s.algo)
	}
	if r.err != nil {
		return nil, r.err
	}

	if err := s.subpackets(hashedArea, true); err != nil {
		return nil, err
	}
	// Only the issuer may come from the unhashed area; it is a hint for
	// finding the key, and a wrong hint just fails verification.
	if err := s.subpackets(unhashedArea, false); err != nil {
		return nil, err
	}
	if s.created.IsZero() {
		// v4 signatures must carry a hashed creation time (RFC 4880 §5.2.3.4).
		return nil, errors.New("openpgp: signature has no creation time")
	}
	return s, nil
}

func (s *signature) subpackets(area []byte, hashed bool) error {
	for len(area) > 0 {
		var n int
		switch {
		case area[0] < 192:
			n, area = int(area[0]), area[1:]
		case area[0] < 255:
			if len(area) < 2 {
				return errors.New("openpgp: truncated subpacket")
			}
			n, area = (int(area[0])-192)<<8+int(area[1])+192, area[2:]
		default:
			if len(area) < 5 {
				return errors.New("openpgp: truncated subpacket")
			}
			n, area = int(binary.BigEndian.Uint32(area[1:5])), area[5:]
		}
		if n < 1 || n > len(area) {
			return errors.New("openpgp: truncated subpacket")
		}
		typ, data := area[0], area[1:n]
		area = area[n:]
		critical := typ&0x80 != 0
		typ &= 0x7f
		if hashed && critical && !understood[typ] {
			return fmt.Errorf("openpgp: unknown critical subpacket %d", typ)
		}
		switch {
		case typ == 16 && len(data) == 8:
			if s.issuer == nil {
				s.issuer = data
			}
		case typ == 33 && len(data) == 21 && data[0] == 4:
			if s.issuer == nil {
				s.issuer = data[13:]
			}
		case typ == 32:
			// The embedded back-signature of a signing subkey. GnuPG puts it
			// in the unhashed area; it is self-authenticating either way.
			if e, err := parseSignature(data); err == nil {
				s.embedded = e
			}
		case !hashed:
		case typ == 2 && len(data) == 4:
			s.created = time.Unix(int64(binary.BigEndian.Uint32(data)), 0)
		case typ == 3 && len(data) == 4:
			s.sigExpiry = binary.BigEndian.Uint32(data)
		case typ == 9 && len(data) == 4:
			s.keyExpiry = binary.BigEndian.Uint32(data)
		case typ == 27 && len(data) >= 1:
			f := data[0]
			s.flags = &f
		}
	}
	return nil
}

// finish appends the signature's hashed portion and the v4 trailer to h and
// returns the digest the signature is computed over.
func (s *signature) finish(h hash.Hash) []byte {
	h.Write(s.hashed)
	var trailer [6]byte
	trailer[0], trailer[1] = 4, 0xff
	binary.BigEndian.PutUint32(trailer[2:], uint32(len(s.hashed)))
	h.Write(trailer[:])
	return h.Sum(nil)
}

// canonicalText converts line endings to CRLF, as a text signature requires.
func canonicalText(b []byte) []byte {
	b = bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n"))
	return bytes.ReplaceAll(b, []byte("\n"), []byte("\r\n"))
}

// ---------------------------------------------------------------- packets

type packet struct {
	tag  byte
	body []byte
}

func readPackets(b []byte) ([]packet, error) {
	var out []packet
	for len(b) > 0 {
		hdr := b[0]
		if hdr&0x80 == 0 {
			return nil, errors.New("openpgp: invalid packet header")
		}
		var tag byte
		var n, hlen int
		if hdr&0x40 != 0 { // new format
			tag = hdr & 0x3f
			if len(b) < 2 {
				return nil, errors.New("openpgp: truncated packet header")
			}
			switch l := b[1]; {
			case l < 192:
				n, hlen = int(l), 2
			case l < 224:
				if len(b) < 3 {
					return nil, errors.New("openpgp: truncated packet header")
				}
				n, hlen = (int(l)-192)<<8+int(b[2])+192, 3
			case l == 255:
				if len(b) < 6 {
					return nil, errors.New("openpgp: truncated packet header")
				}
				n, hlen = int(binary.BigEndian.Uint32(b[2:6])), 6
			default:
				// Partial lengths only occur in data packets, which a key
				// ring or a detached signature never contains.
				return nil, errors.New("openpgp: partial body lengths are not supported")
			}
		} else { // old format
			tag = (hdr >> 2) & 0x0f
			switch hdr & 3 {
			case 0:
				if len(b) < 2 {
					return nil, errors.New("openpgp: truncated packet header")
				}
				n, hlen = int(b[1]), 2
			case 1:
				if len(b) < 3 {
					return nil, errors.New("openpgp: truncated packet header")
				}
				n, hlen = int(binary.BigEndian.Uint16(b[1:3])), 3
			case 2:
				if len(b) < 5 {
					return nil, errors.New("openpgp: truncated packet header")
				}
				n, hlen = int(binary.BigEndian.Uint32(b[1:5])), 5
			default:
				return nil, errors.New("openpgp: indeterminate packet lengths are not supported")
			}
		}
		if n < 0 || hlen+n > len(b) {
			return nil, errors.New("openpgp: truncated packet")
		}
		out = append(out, packet{tag: tag, body: b[hlen : hlen+n]})
		b = b[hlen+n:]
	}
	return out, nil
}

type reader struct {
	b   []byte
	err error
}

func (r *reader) bytes(n int) []byte {
	if r.err != nil {
		return nil
	}
	if n < 0 || n > len(r.b) {
		r.err = errors.New("openpgp: truncated packet body")
		return nil
	}
	out := r.b[:n]
	r.b = r.b[n:]
	return out
}

func (r *reader) byte() byte {
	b := r.bytes(1)
	if b == nil {
		return 0
	}
	return b[0]
}

func (r *reader) uint16() uint16 {
	b := r.bytes(2)
	if b == nil {
		return 0
	}
	return binary.BigEndian.Uint16(b)
}

func (r *reader) mpi() []byte {
	bits := int(r.uint16())
	return r.bytes((bits + 7) / 8)
}

// ---------------------------------------------------------------- armor

// decodeArmor returns the decoded body of every armored block of the given
// kind, checking each block's CRC-24 when present.
func decodeArmor(data []byte, kind string) ([][]byte, error) {
	begin, end := "-----BEGIN "+kind+"-----", "-----END "+kind+"-----"
	var out [][]byte
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		if strings.TrimSpace(sc.Text()) != begin {
			continue
		}
		var body strings.Builder
		var crc string
		inHeaders, done := true, false
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == end {
				done = true
				break
			}
			if inHeaders {
				if line == "" {
					inHeaders = false
					continue
				}
				if strings.Contains(line, ": ") {
					continue
				}
				inHeaders = false
			}
			if strings.HasPrefix(line, "=") && len(line) == 5 {
				crc = line[1:]
				continue
			}
			body.WriteString(line)
		}
		if !done {
			return nil, fmt.Errorf("openpgp: %s block is not terminated", kind)
		}
		raw, err := base64.StdEncoding.DecodeString(body.String())
		if err != nil {
			return nil, fmt.Errorf("openpgp: bad armor: %w", err)
		}
		if crc != "" {
			want, err := base64.StdEncoding.DecodeString(crc)
			if err != nil || len(want) != 3 {
				return nil, errors.New("openpgp: bad armor checksum")
			}
			got := crc24(raw)
			if want[0] != byte(got>>16) || want[1] != byte(got>>8) || want[2] != byte(got) {
				return nil, errors.New("openpgp: armor checksum mismatch")
			}
		}
		out = append(out, raw)
	}
	if err := sc.Err(); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return out, nil
}

func crc24(b []byte) uint32 {
	crc := uint32(0xb704ce)
	for _, c := range b {
		crc ^= uint32(c) << 16
		for i := 0; i < 8; i++ {
			crc <<= 1
			if crc&0x1000000 != 0 {
				crc ^= 0x1864cfb
			}
		}
	}
	return crc & 0xffffff
}
