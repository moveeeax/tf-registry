// Package lockfile reads the provider selections out of a Terraform or OpenTofu
// dependency lock file (.terraform.lock.hcl).
//
// The lock file is HCL, but only a narrow, machine-written subset of it:
//
//	provider "registry.terraform.io/hashicorp/aws" {
//	  version     = "5.31.0"
//	  constraints = "~> 5.0"
//	  hashes = [
//	    "h1:...",
//	    "zh:...",
//	  ]
//	}
//
// Pulling in hashicorp/hcl for that would break the "standard library only"
// rule this module keeps, so this package parses exactly that subset: top-level
// blocks with one string label, string and list-of-string attributes, and the
// three HCL comment styles. Anything else is an error rather than a guess,
// because a misread hash list is a misread trust anchor.
package lockfile

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Addr is a fully qualified provider source address.
type Addr struct {
	Hostname  string // e.g. registry.terraform.io
	Namespace string // e.g. hashicorp
	Type      string // e.g. aws
}

func (a Addr) String() string { return a.Hostname + "/" + a.Namespace + "/" + a.Type }

// Provider is one provider selection from a lock file.
type Provider struct {
	Addr        Addr
	Version     string
	Constraints string
	Hashes      []string // sorted, deduplicated, e.g. "h1:..." and "zh:..."
}

// Key identifies a selection independent of its hashes.
func (p Provider) Key() string { return p.Addr.String() + " " + p.Version }

var (
	labelRE   = regexp.MustCompile(`^[a-z0-9]+(?:[a-z0-9.-]*[a-z0-9])?(?::[0-9]+)?$`)
	segmentRE = regexp.MustCompile(`^[0-9a-z](?:[0-9a-z_-]*[0-9a-z])?$`)
	versionRE = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$`)
)

// ParseAddr parses a fully qualified hostname/namespace/type address, the only
// form a lock file contains. Addresses are case-insensitive and normalised to
// lower case, as Terraform does.
func ParseAddr(s string) (Addr, error) {
	parts := strings.Split(strings.ToLower(s), "/")
	if len(parts) != 3 {
		return Addr{}, fmt.Errorf("provider address %q is not hostname/namespace/type", s)
	}
	if !labelRE.MatchString(parts[0]) {
		return Addr{}, fmt.Errorf("provider address %q has an invalid hostname", s)
	}
	for _, seg := range parts[1:] {
		if !segmentRE.MatchString(seg) {
			return Addr{}, fmt.Errorf("provider address %q has an invalid segment %q", s, seg)
		}
	}
	return Addr{Hostname: parts[0], Namespace: parts[1], Type: parts[2]}, nil
}

// ParseFile reads and parses one lock file.
func ParseFile(path string) ([]Provider, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("lockfile: %w", err)
	}
	ps, err := Parse(b)
	if err != nil {
		return nil, fmt.Errorf("lockfile: %s: %w", path, err)
	}
	return ps, nil
}

// Parse parses the content of a lock file.
func Parse(src []byte) ([]Provider, error) {
	toks, err := lex(string(src))
	if err != nil {
		return nil, err
	}
	p := &parser{toks: toks}
	var out []Provider
	seen := map[string]bool{}
	for p.skipNewlines(); !p.at(tokEOF); p.skipNewlines() {
		blockType, err := p.expect(tokIdent)
		if err != nil {
			return nil, err
		}
		label, err := p.expect(tokString)
		if err != nil {
			return nil, err
		}
		attrs, err := p.body()
		if err != nil {
			return nil, err
		}
		if blockType.text != "provider" {
			// Lock files have only ever had provider blocks; a future block
			// type is not ours to interpret.
			continue
		}
		prov, err := toProvider(label, attrs)
		if err != nil {
			return nil, err
		}
		if seen[prov.Addr.String()] {
			return nil, fmt.Errorf("line %d: provider %q is locked twice", label.line, prov.Addr)
		}
		seen[prov.Addr.String()] = true
		out = append(out, prov)
	}
	return out, nil
}

func toProvider(label token, attrs map[string]value) (Provider, error) {
	addr, err := ParseAddr(label.text)
	if err != nil {
		return Provider{}, fmt.Errorf("line %d: %w", label.line, err)
	}
	prov := Provider{Addr: addr}

	v, ok := attrs["version"]
	if !ok || v.list != nil {
		return Provider{}, fmt.Errorf("line %d: provider %q has no version string", label.line, addr)
	}
	if !versionRE.MatchString(v.str) {
		return Provider{}, fmt.Errorf("line %d: provider %q has invalid version %q", v.line, addr, v.str)
	}
	prov.Version = v.str

	if c, ok := attrs["constraints"]; ok {
		if c.list != nil {
			return Provider{}, fmt.Errorf("line %d: constraints must be a string", c.line)
		}
		prov.Constraints = c.str
	}

	if h, ok := attrs["hashes"]; ok {
		if h.list == nil {
			return Provider{}, fmt.Errorf("line %d: hashes must be a list", h.line)
		}
		for _, s := range h.list {
			if !strings.HasPrefix(s, "h1:") && !strings.HasPrefix(s, "zh:") {
				// Unknown schemes are skipped, not rejected: Terraform treats
				// them the same way so that newer lock files stay readable.
				continue
			}
			prov.Hashes = append(prov.Hashes, s)
		}
	}
	prov.Hashes = dedupe(prov.Hashes)
	return prov, nil
}

// Merge folds the selections of several lock files into one deduplicated list,
// sorted by address then version. Two stacks pinning the same provider version
// become one entry whose hashes are the union of both lock files' hashes: a
// package matching either is the package that stack would accept.
func Merge(sets ...[]Provider) []Provider {
	byKey := map[string]*Provider{}
	for _, set := range sets {
		for _, p := range set {
			if have, ok := byKey[p.Key()]; ok {
				have.Hashes = dedupe(append(have.Hashes, p.Hashes...))
				if have.Constraints == "" {
					have.Constraints = p.Constraints
				}
				continue
			}
			cp := p
			cp.Hashes = dedupe(append([]string(nil), p.Hashes...))
			byKey[p.Key()] = &cp
		}
	}
	out := make([]Provider, 0, len(byKey))
	for _, p := range byKey {
		out = append(out, *p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Addr != out[j].Addr {
			return out[i].Addr.String() < out[j].Addr.String()
		}
		return out[i].Version < out[j].Version
	})
	return out
}

func dedupe(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	sort.Strings(in)
	out := in[:1]
	for _, s := range in[1:] {
		if s != out[len(out)-1] {
			out = append(out, s)
		}
	}
	return out
}

// ---------------------------------------------------------------- parser

type value struct {
	str  string
	list []string // non-nil for a list, possibly empty
	line int
}

type parser struct {
	toks []token
	pos  int
}

func (p *parser) peek() token       { return p.toks[p.pos] }
func (p *parser) at(k tokKind) bool { return p.peek().kind == k }
func (p *parser) next() token       { t := p.toks[p.pos]; p.pos++; return t }
func (p *parser) skipNewlines() {
	for p.at(tokNewline) {
		p.pos++
	}
}
func (p *parser) unexpected(t token) error {
	return fmt.Errorf("line %d: unexpected %s", t.line, t.describe())
}

func (p *parser) expect(k tokKind) (token, error) {
	p.skipNewlines()
	t := p.next()
	if t.kind != k {
		return t, p.unexpected(t)
	}
	return t, nil
}

func (p *parser) body() (map[string]value, error) {
	if _, err := p.expect(tokLBrace); err != nil {
		return nil, err
	}
	attrs := map[string]value{}
	for {
		p.skipNewlines()
		t := p.next()
		switch t.kind {
		case tokRBrace:
			return attrs, nil
		case tokIdent:
		default:
			return nil, p.unexpected(t)
		}
		if _, err := p.expect(tokEquals); err != nil {
			return nil, err
		}
		v, err := p.value()
		if err != nil {
			return nil, err
		}
		if _, dup := attrs[t.text]; dup {
			return nil, fmt.Errorf("line %d: attribute %q set twice", t.line, t.text)
		}
		attrs[t.text] = v
		// An attribute ends at a newline or at the closing brace.
		if !p.at(tokNewline) && !p.at(tokRBrace) {
			return nil, p.unexpected(p.peek())
		}
	}
}

func (p *parser) value() (value, error) {
	p.skipNewlines()
	t := p.next()
	switch t.kind {
	case tokString:
		return value{str: t.text, line: t.line}, nil
	case tokLBrack:
		v := value{list: []string{}, line: t.line}
		for {
			p.skipNewlines()
			t := p.next()
			if t.kind == tokRBrack {
				return v, nil
			}
			if t.kind != tokString {
				return value{}, p.unexpected(t)
			}
			v.list = append(v.list, t.text)
			p.skipNewlines()
			switch p.peek().kind {
			case tokComma:
				p.next()
			case tokRBrack:
			default:
				return value{}, p.unexpected(p.peek())
			}
		}
	default:
		return value{}, p.unexpected(t)
	}
}

// ---------------------------------------------------------------- lexer

type tokKind int

const (
	tokEOF tokKind = iota
	tokNewline
	tokIdent
	tokString
	tokLBrace
	tokRBrace
	tokLBrack
	tokRBrack
	tokEquals
	tokComma
)

type token struct {
	kind tokKind
	text string
	line int
}

func (t token) describe() string {
	switch t.kind {
	case tokEOF:
		return "end of file"
	case tokNewline:
		return "newline"
	case tokString:
		return fmt.Sprintf("string %q", t.text)
	default:
		return fmt.Sprintf("%q", t.text)
	}
}

func lex(src string) ([]token, error) {
	var toks []token
	line := 1
	i := 0
	for i < len(src) {
		c := src[i]
		switch {
		case c == '\n':
			toks = append(toks, token{kind: tokNewline, text: "\n", line: line})
			line++
			i++
		case c == ' ' || c == '\t' || c == '\r':
			i++
		case c == '#' || (c == '/' && i+1 < len(src) && src[i+1] == '/'):
			for i < len(src) && src[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < len(src) && src[i+1] == '*':
			end := strings.Index(src[i+2:], "*/")
			if end < 0 {
				return nil, fmt.Errorf("line %d: unterminated comment", line)
			}
			line += strings.Count(src[i:i+2+end], "\n")
			i += end + 4
		case c == '"':
			j := i + 1
			for j < len(src) && src[j] != '"' {
				if src[j] == '\\' {
					j++
				}
				if j < len(src) && src[j] == '\n' {
					return nil, fmt.Errorf("line %d: newline in string", line)
				}
				j++
			}
			if j >= len(src) {
				return nil, fmt.Errorf("line %d: unterminated string", line)
			}
			raw := src[i : j+1]
			if strings.Contains(raw, "${") || strings.Contains(raw, "%{") {
				return nil, fmt.Errorf("line %d: template sequences are not valid in a lock file", line)
			}
			s, err := strconv.Unquote(raw)
			if err != nil {
				return nil, fmt.Errorf("line %d: bad string literal %s", line, raw)
			}
			toks = append(toks, token{kind: tokString, text: s, line: line})
			i = j + 1
		case isIdentStart(c):
			j := i
			for j < len(src) && isIdentPart(src[j]) {
				j++
			}
			toks = append(toks, token{kind: tokIdent, text: src[i:j], line: line})
			i = j
		default:
			kinds := map[byte]tokKind{'{': tokLBrace, '}': tokRBrace, '[': tokLBrack, ']': tokRBrack, '=': tokEquals, ',': tokComma}
			k, ok := kinds[c]
			if !ok {
				return nil, fmt.Errorf("line %d: unexpected character %q", line, c)
			}
			toks = append(toks, token{kind: k, text: string(c), line: line})
			i++
		}
	}
	toks = append(toks, token{kind: tokEOF, line: line})
	return toks, nil
}

func isIdentStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isIdentPart(c byte) bool {
	return isIdentStart(c) || c == '-' || (c >= '0' && c <= '9')
}
