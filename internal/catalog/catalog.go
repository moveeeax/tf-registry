// Package catalog loads and validates the on-disk module catalog that the
// registry serves.
//
// The layout is deliberately boring, because it has to be reproducible from a
// CI job and greppable from a shell:
//
//	<root>/<namespace>/<name>/<system>/<version>/module.tar.gz
//	<root>/<namespace>/<name>/<system>/<version>/module.tar.gz.sig   (optional)
//
// namespace maps to a customer org, and <name>/<system> are the last two
// segments of the familiar terraform-<system>-<name> naming convention, so
// terraform-aws-vpc published by acme is addressed as acme/vpc/aws.
package catalog

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/moveeeax/tf-registry/internal/semver"
)

// ArchiveName is the fixed file name of a module archive inside a version dir.
const ArchiveName = "module.tar.gz"

var (
	nameRE   = regexp.MustCompile(`^[0-9a-zA-Z](?:[0-9a-zA-Z._-]*[0-9a-zA-Z])?$`)
	systemRE = regexp.MustCompile(`^[0-9a-z][0-9a-z-]*$`)
)

// Version is one published version of one module.
type Version struct {
	Version  string // canonical semver, no leading "v"
	Archive  string // absolute path to module.tar.gz
	SigPath  string // absolute path to the detached signature, "" if absent
	SHA256   string // hex digest of the archive
	Size     int64
	Signed   bool   // a signature was present and verified
	SigError string // why verification failed, if it did

	parsed semver.Version
}

// Module is one namespace/name/system triple with its versions.
type Module struct {
	Namespace string
	Name      string
	System    string
	Versions  []*Version // ascending by semver precedence
}

// ID is the address Terraform uses, e.g. "acme/vpc/aws".
func (m *Module) ID() string { return m.Namespace + "/" + m.Name + "/" + m.System }

// Latest returns the highest-precedence version, preferring stable releases
// over pre-releases. It returns nil when the module has no servable versions.
func (m *Module) Latest() *Version {
	var latest *Version
	for _, v := range m.Versions {
		if v.parsed.Pre == "" {
			latest = v
		}
	}
	if latest == nil && len(m.Versions) > 0 {
		latest = m.Versions[len(m.Versions)-1]
	}
	return latest
}

// Find returns the named version, or nil.
func (m *Module) Find(version string) *Version {
	want, err := semver.Parse(version)
	if err != nil {
		return nil
	}
	for _, v := range m.Versions {
		if v.parsed.Compare(want) == 0 {
			return v
		}
	}
	return nil
}

// Catalog is an immutable, in-memory view of the module tree. Loading it is
// cheap relative to how often it is read, so the server simply reloads on
// SIGHUP rather than watching the filesystem.
type Catalog struct {
	Root    string
	modules map[string]*Module
}

// Issue is a problem found while loading. Fatal issues mean the affected
// version is not servable; the rest are advisory.
type Issue struct {
	Path    string
	Message string
	Fatal   bool
}

func (i Issue) String() string {
	level := "warn"
	if i.Fatal {
		level = "error"
	}
	return fmt.Sprintf("%s: %s: %s", level, i.Path, i.Message)
}

// Load walks root and returns everything that parsed, plus every problem found.
// A malformed version directory never stops the rest of the catalog from
// loading: one bad publish must not take the registry down.
func Load(root string) (*Catalog, []Issue, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, nil, err
	}
	info, err := os.Stat(abs)
	if err != nil {
		return nil, nil, fmt.Errorf("catalog: %w", err)
	}
	if !info.IsDir() {
		return nil, nil, fmt.Errorf("catalog: %s is not a directory", abs)
	}

	c := &Catalog{Root: abs, modules: map[string]*Module{}}
	var issues []Issue

	namespaces, err := dirs(abs)
	if err != nil {
		return nil, nil, err
	}
	for _, ns := range namespaces {
		if !nameRE.MatchString(ns) {
			issues = append(issues, Issue{ns, "namespace is not a valid registry identifier", true})
			continue
		}
		names, err := dirs(filepath.Join(abs, ns))
		if err != nil {
			return nil, nil, err
		}
		for _, name := range names {
			if !nameRE.MatchString(name) {
				issues = append(issues, Issue{path.Join(ns, name), "module name is not a valid registry identifier", true})
				continue
			}
			systems, err := dirs(filepath.Join(abs, ns, name))
			if err != nil {
				return nil, nil, err
			}
			for _, system := range systems {
				if !systemRE.MatchString(system) {
					issues = append(issues, Issue{path.Join(ns, name, system), "target system must be lower-case letters, digits and dashes", true})
					continue
				}
				mod := &Module{Namespace: ns, Name: name, System: system}
				versions, err := dirs(filepath.Join(abs, ns, name, system))
				if err != nil {
					return nil, nil, err
				}
				for _, ver := range versions {
					rel := path.Join(ns, name, system, ver)
					v, vIssues := loadVersion(filepath.Join(abs, ns, name, system, ver), rel, ver)
					issues = append(issues, vIssues...)
					if v != nil {
						mod.Versions = append(mod.Versions, v)
					}
				}
				if len(mod.Versions) == 0 {
					continue
				}
				sort.Slice(mod.Versions, func(i, j int) bool {
					return mod.Versions[i].parsed.Compare(mod.Versions[j].parsed) < 0
				})
				c.modules[mod.ID()] = mod
			}
		}
	}
	return c, issues, nil
}

func loadVersion(dir, rel, ver string) (*Version, []Issue) {
	parsed, err := semver.Parse(ver)
	if err != nil {
		return nil, []Issue{{rel, "version directory is not valid semver", true}}
	}
	if strings.HasPrefix(ver, "v") {
		return nil, []Issue{{rel, "version directory must not carry a leading \"v\"", true}}
	}

	archive := filepath.Join(dir, ArchiveName)
	st, err := os.Stat(archive)
	if err != nil {
		return nil, []Issue{{rel, "missing " + ArchiveName, true}}
	}

	sum, err := inspectArchive(archive)
	if err != nil {
		return nil, []Issue{{rel, err.Error(), true}}
	}

	v := &Version{
		Version: parsed.String(),
		Archive: archive,
		SHA256:  sum,
		Size:    st.Size(),
		parsed:  parsed,
	}
	if sig := archive + ".sig"; fileExists(sig) {
		v.SigPath = sig
	}
	return v, nil
}

// inspectArchive streams the tarball once: it hashes it and, at the same time,
// asserts it is a gzipped tar with at least one .tf file at the root. Terraform
// will happily download a broken archive and fail later with a confusing error,
// so the registry refuses to serve one in the first place.
func inspectArchive(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", fmt.Errorf("open %s: %w", ArchiveName, err)
	}
	defer f.Close()

	h := sha256.New()
	gz, err := gzip.NewReader(io.TeeReader(f, h))
	if err != nil {
		return "", fmt.Errorf("%s is not a gzip stream: %v", ArchiveName, err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	foundTF := false
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", fmt.Errorf("%s is not a valid tar archive: %v", ArchiveName, err)
		}
		clean := strings.TrimPrefix(path.Clean(hdr.Name), "./")
		if strings.HasPrefix(clean, "../") || path.IsAbs(clean) {
			return "", fmt.Errorf("%s contains an unsafe path %q", ArchiveName, hdr.Name)
		}
		if hdr.Typeflag == tar.TypeReg && !strings.Contains(clean, "/") && strings.HasSuffix(clean, ".tf") {
			foundTF = true
		}
	}
	// Drain whatever the gzip reader did not consume so the hash covers the
	// whole file, trailing bytes included.
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("read %s: %w", ArchiveName, err)
	}
	if !foundTF {
		return "", fmt.Errorf("%s has no .tf files at the archive root", ArchiveName)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// SignatureVerifier is the subset of internal/signature the catalog needs.
type SignatureVerifier interface {
	VerifyBlob(r io.Reader, sig []byte) error
}

// CheckSignatures verifies every archive that has a detached signature.
//
// A signature that is present but does not verify always drops the version:
// that is tampering evidence, not a policy question. Whether a *missing*
// signature is fatal is the policy question, and that is what require decides.
// A private registry that serves an unverifiable artifact has no reason to
// exist, so production configs set it.
func (c *Catalog) CheckSignatures(v SignatureVerifier, require bool) []Issue {
	var issues []Issue
	for id, mod := range c.modules {
		kept := mod.Versions[:0]
		for _, ver := range mod.Versions {
			rel := id + "/" + ver.Version
			switch {
			case ver.SigPath == "":
				ver.SigError = "no detached signature"
				issues = append(issues, Issue{rel, "unsigned: no " + ArchiveName + ".sig alongside the archive", require})
			default:
				if err := verifyOne(v, ver); err != nil {
					ver.SigError = err.Error()
					issues = append(issues, Issue{rel, "signature verification failed: " + err.Error(), true})
				} else {
					ver.Signed = true
				}
			}
			if ver.Signed || (ver.SigPath == "" && !require) {
				kept = append(kept, ver)
			}
		}
		mod.Versions = kept
		if len(mod.Versions) == 0 {
			delete(c.modules, id)
		}
	}
	sort.Slice(issues, func(i, j int) bool { return issues[i].Path < issues[j].Path })
	return issues
}

func verifyOne(v SignatureVerifier, ver *Version) error {
	sig, err := os.ReadFile(ver.SigPath)
	if err != nil {
		return err
	}
	f, err := os.Open(ver.Archive)
	if err != nil {
		return err
	}
	defer f.Close()
	return v.VerifyBlob(f, sig)
}

// Module returns one module by address, or nil.
func (c *Catalog) Module(namespace, name, system string) *Module {
	return c.modules[namespace+"/"+name+"/"+system]
}

// Modules returns every module, ordered by address.
func (c *Catalog) Modules() []*Module {
	out := make([]*Module, 0, len(c.modules))
	for _, m := range c.modules {
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID() < out[j].ID() })
	return out
}

// Len is the number of modules; VersionCount is the number of servable versions.
func (c *Catalog) Len() int { return len(c.modules) }

// VersionCount returns the total number of servable versions in the catalog.
func (c *Catalog) VersionCount() int {
	n := 0
	for _, m := range c.modules {
		n += len(m.Versions)
	}
	return n
}

func dirs(p string) ([]string, error) {
	entries, err := os.ReadDir(p)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		out = append(out, e.Name())
	}
	sort.Strings(out)
	return out, nil
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.Mode().IsRegular()
}
