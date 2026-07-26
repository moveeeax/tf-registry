package catalog

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/moveeeax/tf-registry/internal/signature"
)

// exampleCatalog is the same tree the README walks through, so a change that
// breaks the documented example breaks the tests too.
const exampleCatalog = "../../examples/catalog"

func loadExample(t *testing.T) *Catalog {
	t.Helper()
	c, issues, err := Load(exampleCatalog)
	if err != nil {
		t.Fatalf("Load(%s): %v", exampleCatalog, err)
	}
	for _, i := range issues {
		t.Errorf("unexpected issue in example catalog: %s", i)
	}
	return c
}

func TestLoadExampleCatalog(t *testing.T) {
	c := loadExample(t)

	if got, want := c.Len(), 3; got != want {
		t.Fatalf("Len() = %d, want %d (%v)", got, want, ids(c))
	}
	if got, want := c.VersionCount(), 5; got != want {
		t.Errorf("VersionCount() = %d, want %d", got, want)
	}

	want := []string{"acme/aks/azurerm", "acme/vpc/aws", "globex/object-store/oci"}
	if got := ids(c); !equal(got, want) {
		t.Errorf("Modules() = %v, want %v", got, want)
	}

	vpc := c.Module("acme", "vpc", "aws")
	if vpc == nil {
		t.Fatal("Module(acme, vpc, aws) = nil")
	}
	gotVersions := make([]string, len(vpc.Versions))
	for i, v := range vpc.Versions {
		gotVersions[i] = v.Version
	}
	// 1.10.0 must sort above 1.2.0, and the pre-release above both.
	if wantVersions := []string{"1.2.0", "1.10.0", "2.0.0-rc.1"}; !equal(gotVersions, wantVersions) {
		t.Errorf("versions = %v, want %v", gotVersions, wantVersions)
	}
}

func TestLatestSkipsPrereleases(t *testing.T) {
	c := loadExample(t)
	vpc := c.Module("acme", "vpc", "aws")
	if got := vpc.Latest().Version; got != "1.10.0" {
		t.Errorf("Latest() = %s, want 1.10.0 (2.0.0-rc.1 is a pre-release)", got)
	}

	aks := c.Module("acme", "aks", "azurerm")
	if got := aks.Latest().Version; got != "0.3.1" {
		t.Errorf("Latest() = %s, want 0.3.1", got)
	}
}

func TestFind(t *testing.T) {
	c := loadExample(t)
	vpc := c.Module("acme", "vpc", "aws")

	for _, in := range []string{"1.2.0", "v1.2.0"} {
		v := vpc.Find(in)
		if v == nil {
			t.Fatalf("Find(%q) = nil", in)
		}
		if v.Version != "1.2.0" {
			t.Errorf("Find(%q).Version = %s", in, v.Version)
		}
		if len(v.SHA256) != 64 {
			t.Errorf("Find(%q).SHA256 = %q, want a 64-char hex digest", in, v.SHA256)
		}
		if v.Size <= 0 {
			t.Errorf("Find(%q).Size = %d", in, v.Size)
		}
	}
	for _, in := range []string{"9.9.9", "nonsense", ""} {
		if v := vpc.Find(in); v != nil {
			t.Errorf("Find(%q) = %v, want nil", in, v)
		}
	}
	if c.Module("acme", "vpc", "gcp") != nil {
		t.Error("Module for an unpublished target system should be nil")
	}
}

func TestLoadReportsBrokenArchives(t *testing.T) {
	c, issues, err := Load(filepath.Join("testdata", "broken"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	want := map[string]string{
		"notf/mod/aws/1.0.0":     "no .tf files at the archive root",
		"badversion/mod/aws/1.0": "not valid semver",
		"notgzip/mod/aws/1.0.0":  "not a gzip stream",
	}
	got := map[string]string{}
	for _, i := range issues {
		got[i.Path] = i.Message
		if !i.Fatal {
			t.Errorf("issue %s should be fatal", i)
		}
	}
	for p, substr := range want {
		msg, ok := got[p]
		if !ok {
			t.Errorf("no issue reported for %s (got %v)", p, got)
			continue
		}
		if !strings.Contains(msg, substr) {
			t.Errorf("issue for %s = %q, want it to mention %q", p, msg, substr)
		}
	}

	// The two structurally sound modules still load; the broken ones do not.
	if c.Module("notf", "mod", "aws") != nil {
		t.Error("a module with no .tf files must not be servable")
	}
	if c.Module("tampered", "mod", "aws") == nil {
		t.Error("the tampered module loads fine until signatures are checked")
	}
}

func TestCheckSignaturesRejectsTamperedAndUnsigned(t *testing.T) {
	v, err := signature.LoadPublicKeyFile(filepath.Join("testdata", "broken", "cosign.pub"))
	if err != nil {
		t.Fatalf("LoadPublicKeyFile: %v", err)
	}
	c, _, err := Load(filepath.Join("testdata", "broken"))
	if err != nil {
		t.Fatal(err)
	}

	issues := c.CheckSignatures(v, true)
	byPath := map[string]Issue{}
	for _, i := range issues {
		byPath[i.Path] = i
	}

	if i, ok := byPath["tampered/mod/aws/1.0.0"]; !ok || !strings.Contains(i.Message, "verification failed") {
		t.Errorf("tampered module: got %v, want a verification failure", i)
	}
	if i, ok := byPath["unsigned/mod/aws/1.0.0"]; !ok || !strings.Contains(i.Message, "unsigned") {
		t.Errorf("unsigned module: got %v, want an unsigned issue", i)
	}
	if c.Module("tampered", "mod", "aws") != nil {
		t.Error("a module whose signature fails verification must not be servable")
	}
	if c.Module("unsigned", "mod", "aws") != nil {
		t.Error("with require=true an unsigned module must not be servable")
	}
}

func TestCheckSignaturesOptionalKeepsUnsignedButNotTampered(t *testing.T) {
	v, err := signature.LoadPublicKeyFile(filepath.Join("testdata", "broken", "cosign.pub"))
	if err != nil {
		t.Fatal(err)
	}
	c, _, err := Load(filepath.Join("testdata", "broken"))
	if err != nil {
		t.Fatal(err)
	}

	c.CheckSignatures(v, false)

	if c.Module("unsigned", "mod", "aws") == nil {
		t.Error("with require=false an unsigned module stays servable")
	}
	if c.Module("tampered", "mod", "aws") != nil {
		t.Error("a bad signature is tampering evidence and must drop the version regardless of policy")
	}
}

func TestCheckSignaturesOnExampleCatalog(t *testing.T) {
	v, err := signature.LoadPublicKeyFile("../../examples/keys/cosign.pub")
	if err != nil {
		t.Fatal(err)
	}
	c := loadExample(t)

	issues := c.CheckSignatures(v, true)
	if len(issues) != 1 {
		t.Fatalf("issues = %v, want exactly one (the unsigned pre-release)", issues)
	}
	if issues[0].Path != "acme/vpc/aws/2.0.0-rc.1" {
		t.Errorf("issue path = %s, want acme/vpc/aws/2.0.0-rc.1", issues[0].Path)
	}

	vpc := c.Module("acme", "vpc", "aws")
	if got := len(vpc.Versions); got != 2 {
		t.Fatalf("acme/vpc/aws has %d servable versions, want 2", got)
	}
	for _, ver := range vpc.Versions {
		if !ver.Signed {
			t.Errorf("version %s should be marked signed", ver.Version)
		}
	}
	if got := c.VersionCount(); got != 4 {
		t.Errorf("VersionCount() after enforcement = %d, want 4", got)
	}
}

func TestLoadMissingRoot(t *testing.T) {
	if _, _, err := Load(filepath.Join("testdata", "no-such-dir")); err == nil {
		t.Error("Load on a missing root: want error")
	}
	if _, _, err := Load(filepath.Join("testdata", "broken", "cosign.pub")); err == nil {
		t.Error("Load on a file: want error")
	}
}

func ids(c *Catalog) []string {
	out := []string{}
	for _, m := range c.Modules() {
		out = append(out, m.ID())
	}
	return out
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
