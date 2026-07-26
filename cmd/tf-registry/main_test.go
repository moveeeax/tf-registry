package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func runCLI(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	var out, errOut bytes.Buffer
	err = run(args, &out, &errOut)
	return out.String(), errOut.String(), err
}

// TestValidateExampleCatalog is the command the README tells the reader to run
// first. If it stops behaving, the documented walkthrough is wrong.
func TestValidateExampleCatalog(t *testing.T) {
	stdout, _, err := runCLI(t, "validate",
		"-catalog", "../../examples/catalog",
		"-key", "../../examples/keys/cosign.pub")
	if err != nil {
		t.Fatalf("validate returned error: %v\n%s", err, stdout)
	}

	for _, want := range []string{
		"acme/aks/azurerm",
		"acme/vpc/aws",
		"globex/object-store/oci",
		"1.10.0",
		"signed",
		"3 modules, 5 servable versions, 0 errors, 1 warnings",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("validate output is missing %q:\n%s", want, stdout)
		}
	}
}

func TestValidateEnforcingSignatures(t *testing.T) {
	stdout, _, err := runCLI(t, "validate",
		"-catalog", "../../examples/catalog",
		"-key", "../../examples/keys/cosign.pub",
		"-require-signatures")
	if err == nil {
		t.Fatalf("validate -require-signatures should fail on the unsigned pre-release:\n%s", stdout)
	}
	if !strings.Contains(stdout, "acme/vpc/aws/2.0.0-rc.1") {
		t.Errorf("output does not name the offending version:\n%s", stdout)
	}
	if !strings.Contains(stdout, "3 modules, 4 servable versions, 1 errors") {
		t.Errorf("summary line is wrong:\n%s", stdout)
	}
}

func TestValidateRejectsBrokenCatalog(t *testing.T) {
	stdout, _, err := runCLI(t, "validate", "-catalog", "../../internal/catalog/testdata/broken")
	if err == nil {
		t.Fatalf("validate on the broken fixture should fail:\n%s", stdout)
	}
	for _, want := range []string{"no .tf files", "not a gzip stream", "not valid semver"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("output is missing %q:\n%s", want, stdout)
		}
	}
}

func TestValidateFlagErrors(t *testing.T) {
	if _, _, err := runCLI(t, "validate", "-catalog", "../../examples/catalog", "-require-signatures"); err == nil {
		t.Error("-require-signatures without -key should be rejected")
	}
	if _, _, err := runCLI(t, "validate", "-catalog", "./does-not-exist"); err == nil {
		t.Error("validate on a missing catalog should fail")
	}
}

func TestVerifyCommand(t *testing.T) {
	key := "../../examples/keys/cosign.pub"
	archive := "../../examples/catalog/acme/vpc/aws/1.2.0/module.tar.gz"

	stdout, _, err := runCLI(t, "verify", "-key", key, archive, archive+".sig")
	if err != nil {
		t.Fatalf("verify on a good pair: %v", err)
	}
	if !strings.Contains(stdout, "OK:") || !strings.Contains(stdout, "ecdsa-P-256") {
		t.Errorf("verify output = %q", stdout)
	}

	// The signature of a different module must not verify this archive.
	other := "../../examples/catalog/acme/aks/azurerm/0.3.1/module.tar.gz.sig"
	if _, _, err := runCLI(t, "verify", "-key", key, archive, other); err == nil {
		t.Error("verify accepted a signature from another module")
	}
	if _, _, err := runCLI(t, "verify", "-key", key, archive); err == nil {
		t.Error("verify with a missing argument should fail")
	}
}

func TestTokenCommand(t *testing.T) {
	stdout, _, err := runCLI(t, "token")
	if err != nil {
		t.Fatalf("token: %v", err)
	}

	var token, digest string
	for _, line := range strings.Fields(stdout) {
		if strings.HasPrefix(line, "tfr_") {
			token = strings.Trim(line, `",`)
			break
		}
	}
	if token == "" {
		t.Fatalf("no token in output:\n%s", stdout)
	}
	for _, field := range strings.Fields(stdout) {
		trimmed := strings.Trim(field, `",`)
		if len(trimmed) == 64 {
			if _, err := hex.DecodeString(trimmed); err == nil {
				digest = trimmed
			}
		}
	}
	if digest == "" {
		t.Fatalf("no digest in output:\n%s", stdout)
	}

	sum := sha256.Sum256([]byte(token))
	if hex.EncodeToString(sum[:]) != digest {
		t.Error("the printed digest is not the digest of the printed token")
	}

	// -hash must agree with what token printed.
	hashed, _, err := runCLI(t, "token", "-hash", token)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(hashed) != digest {
		t.Errorf("token -hash = %q, want %q", strings.TrimSpace(hashed), digest)
	}
}

func TestLoadExampleConfig(t *testing.T) {
	cfg, err := LoadConfig("../../examples/registry.json")
	if err != nil {
		t.Fatalf("LoadConfig on the example config: %v", err)
	}
	if !cfg.RequireSignatures {
		t.Error("the example config should require signatures")
	}
	if cfg.TTL().Minutes() != 5 {
		t.Errorf("TTL = %s, want 5m", cfg.TTL())
	}
	if len(cfg.Orgs) != 2 {
		t.Fatalf("orgs = %d, want 2", len(cfg.Orgs))
	}

	// Relative paths resolve against the config file, not the cwd.
	if _, err := os.Stat(cfg.Path(cfg.CatalogDir)); err != nil {
		t.Errorf("catalog_dir did not resolve: %v", err)
	}
	if _, err := os.Stat(cfg.Path(cfg.PublicKeyFile)); err != nil {
		t.Errorf("public_key_file did not resolve: %v", err)
	}

	// The digests in the example config must match the documented demo tokens,
	// or the README walkthrough authenticates against nothing.
	want := map[string]string{"acme": "tfr_demo_acme_token", "globex": "tfr_demo_globex_token"}
	for _, org := range cfg.Orgs {
		sum := sha256.Sum256([]byte(want[org.Name]))
		if org.TokenSHA256 != hex.EncodeToString(sum[:]) {
			t.Errorf("org %s: token_sha256 does not match the documented demo token", org.Name)
		}
	}
}

func TestLoadConfigRejectsBadInput(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	org := `"orgs":[{"name":"a","namespaces":["a"],"token_sha256":"` + strings.Repeat("a", 64) + `"}]`
	cases := map[string]string{
		"not json":       `{`,
		"unknown field":  `{"base_url":"http://x","catalog_dir":"c","listen_on":"x",` + org + `}`,
		"no base_url":    `{"catalog_dir":"c",` + org + `}`,
		"no catalog_dir": `{"base_url":"http://x",` + org + `}`,
		"no orgs":        `{"base_url":"http://x","catalog_dir":"c"}`,
		"bad ttl":        `{"base_url":"http://x","catalog_dir":"c","download_url_ttl":"soon",` + org + `}`,
		"zero ttl":       `{"base_url":"http://x","catalog_dir":"c","download_url_ttl":"0s",` + org + `}`,
		"require no key": `{"base_url":"http://x","catalog_dir":"c","require_signatures":true,` + org + `}`,
	}
	for name, body := range cases {
		if _, err := LoadConfig(write(strings.ReplaceAll(name, " ", "_")+".json", body)); err == nil {
			t.Errorf("LoadConfig(%s): want error", name)
		}
	}
	if _, err := LoadConfig(filepath.Join(dir, "missing.json")); err == nil {
		t.Error("LoadConfig on a missing file: want error")
	}
}

func TestUnknownCommand(t *testing.T) {
	if _, _, err := runCLI(t); err == nil {
		t.Error("no arguments should be an error")
	}
	if _, _, err := runCLI(t, "deploy"); err == nil {
		t.Error("an unknown command should be an error")
	}
	if stdout, _, err := runCLI(t, "version"); err != nil || !strings.Contains(stdout, "tf-registry") {
		t.Errorf("version = %q, %v", stdout, err)
	}
	if stdout, _, err := runCLI(t, "help"); err != nil || !strings.Contains(stdout, "Usage:") {
		t.Errorf("help = %q, %v", stdout, err)
	}
}
