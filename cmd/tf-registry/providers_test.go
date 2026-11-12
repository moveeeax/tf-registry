package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

const providerTestdata = "../../internal/provider/testdata"

// startProviderRegistry serves the fake "example/demo" provider from the
// provider package's testdata and points providerHTTP at it.
func startProviderRegistry(t *testing.T) (host string, downloads *atomic.Int32) {
	t.Helper()
	key, err := os.ReadFile(filepath.Join(providerTestdata, "signing-key.asc"))
	if err != nil {
		t.Fatal(err)
	}
	n := &atomic.Int32{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const prefix = "/v1/providers/example/demo/1.0.0/download/"
		switch {
		case r.URL.Path == "/.well-known/terraform.json":
			fmt.Fprint(w, `{"providers.v1":"/v1/providers/"}`)
		case strings.HasPrefix(r.URL.Path, prefix):
			osArch := strings.Replace(strings.TrimPrefix(r.URL.Path, prefix), "/", "_", 1)
			name := "terraform-provider-demo_1.0.0_" + osArch + ".zip"
			if _, err := os.Stat(filepath.Join(providerTestdata, name)); err != nil {
				http.NotFound(w, r)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{
				"filename":              name,
				"download_url":          "/files/" + name,
				"shasums_url":           "/files/terraform-provider-demo_1.0.0_SHA256SUMS",
				"shasums_signature_url": "/files/terraform-provider-demo_1.0.0_SHA256SUMS.sig",
				"signing_keys": map[string]any{
					"gpg_public_keys": []map[string]string{{"ascii_armor": string(key)}},
				},
			})
		case strings.HasPrefix(r.URL.Path, "/files/"):
			if strings.HasSuffix(r.URL.Path, ".zip") {
				n.Add(1)
			}
			http.ServeFile(w, r, filepath.Join(providerTestdata, strings.TrimPrefix(r.URL.Path, "/files/")))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	old := providerHTTP
	providerHTTP = srv.Client()
	t.Cleanup(func() { providerHTTP = old })
	u, _ := url.Parse(srv.URL)
	return u.Host, n
}

// writeLocks writes two stack lock files pinning the same provider: the merge
// must fetch each package once.
func writeLocks(t *testing.T, host string) string {
	t.Helper()
	dir := t.TempDir()
	for _, stack := range []string{"dev", "prod"} {
		lock := fmt.Sprintf(`provider "%s/example/demo" {
  version = "1.0.0"
  hashes = [
    "h1:rhQgjwqgotvKnCGGdI2z8jiZOgPr8wmgDy9t1A6dJe8=",
    "zh:78ff78d454586b7aeec845903193c2572aa53b3b5ce185e5b57fc6cb90b0fe0d",
    "zh:9831366c802d18967629ae27c2c5b98afbbff966a11244190bea7f96a8d88cd9",
  ]
}
`, host)
		p := filepath.Join(dir, "envs", stack, ".terraform.lock.hcl")
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(lock), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return filepath.Join(dir, "envs", "*", ".terraform.lock.hcl")
}

func TestCacheWarm(t *testing.T) {
	host, downloads := startProviderRegistry(t)
	glob := writeLocks(t, host)
	cache := t.TempDir()
	args := []string{"cache-warm", "-lock", glob, "-cache-dir", cache, "-platform", "linux_amd64", "-platform", "darwin_arm64"}

	stdout, _, err := runCLI(t, args...)
	if err != nil {
		t.Fatalf("cache-warm: %v\n%s", err, stdout)
	}
	for _, want := range []string{
		"from 2 lock file(s): 2 package(s)",
		"fetched  " + host + "/example/demo 1.0.0 darwin_arm64",
		"signed by 7957AC75E1DB1A9C",
		// The lock has an h1: for darwin only (the hash Terraform recorded
		// for that zip), so linux gets the warning.
		"warn: " + host + "/example/demo 1.0.0 linux_amd64: the lock file has no h1: hash",
		"2 fetched, 0 already present, 0 failed",
		"cache key: ",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("output is missing %q:\n%s", want, stdout)
		}
	}
	if n := downloads.Load(); n != 2 {
		t.Errorf("downloaded %d zips for two lock files pinning one version on two platforms, want 2", n)
	}
	if _, err := os.Stat(filepath.Join(cache, host, "example", "demo", "1.0.0", "darwin_arm64", "terraform-provider-demo_v1.0.0")); err != nil {
		t.Errorf("cache entry missing: %v", err)
	}

	// -key-only needs no network and agrees with the key the full run printed.
	keyOut, _, err := runCLI(t, append(args, "-key-only")...)
	if err != nil {
		t.Fatal(err)
	}
	if key := strings.TrimSpace(keyOut); len(key) != 64 || !strings.Contains(stdout, "cache key: "+key) {
		t.Errorf("-key-only printed %q; full run printed:\n%s", key, stdout)
	}

	// Second run: darwin is verified by its h1: and kept; linux has no h1: in
	// the lock, so the directory cannot be checked and is fetched again.
	stdout, _, err = runCLI(t, args...)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "1 fetched, 1 already present, 0 failed") {
		t.Errorf("second run:\n%s", stdout)
	}
}

func TestCacheWarmFlagErrors(t *testing.T) {
	t.Setenv("TF_PLUGIN_CACHE_DIR", "")
	cases := [][]string{
		{"cache-warm", "-cache-dir", "x"},
		{"cache-warm", "-lock", "./does-not-exist/*.hcl", "-cache-dir", "x"},
		{"cache-warm", "-lock", "../../internal/provider/testdata/terraform-fs-mirror.lock.hcl"},
		{"cache-warm", "-lock", "../../internal/provider/testdata/terraform-fs-mirror.lock.hcl", "-cache-dir", "x", "-platform", "linux"},
		{"cache-warm", "-lock", "../../internal/provider/testdata/terraform-fs-mirror.lock.hcl", "-cache-dir", "x", "-concurrency", "0"},
	}
	for _, args := range cases {
		if _, _, err := runCLI(t, args...); err == nil {
			t.Errorf("%v: expected an error", args)
		}
	}
}

func TestMirror(t *testing.T) {
	host, _ := startProviderRegistry(t)
	glob := writeLocks(t, host)
	work := t.TempDir()
	out := filepath.Join(work, "mirror")
	bundle := filepath.Join(work, "mirror.tar.gz")
	rc := filepath.Join(work, "mirror.tfrc")

	stdout, _, err := runCLI(t, "mirror", "-lock", glob, "-out", out,
		"-platform", "linux_amd64", "-platform", "darwin_arm64",
		"-pack", bundle, "-cli-config", rc, "-mirror-path", "/opt/tf-mirror")
	if err != nil {
		t.Fatalf("mirror: %v\n%s", err, stdout)
	}
	for _, want := range []string{
		"building packed mirror",
		"2 fetched, 0 already present, 0 failed",
		"packed " + bundle,
		`path    = "/opt/tf-mirror"`,
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("output is missing %q:\n%s", want, stdout)
		}
	}
	if strings.Contains(stdout, "warn:") {
		t.Errorf("a packed mirror is checked by zh:, it needs no h1: warning:\n%s", stdout)
	}
	zip := filepath.Join(out, host, "example", "demo", "terraform-provider-demo_1.0.0_linux_amd64.zip")
	if _, err := os.Stat(zip); err != nil {
		t.Errorf("mirror zip missing: %v", err)
	}
	sidecar, err := os.ReadFile(bundle + ".sha256")
	if err != nil || !strings.HasSuffix(string(sidecar), "  mirror.tar.gz\n") {
		t.Errorf("sidecar = %q, %v", sidecar, err)
	}
	cfg, err := os.ReadFile(rc)
	if err != nil || !strings.Contains(string(cfg), `"`+host+`/example/demo",`) {
		t.Errorf("cli config = %q, %v", cfg, err)
	}

	stdout, _, err = runCLI(t, "mirror", "-lock", glob, "-out", out, "-platform", "linux_amd64", "-platform", "darwin_arm64")
	if err != nil || !strings.Contains(stdout, "0 fetched, 2 already present, 0 failed") {
		t.Errorf("incremental rebuild: %v\n%s", err, stdout)
	}
}

func TestMirrorFailsOnUnlockedPlatform(t *testing.T) {
	host, _ := startProviderRegistry(t)
	glob := writeLocks(t, host)
	stdout, _, err := runCLI(t, "mirror", "-lock", glob, "-out", t.TempDir(), "-platform", "windows_amd64")
	if err == nil {
		t.Fatalf("mirror for a platform the registry lacks should fail:\n%s", stdout)
	}
	if !strings.Contains(stdout, "error: ") || !strings.Contains(stdout, "0 fetched, 0 already present, 1 failed") {
		t.Errorf("output:\n%s", stdout)
	}
}

func TestMirrorFlagErrors(t *testing.T) {
	lock := "../../internal/provider/testdata/terraform-fs-mirror.lock.hcl"
	for _, args := range [][]string{
		{"mirror", "-lock", lock},
		{"mirror", "-lock", lock, "-out", t.TempDir(), "-layout", "flat"},
	} {
		if _, _, err := runCLI(t, args...); err == nil {
			t.Errorf("%v: expected an error", args)
		}
	}
}
