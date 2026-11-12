package provider

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/moveeeax/tf-registry/internal/lockfile"
)

// testdata holds a fake provider "demo" 1.0.0 for linux_amd64 and darwin_arm64,
// its SHA256SUMS signed with the RSA test key from ../openpgp/testdata (the
// public half is signing-key.asc), and terraform-fs-mirror.lock.hcl: the lock
// file stock Terraform 1.17 wrote for those two zips with
// `terraform providers lock -fs-mirror`, i.e. Terraform's own h1: hashes.

const (
	zhLinux  = "zh:9831366c802d18967629ae27c2c5b98afbbff966a11244190bea7f96a8d88cd9"
	zhDarwin = "zh:78ff78d454586b7aeec845903193c2572aa53b3b5ce185e5b57fc6cb90b0fe0d"
)

var (
	linux  = Platform{"linux", "amd64"}
	darwin = Platform{"darwin", "arm64"}
)

func readTestdata(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// terraformH1 returns the h1: hashes Terraform recorded, keyed by platform.
func terraformH1(t *testing.T) map[Platform]string {
	t.Helper()
	ps, err := lockfile.ParseFile(filepath.Join("testdata", "terraform-fs-mirror.lock.hcl"))
	if err != nil {
		t.Fatal(err)
	}
	out := map[Platform]string{}
	for _, pl := range []Platform{linux, darwin} {
		h1, err := ZipH1(filepath.Join("testdata", "terraform-provider-demo_1.0.0_"+pl.String()+".zip"))
		if err != nil {
			t.Fatal(err)
		}
		for _, h := range ps[0].Hashes {
			if h == h1 {
				out[pl] = h1
			}
		}
	}
	return out
}

func TestZipH1MatchesTerraform(t *testing.T) {
	got := terraformH1(t)
	if len(got) != 2 {
		t.Fatalf("ZipH1 matched %d of Terraform's 2 h1: hashes", len(got))
	}
}

func TestDirH1MatchesZipH1(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join("testdata", "terraform-provider-demo_1.0.0_linux_amd64.zip")
	if err := unzip(zipPath, dir); err != nil {
		t.Fatal(err)
	}
	a, err := ZipH1(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	b, err := DirH1(dir)
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatalf("DirH1 = %s, ZipH1 = %s", b, a)
	}
	info, err := os.Stat(filepath.Join(dir, "terraform-provider-demo_v1.0.0"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o100 == 0 {
		t.Errorf("provider binary lost its executable bit: %v", info.Mode())
	}
}

func TestPlanAndCacheKey(t *testing.T) {
	aws := lockfile.Provider{Addr: lockfile.Addr{Hostname: "registry.terraform.io", Namespace: "hashicorp", Type: "aws"}, Version: "5.0.0", Hashes: []string{"zh:01"}}
	rnd := lockfile.Provider{Addr: lockfile.Addr{Hostname: "registry.terraform.io", Namespace: "hashicorp", Type: "random"}, Version: "3.6.0", Hashes: []string{"zh:02"}}
	items := Plan([]lockfile.Provider{rnd, aws}, []Platform{linux, darwin, linux})
	var got []string
	for _, it := range items {
		got = append(got, it.String())
	}
	want := []string{
		"registry.terraform.io/hashicorp/aws 5.0.0 darwin_arm64",
		"registry.terraform.io/hashicorp/aws 5.0.0 linux_amd64",
		"registry.terraform.io/hashicorp/random 3.6.0 darwin_arm64",
		"registry.terraform.io/hashicorp/random 3.6.0 linux_amd64",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("Plan =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	k1 := CacheKey(items, Unpacked)
	if k2 := CacheKey(Plan([]lockfile.Provider{aws, rnd}, []Platform{darwin, linux}), Unpacked); k1 != k2 {
		t.Error("cache key depends on input order")
	}
	if CacheKey(items, Packed) == k1 {
		t.Error("cache key ignores the layout")
	}
	aws2 := aws
	aws2.Hashes = []string{"zh:03"}
	if CacheKey(Plan([]lockfile.Provider{aws2, rnd}, []Platform{linux, darwin}), Unpacked) == k1 {
		t.Error("cache key ignores a changed lock hash")
	}
	if CacheKey(Plan([]lockfile.Provider{aws, rnd}, []Platform{linux}), Unpacked) == k1 {
		t.Error("cache key ignores the platform list")
	}
}

func TestLayoutPaths(t *testing.T) {
	it := Item{Provider: lockfile.Provider{Addr: lockfile.Addr{Hostname: "registry.terraform.io", Namespace: "hashicorp", Type: "aws"}, Version: "5.0.0"}, Platform: linux}
	if got := Packed.RelPath(it); got != "registry.terraform.io/hashicorp/aws/terraform-provider-aws_5.0.0_linux_amd64.zip" {
		t.Errorf("packed = %s", got)
	}
	if got := Unpacked.RelPath(it); got != "registry.terraform.io/hashicorp/aws/5.0.0/linux_amd64" {
		t.Errorf("unpacked = %s", got)
	}
}

func TestParsePlatform(t *testing.T) {
	if p, err := ParsePlatform("linux_amd64"); err != nil || p != linux {
		t.Errorf("ParsePlatform(linux_amd64) = %v, %v", p, err)
	}
	for _, bad := range []string{"linux", "linux-amd64", "Linux_amd64", "linux_amd64_v2", ""} {
		if _, err := ParsePlatform(bad); err == nil {
			t.Errorf("ParsePlatform(%q) accepted", bad)
		}
	}
}

// ---------------------------------------------------------------- fake registry

type fakeRegistry struct {
	t   *testing.T
	srv *httptest.Server

	mu       sync.Mutex
	requests map[string]int // path -> count
	// throttle makes the first n requests to a path answer 429.
	throttle map[string]int
	// files overrides the bytes served for a file name.
	files map[string][]byte
	// signingKey is the armored key the download endpoint advertises.
	signingKey string
	// sawAuth records the Authorization header per path.
	sawAuth map[string]string
}

func newFakeRegistry(t *testing.T) *fakeRegistry {
	f := &fakeRegistry{
		t:          t,
		requests:   map[string]int{},
		throttle:   map[string]int{},
		files:      map[string][]byte{},
		sawAuth:    map[string]string{},
		signingKey: string(readTestdata(t, "signing-key.asc")),
	}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeRegistry) host() string {
	u, _ := url.Parse(f.srv.URL)
	return u.Host
}

func (f *fakeRegistry) count(path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.requests[path]
}

func (f *fakeRegistry) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.requests[r.URL.Path]++
	f.sawAuth[r.URL.Path] = r.Header.Get("Authorization")
	if f.throttle[r.URL.Path] > 0 {
		f.throttle[r.URL.Path]--
		f.mu.Unlock()
		w.Header().Set("Retry-After", "1")
		http.Error(w, "slow down", http.StatusTooManyRequests)
		return
	}
	f.mu.Unlock()

	switch {
	case r.URL.Path == "/.well-known/terraform.json":
		fmt.Fprint(w, `{"modules.v1":"/v1/modules/","providers.v1":"/v1/providers/"}`)
	case strings.HasPrefix(r.URL.Path, "/v1/providers/example/demo/1.0.0/download/"):
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/providers/example/demo/1.0.0/download/"), "/")
		if len(parts) != 2 || parts[0]+"_"+parts[1] == "windows_amd64" {
			http.NotFound(w, r)
			return
		}
		name := "terraform-provider-demo_1.0.0_" + parts[0] + "_" + parts[1] + ".zip"
		sum := strings.TrimPrefix(map[string]string{"linux": zhLinux, "darwin": zhDarwin}[parts[0]], "zh:")
		resp := map[string]any{
			"protocols":             []string{"5.0"},
			"os":                    parts[0],
			"arch":                  parts[1],
			"filename":              name,
			"download_url":          "/files/" + name, // relative, as the protocol allows
			"shasums_url":           f.srv.URL + "/files/terraform-provider-demo_1.0.0_SHA256SUMS",
			"shasums_signature_url": "/files/terraform-provider-demo_1.0.0_SHA256SUMS.sig",
			"shasum":                sum,
			"signing_keys": map[string]any{
				"gpg_public_keys": []map[string]string{{"key_id": "1573FBAA1F6025AA", "ascii_armor": f.signingKey}},
			},
		}
		json.NewEncoder(w).Encode(resp)
	case strings.HasPrefix(r.URL.Path, "/files/"):
		name := strings.TrimPrefix(r.URL.Path, "/files/")
		f.mu.Lock()
		b, ok := f.files[name]
		f.mu.Unlock()
		if !ok {
			var err error
			b, err = os.ReadFile(filepath.Join("testdata", name))
			if err != nil {
				http.NotFound(w, r)
				return
			}
		}
		w.Write(b)
	default:
		http.NotFound(w, r)
	}
}

// lock returns the demo provider locked on the fake registry's host with the
// given hashes.
func (f *fakeRegistry) lock(hashes ...string) lockfile.Provider {
	return lockfile.Provider{
		Addr:    lockfile.Addr{Hostname: f.host(), Namespace: "example", Type: "demo"},
		Version: "1.0.0",
		Hashes:  hashes,
	}
}

func (f *fakeRegistry) installer(root string, layout Layout) *Installer {
	return &Installer{
		Client: &Client{
			HTTP:  f.srv.Client(),
			Token: func(host string) string { return "tok-" + host },
			sleep: func(context.Context, time.Duration) error { return nil },
		},
		Root:             root,
		Layout:           layout,
		VerifySignatures: true,
		Concurrency:      2,
	}
}

func mustOK(t *testing.T, results []Result) {
	t.Helper()
	for _, r := range results {
		if r.Err != nil {
			t.Fatalf("%s: %v", r.Item, r.Err)
		}
	}
}

func TestInstallUnpackedCache(t *testing.T) {
	f := newFakeRegistry(t)
	h1 := terraformH1(t)
	root := t.TempDir()
	items := Plan([]lockfile.Provider{f.lock(zhLinux, zhDarwin, h1[linux])}, []Platform{linux, darwin})

	results := f.installer(root, Unpacked).Install(context.Background(), items)
	mustOK(t, results)
	for _, r := range results {
		if r.Status != Fetched {
			t.Errorf("%s: status %s, want fetched", r.Item, r.Status)
		}
		if r.Signer != "7957AC75E1DB1A9C" {
			t.Errorf("%s: signer %q", r.Item, r.Signer)
		}
		got, err := DirH1(r.Path)
		if err != nil || got != h1[r.Item.Platform] {
			t.Errorf("%s: unpacked tree hashes to %s (%v), want Terraform's %s", r.Item, got, err, h1[r.Item.Platform])
		}
		// Only darwin lacks an h1: in this lock, so only darwin is flagged.
		if (r.Warning != "") != (r.Item.Platform == darwin) {
			t.Errorf("%s: warning = %q", r.Item, r.Warning)
		}
	}
	want := filepath.Join(root, f.host(), "example", "demo", "1.0.0", "linux_amd64", "terraform-provider-demo_v1.0.0")
	if _, err := os.Stat(want); err != nil {
		t.Errorf("cache entry not where plugin_cache_dir expects it: %v", err)
	}
	// SHA256SUMS is shared by both platforms and fetched once.
	if n := f.count("/files/terraform-provider-demo_1.0.0_SHA256SUMS"); n != 1 {
		t.Errorf("SHA256SUMS fetched %d times, want 1", n)
	}
	// The registry API gets the token; nothing is left behind in the cache.
	if got := f.sawAuth["/v1/providers/example/demo/1.0.0/download/linux/amd64"]; got != "Bearer tok-"+f.host() {
		t.Errorf("registry call Authorization = %q", got)
	}
	assertNoStragglers(t, root)

	// A second run finds the h1:-locked entry and downloads nothing for it.
	before := f.count("/files/terraform-provider-demo_1.0.0_linux_amd64.zip")
	results = f.installer(root, Unpacked).Install(context.Background(), items)
	mustOK(t, results)
	for _, r := range results {
		if r.Item.Platform == linux && r.Status != Present {
			t.Errorf("second run: linux status %s, want present", r.Status)
		}
	}
	if after := f.count("/files/terraform-provider-demo_1.0.0_linux_amd64.zip"); after != before {
		t.Errorf("second run downloaded the linux zip again")
	}
}

func TestInstallPackedMirrorIsIncremental(t *testing.T) {
	f := newFakeRegistry(t)
	root := t.TempDir()
	items := Plan([]lockfile.Provider{f.lock(zhLinux, zhDarwin)}, []Platform{linux, darwin})
	mustOK(t, f.installer(root, Packed).Install(context.Background(), items))

	for _, it := range items {
		p := Packed.Path(root, it)
		sum, err := FileSHA256(p)
		if err != nil {
			t.Fatal(err)
		}
		want := map[Platform]string{linux: zhLinux, darwin: zhDarwin}[it.Platform]
		if "zh:"+sum != want {
			t.Errorf("%s: mirror zip is %s, want %s", it, sum, want)
		}
	}

	results := f.installer(root, Packed).Install(context.Background(), items)
	mustOK(t, results)
	for _, r := range results {
		if r.Status != Present {
			t.Errorf("%s: second run status %s, want present", r.Item, r.Status)
		}
	}
	if n := f.count("/v1/providers/example/demo/1.0.0/download/linux/amd64"); n != 1 {
		t.Errorf("second run asked the registry again (%d calls)", n)
	}

	// A mirror file that no longer matches is replaced, not trusted.
	p := Packed.Path(root, items[1])
	if err := os.WriteFile(p, []byte("corrupt"), 0o644); err != nil {
		t.Fatal(err)
	}
	results = f.installer(root, Packed).Install(context.Background(), items[1:])
	mustOK(t, results)
	if results[0].Status != Fetched {
		t.Errorf("corrupt entry status %s, want fetched", results[0].Status)
	}
}

func TestInstallRefusesPackageNotInLock(t *testing.T) {
	f := newFakeRegistry(t)
	root := t.TempDir()
	// The lock pins some other build of the provider.
	items := Plan([]lockfile.Provider{f.lock("zh:" + strings.Repeat("0", 64))}, []Platform{linux})
	r := f.installer(root, Packed).Install(context.Background(), items)[0]
	if r.Err == nil || !strings.Contains(r.Err.Error(), "matches no hash in the lock file") {
		t.Fatalf("err = %v", r.Err)
	}
	if _, err := os.Stat(r.Path); !errors.Is(err, os.ErrNotExist) {
		t.Error("a refused package was written to disk")
	}
	assertNoStragglers(t, root)
}

func TestInstallRefusesEmptyLock(t *testing.T) {
	f := newFakeRegistry(t)
	r := f.installer(t.TempDir(), Packed).Install(context.Background(), Plan([]lockfile.Provider{f.lock()}, []Platform{linux}))[0]
	if r.Err == nil || !strings.Contains(r.Err.Error(), "records no hashes") {
		t.Fatalf("err = %v", r.Err)
	}
}

func TestInstallSignatureChecks(t *testing.T) {
	sums := readTestdata(t, "terraform-provider-demo_1.0.0_SHA256SUMS")
	cases := map[string]func(f *fakeRegistry){
		"wrong key": func(f *fakeRegistry) { f.signingKey = string(readTestdata(t, "other-key.asc")) },
		"tampered sums": func(f *fakeRegistry) {
			f.files["terraform-provider-demo_1.0.0_SHA256SUMS"] = []byte(strings.Replace(string(sums), "9831", "9832", 1))
		},
		"bad signature": func(f *fakeRegistry) {
			f.files["terraform-provider-demo_1.0.0_SHA256SUMS.sig"] = []byte("not a signature")
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFakeRegistry(t)
			mutate(f)
			root := t.TempDir()
			items := Plan([]lockfile.Provider{f.lock(zhLinux)}, []Platform{linux})
			r := f.installer(root, Packed).Install(context.Background(), items)[0]
			if r.Err == nil || !strings.Contains(r.Err.Error(), "SHA256SUMS") {
				t.Fatalf("err = %v, want a SHA256SUMS failure", r.Err)
			}
			if _, err := os.Stat(r.Path); !errors.Is(err, os.ErrNotExist) {
				t.Error("a package with a failed signature check was written")
			}
		})
	}

	// With checks off, the lock alone decides.
	f := newFakeRegistry(t)
	f.signingKey = string(readTestdata(t, "other-key.asc"))
	in := f.installer(t.TempDir(), Packed)
	in.VerifySignatures = false
	mustOK(t, in.Install(context.Background(), Plan([]lockfile.Provider{f.lock(zhLinux)}, []Platform{linux})))
}

func TestInstallRefusesRegistryShasumMismatch(t *testing.T) {
	f := newFakeRegistry(t)
	// Serve darwin's bytes under linux's name: the registry's shasum, the
	// lock and SHA256SUMS all disagree with the download.
	f.files["terraform-provider-demo_1.0.0_linux_amd64.zip"] = readTestdata(t, "terraform-provider-demo_1.0.0_darwin_arm64.zip")
	items := Plan([]lockfile.Provider{f.lock(zhLinux, zhDarwin)}, []Platform{linux})
	r := f.installer(t.TempDir(), Packed).Install(context.Background(), items)[0]
	if r.Err == nil || !strings.Contains(r.Err.Error(), "the registry said") {
		t.Fatalf("err = %v", r.Err)
	}
}

func TestInstallRetriesRateLimits(t *testing.T) {
	f := newFakeRegistry(t)
	f.throttle["/v1/providers/example/demo/1.0.0/download/linux/amd64"] = 2
	f.throttle["/files/terraform-provider-demo_1.0.0_linux_amd64.zip"] = 1
	in := f.installer(t.TempDir(), Packed)
	var waits []time.Duration
	var mu sync.Mutex
	in.Client.sleep = func(_ context.Context, d time.Duration) error {
		mu.Lock()
		waits = append(waits, d)
		mu.Unlock()
		return nil
	}
	mustOK(t, in.Install(context.Background(), Plan([]lockfile.Provider{f.lock(zhLinux)}, []Platform{linux})))
	if len(waits) != 3 {
		t.Fatalf("slept %d times, want 3", len(waits))
	}
	for _, w := range waits {
		if w != time.Second {
			t.Errorf("waited %v, want the 1s Retry-After", w)
		}
	}

	// Past the attempt budget, the error says so.
	f.throttle["/v1/providers/example/demo/1.0.0/download/darwin/arm64"] = 100
	in.Client.Attempts = 3
	r := in.Install(context.Background(), Plan([]lockfile.Provider{f.lock(zhDarwin)}, []Platform{darwin}))[0]
	if r.Err == nil || !strings.Contains(r.Err.Error(), "gave up after 3 attempts") {
		t.Fatalf("err = %v", r.Err)
	}
}

func TestInstallUnknownPlatform(t *testing.T) {
	f := newFakeRegistry(t)
	items := Plan([]lockfile.Provider{f.lock(zhLinux)}, []Platform{{"windows", "amd64"}})
	r := f.installer(t.TempDir(), Packed).Install(context.Background(), items)[0]
	if r.Err == nil || !strings.Contains(r.Err.Error(), "no package for this version and platform") {
		t.Fatalf("err = %v", r.Err)
	}
	if n := f.count("/v1/providers/example/demo/1.0.0/download/windows/amd64"); n != 1 {
		t.Errorf("a 404 was retried: %d calls", n)
	}
}

func TestUnzipRejectsEscapes(t *testing.T) {
	for _, name := range []string{"../evil", "/etc/evil", `a\..\..\evil`} {
		t.Run(name, func(t *testing.T) {
			zipPath := filepath.Join(t.TempDir(), "evil.zip")
			writeZip(t, zipPath, map[string]string{name: "x"})
			if err := unzip(zipPath, t.TempDir()); err == nil {
				t.Fatal("unzip accepted an escaping entry")
			}
		})
	}
}

func TestTokenFromEnv(t *testing.T) {
	t.Setenv("TF_TOKEN_app_terraform_io", "a")
	t.Setenv("TF_TOKEN_my__registry_example_com", "b")
	if got := TokenFromEnv("app.terraform.io"); got != "a" {
		t.Errorf("app.terraform.io: %q", got)
	}
	if got := TokenFromEnv("my-registry.example.com"); got != "b" {
		t.Errorf("my-registry.example.com: %q", got)
	}
}

func TestCLIConfig(t *testing.T) {
	f := lockfile.Provider{Addr: lockfile.Addr{Hostname: "registry.terraform.io", Namespace: "hashicorp", Type: "aws"}, Version: "5.0.0"}
	g := lockfile.Provider{Addr: lockfile.Addr{Hostname: "registry.opentofu.org", Namespace: "hashicorp", Type: "random"}, Version: "3.6.0"}
	got := CLIConfig("/opt/mirror", Plan([]lockfile.Provider{g, f}, []Platform{linux, darwin}))
	want := `provider_installation {
  filesystem_mirror {
    path    = "/opt/mirror"
    include = [
      "registry.opentofu.org/hashicorp/random",
      "registry.terraform.io/hashicorp/aws",
    ]
  }
  direct {
    exclude = [
      "registry.opentofu.org/hashicorp/random",
      "registry.terraform.io/hashicorp/aws",
    ]
  }
}
`
	if got != want {
		t.Fatalf("CLIConfig =\n%s\nwant\n%s", got, want)
	}
}

func TestPack(t *testing.T) {
	f := newFakeRegistry(t)
	for _, layout := range []Layout{Packed, Unpacked} {
		t.Run(layout.String(), func(t *testing.T) {
			root := t.TempDir()
			h1 := terraformH1(t)
			items := Plan([]lockfile.Provider{f.lock(zhLinux, zhDarwin, h1[linux], h1[darwin])}, []Platform{linux, darwin})
			mustOK(t, f.installer(root, layout).Install(context.Background(), items))
			// A stale entry from an older build must not travel.
			stale := filepath.Join(root, f.host(), "example", "demo", "stale.txt")
			os.WriteFile(stale, []byte("old"), 0o644)

			out := filepath.Join(t.TempDir(), "mirror.tar.gz")
			sum1, err := Pack(root, layout, items, out)
			if err != nil {
				t.Fatal(err)
			}
			if got, _ := FileSHA256(out); got != sum1 {
				t.Errorf("Pack returned %s, file is %s", sum1, got)
			}
			names := tarNames(t, out)
			for _, n := range names {
				if strings.Contains(n, "stale") {
					t.Errorf("stale file packed: %s", n)
				}
			}
			for _, it := range items {
				rel := layout.RelPath(it)
				found := false
				for _, n := range names {
					found = found || n == rel || strings.HasPrefix(n, rel+"/")
				}
				if !found {
					t.Errorf("%s missing from the tarball: %v", rel, names)
				}
			}
			// Deterministic: packing again gives the same digest.
			if sum2, err := Pack(root, layout, items, out); err != nil || sum2 != sum1 {
				t.Errorf("repacking gave %s (%v), want %s", sum2, err, sum1)
			}

			// A mirror entry edited after the build is refused.
			p := layout.Path(root, items[0])
			if layout == Unpacked {
				p = filepath.Join(p, "LICENSE")
			}
			os.WriteFile(p, []byte("edited"), 0o644)
			if _, err := Pack(root, layout, items, out); err == nil || !strings.Contains(err.Error(), "no longer matches") {
				t.Fatalf("Pack after tampering: err = %v", err)
			}
		})
	}
}

func tarNames(t *testing.T, path string) []string {
	t.Helper()
	fh, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()
	gz, err := gzip.NewReader(fh)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	var names []string
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, strings.TrimSuffix(h.Name, "/"))
	}
	sort.Strings(names)
	return names
}

// assertNoStragglers fails if a temporary download or staging dir was left.
func assertNoStragglers(t *testing.T, root string) {
	t.Helper()
	filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err == nil && strings.HasPrefix(info.Name(), ".") {
			t.Errorf("left behind: %s", p)
		}
		return nil
	})
}

func writeZip(t *testing.T, path string, files map[string]string) {
	t.Helper()
	fh, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(fh)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		io.WriteString(w, body)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	fh.Close()
}
