package provider

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/moveeeax/tf-registry/internal/openpgp"
)

// maxUnpacked bounds what one provider .zip may expand to. The largest
// providers unpack to several hundred megabytes; this is well above that and
// well below what a zip bomb would claim.
const maxUnpacked = 4 << 30

// maxSums bounds a SHA256SUMS file and its signature.
const maxSums = 1 << 20

// Status says what Install did with one item.
type Status string

const (
	Fetched Status = "fetched" // downloaded, verified and written
	Present Status = "present" // already on disk and matching the lock file
	Failed  Status = "failed"
)

// Result is the outcome for one item.
type Result struct {
	Item   Item
	Status Status
	Path   string
	// MatchedBy is the lock-file hash the package matched.
	MatchedBy string
	// Signer is the key ID that signed the release's SHA256SUMS, when
	// signatures were checked.
	Signer string
	// Warning is set when the package is on disk but Terraform may still
	// refuse to use it, e.g. a plugin cache entry with no h1: in the lock.
	Warning string
	Err     error
}

// Installer fetches planned items into Root in the chosen layout.
type Installer struct {
	Client           *Client
	Root             string
	Layout           Layout
	VerifySignatures bool
	Concurrency      int              // default 4
	Now              func() time.Time // for signature expiry; default time.Now

	sums sync.Map // SHA256SUMS URL -> *sumsEntry
}

type sumsEntry struct {
	once   sync.Once
	sums   map[string]string // file name -> hex sha256
	signer string
	err    error
}

// Install processes every item, at most Concurrency at a time. A failure on
// one item does not stop the others: the caller gets every result and decides.
func (in *Installer) Install(ctx context.Context, items []Item) []Result {
	n := in.Concurrency
	if n <= 0 {
		n = 4
	}
	results := make([]Result, len(items))
	sem := make(chan struct{}, n)
	var wg sync.WaitGroup
	for i, it := range items {
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				results[i] = Result{Item: it, Status: Failed, Err: ctx.Err()}
				return
			}
			defer func() { <-sem }()
			results[i] = in.installOne(ctx, it)
		}()
	}
	wg.Wait()
	return results
}

func (in *Installer) installOne(ctx context.Context, it Item) Result {
	res := Result{Item: it, Path: in.Layout.Path(in.Root, it)}
	fail := func(err error) Result {
		res.Status, res.Err = Failed, err
		return res
	}
	locked := newHashSet(it.Provider.Hashes)
	if len(locked) == 0 {
		return fail(fmt.Errorf("%s: the lock file records no hashes for this version, so there is nothing to verify against; "+
			"run `terraform providers lock -platform=%s` and commit the result", it, it.Platform))
	}

	// Incremental: an entry already on disk that matches the lock is kept.
	if match, ok := in.present(res.Path, locked); ok {
		res.Status, res.MatchedBy = Present, match
		return res
	}

	meta, err := in.Client.FindPackage(ctx, it)
	if err != nil {
		return fail(err)
	}
	downloadURL, err := meta.Resolve(meta.DownloadURL)
	if err != nil {
		return fail(fmt.Errorf("%s: %w", it, err))
	}

	dir := filepath.Dir(res.Path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fail(err)
	}
	tmp, err := os.CreateTemp(dir, ".download-*.zip")
	if err != nil {
		return fail(err)
	}
	tmpPath := tmp.Name()
	tmp.Close()
	defer os.Remove(tmpPath)

	var sum string
	err = in.Client.Fetch(ctx, downloadURL, it.Provider.Addr.Hostname, func(body io.Reader) error {
		f, err := os.Create(tmpPath)
		if err != nil {
			return permanent(err)
		}
		h := sha256.New()
		_, err = io.Copy(io.MultiWriter(f, h), body)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		sum = hex.EncodeToString(h.Sum(nil))
		return err
	})
	if err != nil {
		return fail(fmt.Errorf("%s: download: %w", it, err))
	}

	// 1. The registry's own claim about the file.
	if meta.SHASum != "" && !strings.EqualFold(meta.SHASum, sum) {
		return fail(fmt.Errorf("%s: downloaded file has sha256 %s, the registry said %s", it, sum, meta.SHASum))
	}

	// 2. The lock file. This is the check that matters: it pins the exact
	//    bytes `terraform init` accepted when the lock was written.
	h1, err := ZipH1(tmpPath)
	if err != nil {
		return fail(fmt.Errorf("%s: downloaded file is not a readable zip: %w", it, err))
	}
	switch {
	case locked["zh:"+sum]:
		res.MatchedBy = "zh:" + sum
	case locked[h1]:
		res.MatchedBy = h1
	default:
		return fail(fmt.Errorf("%s: package matches no hash in the lock file (zh:%s, %s); "+
			"refusing it. If the platform was never locked, run `terraform providers lock -platform=%s`",
			it, sum, h1, it.Platform))
	}

	// 3. The publisher's signature over SHA256SUMS.
	if in.VerifySignatures {
		signer, err := in.checkSignature(ctx, it, meta, sum)
		if err != nil {
			return fail(err)
		}
		res.Signer = signer
	}

	if err := in.place(tmpPath, res.Path, h1); err != nil {
		return fail(fmt.Errorf("%s: %w", it, err))
	}
	res.Status = Fetched
	res.Warning = in.cacheWarning(it, locked[h1])
	return res
}

// cacheWarning flags an unpacked entry Terraform will not trust. An unpacked
// directory can only be checked against an h1: hash, and `terraform init`
// records h1: only for the platform it ran on (zh: for all of them), so a lock
// written on a Mac has no h1: for linux_amd64 until `terraform providers lock
// -platform=linux_amd64` adds it.
func (in *Installer) cacheWarning(it Item, h1Locked bool) string {
	if in.Layout != Unpacked || h1Locked {
		return ""
	}
	return fmt.Sprintf("the lock file has no h1: hash for %s, so Terraform will not reuse this entry; "+
		"run `terraform providers lock -platform=%s` to record one", it.Platform, it.Platform)
}

// present reports whether path already holds a package matching the lock.
func (in *Installer) present(p string, locked hashSet) (string, bool) {
	if _, err := os.Stat(p); err != nil {
		return "", false
	}
	if in.Layout == Packed {
		sum, err := FileSHA256(p)
		if err == nil && locked["zh:"+sum] {
			return "zh:" + sum, true
		}
		if h1, err := ZipH1(p); err == nil && locked[h1] {
			return h1, true
		}
		return "", false
	}
	if h1, err := DirH1(p); err == nil && locked[h1] {
		return h1, true
	}
	return "", false
}

func (in *Installer) checkSignature(ctx context.Context, it Item, meta *PackageMeta, sum string) (string, error) {
	sumsURL, err := meta.Resolve(meta.SHASumsURL)
	if err != nil {
		return "", fmt.Errorf("%s: %w", it, err)
	}
	sigURL, err := meta.Resolve(meta.SHASumsSignatureURL)
	if err != nil {
		return "", fmt.Errorf("%s: %w", it, err)
	}
	if len(meta.SigningKeys.GPGPublicKeys) == 0 {
		return "", fmt.Errorf("%s: the registry returned no signing keys", it)
	}

	// One SHA256SUMS covers every platform of a release, so it is fetched
	// and verified once per release, not once per platform.
	v, _ := in.sums.LoadOrStore(sumsURL+"\x00"+sigURL, &sumsEntry{})
	e := v.(*sumsEntry)
	e.once.Do(func() { e.sums, e.signer, e.err = in.loadSums(ctx, it, meta, sumsURL, sigURL) })
	if e.err != nil {
		return "", e.err
	}

	if meta.Filename == "" {
		return "", fmt.Errorf("%s: the registry response has no filename to look up in SHA256SUMS", it)
	}
	listed, ok := e.sums[meta.Filename]
	if !ok {
		return "", fmt.Errorf("%s: %s is not listed in the signed SHA256SUMS", it, meta.Filename)
	}
	if !strings.EqualFold(listed, sum) {
		return "", fmt.Errorf("%s: signed SHA256SUMS lists %s for %s, the download has %s", it, listed, meta.Filename, sum)
	}
	return e.signer, nil
}

func (in *Installer) loadSums(ctx context.Context, it Item, meta *PackageMeta, sumsURL, sigURL string) (map[string]string, string, error) {
	kr := &openpgp.KeyRing{}
	for _, k := range meta.SigningKeys.GPGPublicKeys {
		if err := kr.AddArmored([]byte(k.ASCIIArmor)); err != nil {
			return nil, "", fmt.Errorf("%s: signing key %s: %w", it, k.KeyID, err)
		}
	}
	host := it.Provider.Addr.Hostname
	sums, err := in.fetchSmall(ctx, sumsURL, host)
	if err != nil {
		return nil, "", fmt.Errorf("%s: SHA256SUMS: %w", it, err)
	}
	sig, err := in.fetchSmall(ctx, sigURL, host)
	if err != nil {
		return nil, "", fmt.Errorf("%s: SHA256SUMS signature: %w", it, err)
	}
	now := time.Now
	if in.Now != nil {
		now = in.Now
	}
	key, err := kr.Verify(sums, sig, now())
	if err != nil {
		return nil, "", fmt.Errorf("%s: SHA256SUMS signature: %w", it, err)
	}

	out := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(sums))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) != 2 {
			continue
		}
		out[strings.TrimPrefix(fields[1], "*")] = fields[0]
	}
	return out, key.KeyID(), nil
}

func (in *Installer) fetchSmall(ctx context.Context, u, host string) ([]byte, error) {
	var b []byte
	err := in.Client.Fetch(ctx, u, host, func(r io.Reader) error {
		var err error
		b, err = io.ReadAll(io.LimitReader(r, maxSums+1))
		if err == nil && len(b) > maxSums {
			return permanent(errors.New("response is larger than 1 MiB"))
		}
		return err
	})
	return b, err
}

// place moves a verified .zip into its final position. Both layouts are built
// next to the destination and renamed into place, so a reader (or a crash)
// never sees half a package.
func (in *Installer) place(zipPath, dest, wantH1 string) error {
	if in.Layout == Packed {
		// CreateTemp made the file 0600; a shared mirror must be readable.
		if err := os.Chmod(zipPath, 0o644); err != nil {
			return err
		}
		return os.Rename(zipPath, dest)
	}
	staging, err := os.MkdirTemp(filepath.Dir(dest), ".unpack-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(staging)
	if err := os.Chmod(staging, 0o755); err != nil {
		return err
	}
	if err := unzip(zipPath, staging); err != nil {
		return err
	}
	// The unpacked tree must hash to what the archive hashed to, or the
	// unpacking itself changed something.
	got, err := DirH1(staging)
	if err != nil {
		return err
	}
	if got != wantH1 {
		return fmt.Errorf("unpacked package hashes to %s, archive to %s", got, wantH1)
	}
	if err := os.RemoveAll(dest); err != nil {
		return err
	}
	return os.Rename(staging, dest)
}

func unzip(zipPath, dest string) error {
	z, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer z.Close()
	var total int64
	for _, f := range z.File {
		name := f.Name
		if strings.Contains(name, "\\") || path.IsAbs(name) || !filepath.IsLocal(filepath.FromSlash(name)) {
			return fmt.Errorf("zip entry %q escapes the package directory", name)
		}
		target := filepath.Join(dest, filepath.FromSlash(name))
		mode := f.Mode()
		switch {
		case mode.IsDir():
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
			continue
		case !mode.IsRegular():
			return fmt.Errorf("zip entry %q is not a regular file", name)
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		perm := mode.Perm() | 0o600
		if mode.Perm() == 0 {
			perm = 0o644
		}
		r, err := f.Open()
		if err != nil {
			return err
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, perm)
		if err != nil {
			r.Close()
			return err
		}
		n, err := io.Copy(out, io.LimitReader(r, maxUnpacked-total+1))
		r.Close()
		if cerr := out.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return err
		}
		total += n
		if total > maxUnpacked {
			return errors.New("package unpacks to more than 4 GiB")
		}
	}
	return nil
}
