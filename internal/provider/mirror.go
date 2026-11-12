package provider

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// CLIConfig renders the provider_installation block that points Terraform at a
// filesystem mirror for exactly the planned providers. Everything else is left
// to direct installation, so on an air-gapped runner a provider the mirror
// lacks fails at init with its name, instead of the mirror being consulted for
// something it was never built to hold.
func CLIConfig(mirrorPath string, items []Item) string {
	seen := map[string]bool{}
	var addrs []string
	for _, it := range items {
		a := it.Provider.Addr.String()
		if !seen[a] {
			seen[a] = true
			addrs = append(addrs, a)
		}
	}
	sort.Strings(addrs)

	var b strings.Builder
	list := func(indent string) {
		for _, a := range addrs {
			fmt.Fprintf(&b, "%s  %s,\n", indent, strconv.Quote(a))
		}
	}
	b.WriteString("provider_installation {\n")
	b.WriteString("  filesystem_mirror {\n")
	fmt.Fprintf(&b, "    path    = %s\n", strconv.Quote(mirrorPath))
	b.WriteString("    include = [\n")
	list("    ")
	b.WriteString("    ]\n  }\n")
	b.WriteString("  direct {\n")
	b.WriteString("    exclude = [\n")
	list("    ")
	b.WriteString("    ]\n  }\n}\n")
	return b.String()
}

// Pack writes the planned entries under root into a gzipped tarball at out
// and returns the tarball's hex SHA-256. Only planned entries go in, so stale
// versions left in the mirror by an earlier build stay behind, and each one is
// re-checked against the lock file on the way in: a file edited on disk after
// the build does not make it across the air gap.
func Pack(root string, layout Layout, items []Item, out string) (string, error) {
	for _, it := range items {
		p := layout.Path(root, it)
		if _, err := os.Stat(p); err != nil {
			return "", fmt.Errorf("pack: %s: %w", it, err)
		}
		if !matchesLock(p, layout, newHashSet(it.Provider.Hashes)) {
			return "", fmt.Errorf("pack: %s: %s no longer matches the lock file", it, p)
		}
	}

	f, err := os.CreateTemp(filepath.Dir(out), ".pack-*.tar.gz")
	if err != nil {
		return "", err
	}
	tmp := f.Name()
	defer os.Remove(tmp)

	h := sha256.New()
	gz := gzip.NewWriter(io.MultiWriter(f, h))
	tw := tar.NewWriter(gz)
	dirs := map[string]bool{}
	addDir := func(rel string) error {
		for _, d := range parents(rel) {
			if dirs[d] {
				continue
			}
			dirs[d] = true
			if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeDir, Name: d + "/", Mode: 0o755}); err != nil {
				return err
			}
		}
		return nil
	}
	addFile := func(abs, rel string) error {
		if err := addDir(rel); err != nil {
			return err
		}
		info, err := os.Stat(abs)
		if err != nil {
			return err
		}
		hdr := &tar.Header{Typeflag: tar.TypeReg, Name: rel, Mode: int64(info.Mode().Perm()), Size: info.Size()}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		src, err := os.Open(abs)
		if err != nil {
			return err
		}
		defer src.Close()
		_, err = io.Copy(tw, src)
		return err
	}

	// Deterministic content: entries in plan order, no timestamps or owners,
	// so the same mirror packs to the same digest twice.
	for _, it := range items {
		rel := layout.RelPath(it)
		abs := layout.Path(root, it)
		if layout == Packed {
			err = addFile(abs, rel)
		} else {
			err = walkFiles(abs, func(file string) error {
				r, err := filepath.Rel(abs, file)
				if err != nil {
					return err
				}
				return addFile(file, rel+"/"+filepath.ToSlash(r))
			})
		}
		if err != nil {
			f.Close()
			return "", fmt.Errorf("pack: %s: %w", it, err)
		}
	}
	if err := tw.Close(); err != nil {
		f.Close()
		return "", err
	}
	if err := gz.Close(); err != nil {
		f.Close()
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	if err := os.Chmod(tmp, 0o644); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, out); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// parents returns every proper parent directory of a slash path, outermost
// first: "a/b/c" gives "a", "a/b".
func parents(rel string) []string {
	parts := strings.Split(rel, "/")
	var out []string
	for i := 1; i < len(parts); i++ {
		out = append(out, strings.Join(parts[:i], "/"))
	}
	return out
}

func walkFiles(root string, fn func(string) error) error {
	var files []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			files = append(files, p)
		}
		return nil
	})
	if err != nil {
		return err
	}
	sort.Strings(files)
	for _, f := range files {
		if err := fn(f); err != nil {
			return err
		}
	}
	return nil
}

// matchesLock reports whether the entry at p carries a locked hash: zh: or h1:
// for a packed .zip, h1: for an unpacked directory.
func matchesLock(p string, layout Layout, locked hashSet) bool {
	if layout == Packed {
		if sum, err := FileSHA256(p); err == nil && locked["zh:"+sum] {
			return true
		}
		h1, err := ZipH1(p)
		return err == nil && locked[h1]
	}
	h1, err := DirH1(p)
	return err == nil && locked[h1]
}
