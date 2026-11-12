package provider

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// The two hash schemes a lock file records (Terraform's internal/getproviders
// package, hash.go):
//
//	zh:<hex>  SHA-256 of the release .zip, as listed in the SHA256SUMS file.
//	h1:<b64>  the Go modules "dirhash" Hash1 of the unpacked package: for each
//	          regular file in lexical order, a line "<sha256 hex>  <slash path>\n",
//	          then base64 of the SHA-256 of all those lines.
//
// zh: only works against the archive; h1: works against the archive (by
// hashing its file entries) and against an unpacked directory, which is why
// Terraform needs an h1: hash before it will reuse a plugin cache entry.

// FileSHA256 returns the hex SHA-256 of a file.
func FileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ZipH1 computes the h1: hash of a provider .zip without unpacking it.
// Directory entries are skipped: unpacking produces no file for them, and h1:
// is defined over the unpacked files.
func ZipH1(path string) (string, error) {
	z, err := zip.OpenReader(path)
	if err != nil {
		return "", err
	}
	defer z.Close()
	files := map[string]*zip.File{}
	var names []string
	for _, f := range z.File {
		if strings.HasSuffix(f.Name, "/") {
			continue
		}
		if _, dup := files[f.Name]; dup {
			return "", fmt.Errorf("zip lists %q twice", f.Name)
		}
		files[f.Name] = f
		names = append(names, f.Name)
	}
	return hash1(names, func(name string) (io.ReadCloser, error) { return files[name].Open() })
}

// DirH1 computes the h1: hash of an unpacked provider directory. Symlinks are
// followed for the root only, as Terraform does.
func DirH1(dir string) (string, error) {
	root, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return "", err
	}
	var names []string
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		names = append(names, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		return "", err
	}
	return hash1(names, func(name string) (io.ReadCloser, error) {
		return os.Open(filepath.Join(root, filepath.FromSlash(name)))
	})
}

func hash1(names []string, open func(string) (io.ReadCloser, error)) (string, error) {
	sort.Strings(names)
	summary := sha256.New()
	for _, name := range names {
		if strings.Contains(name, "\n") {
			return "", errors.New("file names with newlines cannot be hashed")
		}
		r, err := open(name)
		if err != nil {
			return "", err
		}
		h := sha256.New()
		_, err = io.Copy(h, r)
		r.Close()
		if err != nil {
			return "", err
		}
		fmt.Fprintf(summary, "%x  %s\n", h.Sum(nil), name)
	}
	return "h1:" + base64.StdEncoding.EncodeToString(summary.Sum(nil)), nil
}

// hashSet answers "is this hash locked" for one provider version.
type hashSet map[string]bool

func newHashSet(hashes []string) hashSet {
	s := hashSet{}
	for _, h := range hashes {
		s[h] = true
	}
	return s
}
