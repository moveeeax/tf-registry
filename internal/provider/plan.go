// Package provider fetches the provider packages pinned by Terraform lock
// files, verifies them against those lock files, and lays them out on disk in
// the two directory shapes Terraform reads providers from: a plugin cache
// (plugin_cache_dir) and a filesystem mirror (provider_installation's
// filesystem_mirror).
//
// The lock file is the trust anchor. A package is written only when its zh:
// or h1: hash is one the lock file already records, so nothing newer than the
// pins and nothing different from what `terraform init` locked can land on
// disk. The registry's signed SHA256SUMS is checked as well, unless disabled,
// so a tampered lock file is not the only thing standing in the way.
package provider

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/moveeeax/tf-registry/internal/lockfile"
)

// Platform is a target operating system and architecture, e.g. linux_amd64.
type Platform struct {
	OS, Arch string
}

func (p Platform) String() string { return p.OS + "_" + p.Arch }

var platformRE = regexp.MustCompile(`^([a-z0-9]+)_([a-z0-9]+)$`)

// ParsePlatform parses the os_arch form Terraform uses on the command line.
func ParsePlatform(s string) (Platform, error) {
	m := platformRE.FindStringSubmatch(s)
	if m == nil {
		return Platform{}, fmt.Errorf("platform %q is not in os_arch form, e.g. linux_amd64", s)
	}
	return Platform{OS: m[1], Arch: m[2]}, nil
}

// Item is one package to fetch: a locked provider version for one platform.
type Item struct {
	Provider lockfile.Provider
	Platform Platform
}

func (it Item) String() string {
	return it.Provider.Addr.String() + " " + it.Provider.Version + " " + it.Platform.String()
}

// Plan crosses the merged lock selections with the requested platforms. The
// result is sorted, so output and cache keys do not depend on map order or on
// the order lock files were given in.
func Plan(providers []lockfile.Provider, platforms []Platform) []Item {
	ps := append([]Platform(nil), platforms...)
	sort.Slice(ps, func(i, j int) bool { return ps[i].String() < ps[j].String() })
	var items []Item
	for _, p := range providers {
		seen := map[Platform]bool{}
		for _, pl := range ps {
			if seen[pl] {
				continue
			}
			seen[pl] = true
			items = append(items, Item{Provider: p, Platform: pl})
		}
	}
	sort.SliceStable(items, func(i, j int) bool { return items[i].String() < items[j].String() })
	return items
}

// CacheKey is a content address for a plan: the SHA-256 over every planned
// provider, version, platform and locked hash, plus the layout. It is computed
// from the lock files alone, with no network, so CI can derive it before
// deciding whether to restore a cache or warm one. Any change to a pin or to
// the platform list changes the key.
func CacheKey(items []Item, layout Layout) string {
	h := sha256.New()
	fmt.Fprintf(h, "tf-registry provider plan v1 %s\n", layout)
	for _, it := range items {
		fmt.Fprintf(h, "%s %s\n", it, strings.Join(it.Provider.Hashes, ","))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Layout is a directory shape Terraform can read provider packages from.
type Layout int

const (
	// Unpacked is HOST/NAMESPACE/TYPE/VERSION/OS_ARCH/<package files>. It is
	// the only layout plugin_cache_dir uses, and one of the two a
	// filesystem_mirror accepts.
	Unpacked Layout = iota
	// Packed is HOST/NAMESPACE/TYPE/terraform-provider-TYPE_VERSION_OS_ARCH.zip,
	// the other filesystem_mirror layout. Keeping the release .zip intact
	// keeps its zh: hash checkable.
	Packed
)

func (l Layout) String() string {
	if l == Packed {
		return "packed"
	}
	return "unpacked"
}

// ParseLayout parses "packed" or "unpacked".
func ParseLayout(s string) (Layout, error) {
	switch s {
	case "packed":
		return Packed, nil
	case "unpacked":
		return Unpacked, nil
	}
	return 0, fmt.Errorf("layout %q is neither packed nor unpacked", s)
}

// RelPath is where an item lives under the root directory, in slash form.
func (l Layout) RelPath(it Item) string {
	a := it.Provider.Addr
	if l == Packed {
		return a.Hostname + "/" + a.Namespace + "/" + a.Type + "/" +
			fmt.Sprintf("terraform-provider-%s_%s_%s.zip", a.Type, it.Provider.Version, it.Platform)
	}
	return a.Hostname + "/" + a.Namespace + "/" + a.Type + "/" + it.Provider.Version + "/" + it.Platform.String()
}

// Path is RelPath joined to root.
func (l Layout) Path(root string, it Item) string {
	return filepath.Join(root, filepath.FromSlash(l.RelPath(it)))
}
