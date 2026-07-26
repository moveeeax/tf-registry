// Package semver implements just enough of semver 2.0.0 to order the module
// versions a Terraform registry has to advertise.
//
// The registry protocol hands Terraform a flat list of version strings and
// Terraform does its own constraint solving, so all this package needs to get
// right is parsing and ordering. It deliberately does not implement constraint
// expressions ("~> 1.2").
package semver

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Version is a parsed semantic version. Build metadata is retained for display
// but, per the spec, ignored when comparing.
type Version struct {
	Major, Minor, Patch int
	Pre                 string
	Build               string
}

// Parse parses a semantic version. A single leading "v" is tolerated because
// module tags usually carry one; the parsed version never does.
func Parse(s string) (Version, error) {
	var v Version
	raw := strings.TrimPrefix(s, "v")
	if raw == "" {
		return v, fmt.Errorf("semver: empty version")
	}

	if i := strings.IndexByte(raw, '+'); i >= 0 {
		v.Build = raw[i+1:]
		raw = raw[:i]
		if v.Build == "" || !validDotted(v.Build, true) {
			return Version{}, fmt.Errorf("semver: invalid build metadata in %q", s)
		}
	}
	if i := strings.IndexByte(raw, '-'); i >= 0 {
		v.Pre = raw[i+1:]
		raw = raw[:i]
		if v.Pre == "" || !validDotted(v.Pre, false) {
			return Version{}, fmt.Errorf("semver: invalid pre-release in %q", s)
		}
	}

	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return Version{}, fmt.Errorf("semver: %q is not major.minor.patch", s)
	}
	nums := make([]int, 3)
	for i, p := range parts {
		if p == "" || (len(p) > 1 && p[0] == '0') || !allDigits(p) {
			return Version{}, fmt.Errorf("semver: invalid numeric component %q in %q", p, s)
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return Version{}, fmt.Errorf("semver: invalid numeric component %q in %q", p, s)
		}
		nums[i] = n
	}
	v.Major, v.Minor, v.Patch = nums[0], nums[1], nums[2]
	return v, nil
}

// String renders the version in canonical form, without a leading "v".
func (v Version) String() string {
	s := fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
	if v.Pre != "" {
		s += "-" + v.Pre
	}
	if v.Build != "" {
		s += "+" + v.Build
	}
	return s
}

// Compare returns -1, 0 or 1 as v sorts before, equal to, or after o.
func (v Version) Compare(o Version) int {
	for _, pair := range [3][2]int{
		{v.Major, o.Major}, {v.Minor, o.Minor}, {v.Patch, o.Patch},
	} {
		if c := cmpInt(pair[0], pair[1]); c != 0 {
			return c
		}
	}
	return comparePre(v.Pre, o.Pre)
}

// Sort orders versions ascending, so the last element is the highest precedence.
func Sort(vs []Version) {
	sort.Slice(vs, func(i, j int) bool { return vs[i].Compare(vs[j]) < 0 })
}

func comparePre(a, b string) int {
	// A version without a pre-release outranks one with it.
	switch {
	case a == "" && b == "":
		return 0
	case a == "":
		return 1
	case b == "":
		return -1
	}
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) && i < len(bs); i++ {
		if c := compareIdent(as[i], bs[i]); c != 0 {
			return c
		}
	}
	return cmpInt(len(as), len(bs))
}

func compareIdent(a, b string) int {
	an, bn := allDigits(a), allDigits(b)
	switch {
	case an && bn:
		ai, _ := strconv.Atoi(a)
		bi, _ := strconv.Atoi(b)
		return cmpInt(ai, bi)
	case an:
		return -1 // numeric identifiers rank below alphanumeric ones
	case bn:
		return 1
	default:
		return strings.Compare(a, b)
	}
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// validDotted checks dot-separated identifiers. Pre-release identifiers may not
// have leading zeroes when numeric; build identifiers may.
func validDotted(s string, isBuild bool) bool {
	for _, id := range strings.Split(s, ".") {
		if id == "" {
			return false
		}
		for i := 0; i < len(id); i++ {
			c := id[i]
			ok := c == '-' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
			if !ok {
				return false
			}
		}
		if !isBuild && allDigits(id) && len(id) > 1 && id[0] == '0' {
			return false
		}
	}
	return true
}
