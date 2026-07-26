package semver

import "testing"

func TestParseValid(t *testing.T) {
	cases := map[string]string{
		"1.2.3":            "1.2.3",
		"v1.2.3":           "1.2.3",
		"0.0.1":            "0.0.1",
		"2.0.0-rc.1":       "2.0.0-rc.1",
		"1.0.0-alpha.beta": "1.0.0-alpha.beta",
		"1.0.0+build.5":    "1.0.0+build.5",
		"1.0.0-rc.1+b.007": "1.0.0-rc.1+b.007",
		"10.20.30":         "10.20.30",
	}
	for in, want := range cases {
		v, err := Parse(in)
		if err != nil {
			t.Errorf("Parse(%q) returned error: %v", in, err)
			continue
		}
		if got := v.String(); got != want {
			t.Errorf("Parse(%q).String() = %q, want %q", in, got, want)
		}
	}
}

func TestParseInvalid(t *testing.T) {
	for _, in := range []string{
		"", "v", "1", "1.2", "1.2.3.4", "01.2.3", "1.2.3-", "1.2.3+",
		"1.2.3-01", "a.b.c", "1.2.x", "1.2.3-rc..1", "-1.2.3", "1.2.3 ",
	} {
		if v, err := Parse(in); err == nil {
			t.Errorf("Parse(%q) = %v, want error", in, v)
		}
	}
}

func TestCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0.0", "1.0.0", 0},
		{"1.0.0", "2.0.0", -1},
		{"2.0.0", "1.0.0", 1},
		{"1.9.0", "1.10.0", -1}, // the classic lexical-sort trap
		{"1.0.9", "1.0.10", -1},
		{"1.0.0-rc.1", "1.0.0", -1},
		{"1.0.0", "1.0.0-rc.1", 1},
		{"1.0.0-alpha", "1.0.0-beta", -1},
		{"1.0.0-alpha.1", "1.0.0-alpha.2", -1},
		{"1.0.0-alpha.9", "1.0.0-alpha.10", -1},
		{"1.0.0-1", "1.0.0-alpha", -1}, // numeric identifiers rank lower
		{"1.0.0-alpha", "1.0.0-alpha.1", -1},
		{"1.0.0+a", "1.0.0+b", 0}, // build metadata is ignored
	}
	for _, c := range cases {
		a, err := Parse(c.a)
		if err != nil {
			t.Fatalf("Parse(%q): %v", c.a, err)
		}
		b, err := Parse(c.b)
		if err != nil {
			t.Fatalf("Parse(%q): %v", c.b, err)
		}
		if got := a.Compare(b); got != c.want {
			t.Errorf("Compare(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestSort(t *testing.T) {
	in := []string{"1.10.0", "2.0.0-rc.1", "1.2.0", "2.0.0", "0.3.1", "1.2.0-rc.2"}
	vs := make([]Version, 0, len(in))
	for _, s := range in {
		v, err := Parse(s)
		if err != nil {
			t.Fatalf("Parse(%q): %v", s, err)
		}
		vs = append(vs, v)
	}
	Sort(vs)

	want := []string{"0.3.1", "1.2.0-rc.2", "1.2.0", "1.10.0", "2.0.0-rc.1", "2.0.0"}
	for i, w := range want {
		if got := vs[i].String(); got != w {
			t.Errorf("sorted[%d] = %q, want %q (full: %v)", i, got, w, vs)
		}
	}
}
