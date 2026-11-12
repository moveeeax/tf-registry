package lockfile

import (
	"reflect"
	"strings"
	"testing"
)

// sample is the shape `terraform init` writes, comments included.
const sample = `# This file is maintained automatically by "terraform init".
# Manual edits may be lost in future updates.

provider "registry.terraform.io/hashicorp/aws" {
  version     = "5.31.0"
  constraints = "~> 5.0"
  hashes = [
    "h1:aaaa=",
    "zh:0000000000000000000000000000000000000000000000000000000000000001",
    "zh:0000000000000000000000000000000000000000000000000000000000000002",
  ]
}

provider "registry.opentofu.org/Hashicorp/Random" {
  version = "3.6.0"
  // no constraints: a provider pulled in only by a child module
  hashes = ["zh:0000000000000000000000000000000000000000000000000000000000000003", "x9:future-scheme"]
}
`

func TestParse(t *testing.T) {
	ps, err := Parse([]byte(sample))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	want := []Provider{
		{
			Addr:        Addr{"registry.terraform.io", "hashicorp", "aws"},
			Version:     "5.31.0",
			Constraints: "~> 5.0",
			Hashes: []string{
				"h1:aaaa=",
				"zh:0000000000000000000000000000000000000000000000000000000000000001",
				"zh:0000000000000000000000000000000000000000000000000000000000000002",
			},
		},
		{
			Addr:    Addr{"registry.opentofu.org", "hashicorp", "random"},
			Version: "3.6.0",
			Hashes:  []string{"zh:0000000000000000000000000000000000000000000000000000000000000003"},
		},
	}
	if !reflect.DeepEqual(ps, want) {
		t.Fatalf("Parse =\n%#v\nwant\n%#v", ps, want)
	}
}

func TestParseRejects(t *testing.T) {
	cases := map[string]string{
		"no version":        `provider "registry.terraform.io/a/b" { hashes = [] }`,
		"short address":     `provider "hashicorp/aws" { version = "1.0.0" }`,
		"bad version":       `provider "registry.terraform.io/a/b" { version = "~> 1.0" }`,
		"duplicate":         "provider \"registry.terraform.io/a/b\" {\n version = \"1.0.0\"\n}\nprovider \"registry.terraform.io/a/b\" {\n version = \"1.0.1\"\n}\n",
		"duplicate attr":    "provider \"registry.terraform.io/a/b\" {\n version = \"1.0.0\"\n version = \"1.0.1\"\n}\n",
		"two attrs on line": `provider "registry.terraform.io/a/b" { version = "1.0.0" constraints = "1" }`,
		"template":          `provider "registry.terraform.io/a/b" { version = "${var.v}" }`,
		"expression":        `provider "registry.terraform.io/a/b" { version = 1 }`,
		"unterminated":      `provider "registry.terraform.io/a/b" { version = "1.0.0`,
		"no close":          `provider "registry.terraform.io/a/b" { version = "1.0.0"`,
		"hashes not list":   `provider "registry.terraform.io/a/b" { version = "1.0.0"` + "\n" + `hashes = "zh:00" }`,
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(src)); err == nil {
				t.Errorf("Parse accepted %q", src)
			}
		})
	}
}

func TestParseErrorNamesLine(t *testing.T) {
	_, err := Parse([]byte("\n\nprovider \"registry.terraform.io/a/b\" {\n  version = 1\n}\n"))
	if err == nil || !strings.Contains(err.Error(), "line 4") {
		t.Fatalf("error = %v, want it to name line 4", err)
	}
}

func TestMerge(t *testing.T) {
	aws := Addr{"registry.terraform.io", "hashicorp", "aws"}
	rnd := Addr{"registry.terraform.io", "hashicorp", "random"}
	a := []Provider{
		{Addr: aws, Version: "5.31.0", Hashes: []string{"zh:01", "h1:a"}},
		{Addr: rnd, Version: "3.6.0", Hashes: []string{"zh:03"}},
	}
	b := []Provider{
		{Addr: aws, Version: "5.31.0", Constraints: "~> 5.0", Hashes: []string{"h1:b", "zh:01"}},
		{Addr: aws, Version: "5.20.0", Hashes: []string{"zh:02"}},
	}
	got := Merge(a, b)
	want := []Provider{
		{Addr: aws, Version: "5.20.0", Hashes: []string{"zh:02"}},
		{Addr: aws, Version: "5.31.0", Constraints: "~> 5.0", Hashes: []string{"h1:a", "h1:b", "zh:01"}},
		{Addr: rnd, Version: "3.6.0", Hashes: []string{"zh:03"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Merge =\n%#v\nwant\n%#v", got, want)
	}
	// The inputs must not be modified by the merge.
	if !reflect.DeepEqual(a[0].Hashes, []string{"zh:01", "h1:a"}) {
		t.Errorf("Merge mutated its input: %v", a[0].Hashes)
	}
}
