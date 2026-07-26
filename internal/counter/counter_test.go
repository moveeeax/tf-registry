package counter

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestIncPersistsAndReloads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "counts.json")

	c, err := New(path)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	key := Key("acme", "vpc", "aws", "1.10.0")
	for i := 0; i < 3; i++ {
		if err := c.Inc(key); err != nil {
			t.Fatalf("Inc: %v", err)
		}
	}
	if err := c.Inc(Key("acme", "aks", "azurerm", "0.3.1")); err != nil {
		t.Fatal(err)
	}

	// A fresh process must see the same numbers.
	reloaded, err := New(path)
	if err != nil {
		t.Fatalf("New on existing file: %v", err)
	}
	if got := reloaded.Total(key); got != 3 {
		t.Errorf("Total after reload = %d, want 3", got)
	}
	if got := reloaded.Total(Key("acme", "aks", "azurerm", "0.3.1")); got != 1 {
		t.Errorf("Total for the second module = %d, want 1", got)
	}
	if got := reloaded.Total("acme/nope/aws/1.0.0"); got != 0 {
		t.Errorf("Total for an unknown key = %d, want 0", got)
	}

	// The on-disk shape stays a plain key -> count object.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]int64
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("counts file is not a flat JSON object: %v", err)
	}
	if decoded[key] != 3 {
		t.Errorf("counts file has %d for %s, want 3", decoded[key], key)
	}

	// No temp files left behind by the atomic write.
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("directory contains %d files, want just counts.json", len(entries))
	}
}

func TestReportOrdering(t *testing.T) {
	c, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	inc := func(key string, n int) {
		for i := 0; i < n; i++ {
			if err := c.Inc(key); err != nil {
				t.Fatal(err)
			}
		}
	}
	inc("acme/vpc/aws/1.10.0", 5)
	inc("acme/aks/azurerm/0.3.1", 5)
	inc("globex/object-store/oci/1.0.0", 9)

	report := c.Report()
	want := []Entry{
		{"globex/object-store/oci/1.0.0", 9},
		{"acme/aks/azurerm/0.3.1", 5}, // tie broken by key
		{"acme/vpc/aws/1.10.0", 5},
	}
	if len(report) != len(want) {
		t.Fatalf("Report() = %v, want %v", report, want)
	}
	for i := range want {
		if report[i] != want[i] {
			t.Errorf("Report()[%d] = %v, want %v", i, report[i], want[i])
		}
	}
}

func TestConcurrentInc(t *testing.T) {
	path := filepath.Join(t.TempDir(), "counts.json")
	c, err := New(path)
	if err != nil {
		t.Fatal(err)
	}

	const goroutines, each = 8, 25
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < each; i++ {
				if err := c.Inc("acme/vpc/aws/1.10.0"); err != nil {
					t.Errorf("Inc: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()

	if got, want := c.Total("acme/vpc/aws/1.10.0"), int64(goroutines*each); got != want {
		t.Errorf("Total = %d, want %d", got, want)
	}
}

func TestNewRejectsCorruptFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "counts.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := New(path); err == nil {
		t.Error("New on a corrupt counts file: want error")
	}
}
