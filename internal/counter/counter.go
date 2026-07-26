// Package counter tracks download counts per module version.
//
// The v1 requirement is one number per module and version on one page, so this
// is a mutex-guarded map persisted as JSON, not a metrics pipeline. Writes are
// atomic (temp file + rename) so a crash mid-write cannot leave a truncated
// file that fails to load on the next boot.
package counter

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

// Counter is safe for concurrent use.
type Counter struct {
	mu     sync.Mutex
	path   string
	counts map[string]int64
}

// Entry is one line of the report.
type Entry struct {
	Key       string `json:"key"`
	Downloads int64  `json:"downloads"`
}

// New loads counts from path. A missing file is not an error: the first
// download creates it. Pass an empty path to keep counts in memory only.
func New(path string) (*Counter, error) {
	c := &Counter{path: path, counts: map[string]int64{}}
	if path == "" {
		return c, nil
	}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return c, nil
	}
	if err != nil {
		return nil, fmt.Errorf("counter: read %s: %w", path, err)
	}
	if err := json.Unmarshal(b, &c.counts); err != nil {
		return nil, fmt.Errorf("counter: parse %s: %w", path, err)
	}
	if c.counts == nil {
		c.counts = map[string]int64{}
	}
	return c, nil
}

// Key builds the canonical counter key for a module version.
func Key(namespace, name, system, version string) string {
	return fmt.Sprintf("%s/%s/%s/%s", namespace, name, system, version)
}

// Inc records one download and persists immediately. Download volume on a
// private registry is small enough that a write per download is cheaper than
// the class of bug a background flush introduces.
func (c *Counter) Inc(key string) error {
	c.mu.Lock()
	c.counts[key]++
	snapshot := c.clone()
	path := c.path
	c.mu.Unlock()

	if path == "" {
		return nil
	}
	return writeAtomic(path, snapshot)
}

// Total returns the count for one key.
func (c *Counter) Total(key string) int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.counts[key]
}

// Report returns every non-zero entry, most downloaded first, ties broken by
// key so the output is stable.
func (c *Counter) Report() []Entry {
	c.mu.Lock()
	defer c.mu.Unlock()

	out := make([]Entry, 0, len(c.counts))
	for k, v := range c.counts {
		out = append(out, Entry{Key: k, Downloads: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Downloads != out[j].Downloads {
			return out[i].Downloads > out[j].Downloads
		}
		return out[i].Key < out[j].Key
	})
	return out
}

func (c *Counter) clone() map[string]int64 {
	out := make(map[string]int64, len(c.counts))
	for k, v := range c.counts {
		out[k] = v
	}
	return out
}

func writeAtomic(path string, counts map[string]int64) error {
	b, err := json.MarshalIndent(counts, "", "  ")
	if err != nil {
		return fmt.Errorf("counter: encode: %w", err)
	}
	b = append(b, '\n')

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("counter: create %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".counts-*.json")
	if err != nil {
		return fmt.Errorf("counter: temp file: %w", err)
	}
	defer os.Remove(tmp.Name())

	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return fmt.Errorf("counter: write: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("counter: close: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("counter: rename into place: %w", err)
	}
	return nil
}
