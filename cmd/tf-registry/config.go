package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/moveeeax/tf-registry/internal/auth"
)

// Config is the server's on-disk configuration. It holds no secrets: tokens
// appear only as SHA-256 digests, and the download-link signing key comes from
// the environment. That is deliberate — this file is meant to be committable.
type Config struct {
	Listen            string     `json:"listen"`
	BaseURL           string     `json:"base_url"`
	CatalogDir        string     `json:"catalog_dir"`
	PublicKeyFile     string     `json:"public_key_file"`
	RequireSignatures bool       `json:"require_signatures"`
	DownloadURLTTL    string     `json:"download_url_ttl"`
	CountsFile        string     `json:"counts_file"`
	TLSCertFile       string     `json:"tls_cert_file"`
	TLSKeyFile        string     `json:"tls_key_file"`
	Orgs              []auth.Org `json:"orgs"`

	ttl time.Duration
	dir string // directory the config was loaded from
}

// LoadConfig reads and validates a config file. Relative paths inside it are
// resolved against the config file's own directory, so a checked-in config
// works regardless of the process working directory.
func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}

	var c Config
	dec := json.NewDecoder(bytes.NewReader(b))
	// A typo in a key is a silent misconfiguration otherwise, and the failure
	// mode ("why is nobody authorised?") is expensive to debug at 23:00.
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("config: %s: %w", path, err)
	}

	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	c.dir = filepath.Dir(abs)

	if c.Listen == "" {
		c.Listen = "127.0.0.1:8080"
	}
	if c.DownloadURLTTL == "" {
		c.DownloadURLTTL = "5m"
	}
	c.ttl, err = time.ParseDuration(c.DownloadURLTTL)
	if err != nil {
		return nil, fmt.Errorf("config: download_url_ttl: %w", err)
	}
	switch {
	case c.ttl <= 0:
		return nil, fmt.Errorf("config: download_url_ttl must be positive, got %s", c.DownloadURLTTL)
	case c.BaseURL == "":
		return nil, fmt.Errorf("config: base_url is required; Terraform follows it verbatim")
	case c.CatalogDir == "":
		return nil, fmt.Errorf("config: catalog_dir is required")
	case c.RequireSignatures && c.PublicKeyFile == "":
		return nil, fmt.Errorf("config: require_signatures is set but public_key_file is empty")
	case len(c.Orgs) == 0:
		return nil, fmt.Errorf("config: at least one org is required, or nothing can be read")
	case (c.TLSCertFile == "") != (c.TLSKeyFile == ""):
		return nil, fmt.Errorf("config: tls_cert_file and tls_key_file must be set together")
	}
	return &c, nil
}

// Path resolves p relative to the config file's directory.
func (c *Config) Path(p string) string {
	if p == "" || filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(c.dir, p)
}

// TTL is the parsed download_url_ttl.
func (c *Config) TTL() time.Duration { return c.ttl }
