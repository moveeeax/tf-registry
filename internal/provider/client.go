package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// maxJSON bounds the discovery and download-metadata responses. Real ones are
// a few kilobytes; most of that is the publisher's armored public key.
const maxJSON = 1 << 20

// Client speaks the read side of the provider registry protocol
// (https://developer.hashicorp.com/terraform/internals/provider-registry-protocol):
// service discovery, then one "find a provider package" call per package.
type Client struct {
	HTTP *http.Client

	// Attempts is how many times a request is tried before giving up on a
	// rate limit (429), a 5xx or a network error. Default 5.
	Attempts int
	// Backoff is the first retry delay; each retry doubles it, capped at
	// 30s. A Retry-After header, if present, wins. Default 1s.
	Backoff time.Duration

	// Token returns the bearer token for a registry host, or "". Default:
	// the TF_TOKEN_<host> environment variable, the way Terraform reads it.
	Token func(host string) string

	sleep func(context.Context, time.Duration) error

	mu        sync.Mutex
	discovery map[string]*discovered
}

type discovered struct {
	once sync.Once
	base *url.URL
	err  error
}

// PackageMeta is the "find a provider package" response.
type PackageMeta struct {
	Protocols           []string `json:"protocols"`
	OS                  string   `json:"os"`
	Arch                string   `json:"arch"`
	Filename            string   `json:"filename"`
	DownloadURL         string   `json:"download_url"`
	SHASumsURL          string   `json:"shasums_url"`
	SHASumsSignatureURL string   `json:"shasums_signature_url"`
	SHASum              string   `json:"shasum"`
	SigningKeys         struct {
		GPGPublicKeys []struct {
			KeyID      string `json:"key_id"`
			ASCIIArmor string `json:"ascii_armor"`
		} `json:"gpg_public_keys"`
	} `json:"signing_keys"`

	base *url.URL // the URL the response came from, for relative URLs
}

// Resolve turns one of the response's URLs into an absolute one. The protocol
// allows them to be relative to the URL that returned the response.
func (m *PackageMeta) Resolve(ref string) (string, error) {
	if ref == "" {
		return "", errors.New("empty URL in registry response")
	}
	u, err := m.base.Parse(ref)
	if err != nil {
		return "", fmt.Errorf("bad URL %q in registry response: %w", ref, err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return "", fmt.Errorf("URL %q in registry response is not http(s)", ref)
	}
	return u.String(), nil
}

// TokenFromEnv implements Terraform's TF_TOKEN_<host> lookup: dots in the
// host become underscores and dashes become double underscores.
func TokenFromEnv(host string) string {
	name := strings.NewReplacer(".", "_", "-", "__").Replace(host)
	return os.Getenv("TF_TOKEN_" + name)
}

func (c *Client) attempts() int {
	if c.Attempts > 0 {
		return c.Attempts
	}
	return 5
}

func (c *Client) backoff() time.Duration {
	if c.Backoff > 0 {
		return c.Backoff
	}
	return time.Second
}

func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return http.DefaultClient
}

func (c *Client) token(host string) string {
	if c.Token != nil {
		return c.Token(host)
	}
	return TokenFromEnv(host)
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// providersBase returns the providers.v1 base URL for host, discovering it
// once per host.
func (c *Client) providersBase(ctx context.Context, host string) (*url.URL, error) {
	c.mu.Lock()
	if c.discovery == nil {
		c.discovery = map[string]*discovered{}
	}
	d, ok := c.discovery[host]
	if !ok {
		d = &discovered{}
		c.discovery[host] = d
	}
	c.mu.Unlock()

	d.once.Do(func() {
		wellKnown := &url.URL{Scheme: "https", Host: host, Path: "/.well-known/terraform.json"}
		var doc map[string]any
		if err := c.getJSON(ctx, wellKnown, host, &doc); err != nil {
			d.err = fmt.Errorf("service discovery for %s: %w", host, err)
			return
		}
		raw, ok := doc["providers.v1"].(string)
		if !ok || raw == "" {
			d.err = fmt.Errorf("%s does not offer a provider registry (no providers.v1 in its service discovery)", host)
			return
		}
		base, err := wellKnown.Parse(raw)
		if err != nil {
			d.err = fmt.Errorf("service discovery for %s: bad providers.v1 %q", host, raw)
			return
		}
		if !strings.HasSuffix(base.Path, "/") {
			base.Path += "/"
		}
		d.base = base
	})
	return d.base, d.err
}

// FindPackage asks the registry where to get one provider package.
func (c *Client) FindPackage(ctx context.Context, it Item) (*PackageMeta, error) {
	a := it.Provider.Addr
	base, err := c.providersBase(ctx, a.Hostname)
	if err != nil {
		return nil, err
	}
	rel := &url.URL{Path: strings.Join([]string{
		url.PathEscape(a.Namespace), url.PathEscape(a.Type), url.PathEscape(it.Provider.Version),
		"download", url.PathEscape(it.Platform.OS), url.PathEscape(it.Platform.Arch),
	}, "/")}
	u := base.ResolveReference(rel)
	var meta PackageMeta
	if err := c.getJSON(ctx, u, a.Hostname, &meta); err != nil {
		var se *statusError
		if errors.As(err, &se) && se.code == http.StatusNotFound {
			return nil, fmt.Errorf("%s: the registry has no package for this version and platform", it)
		}
		return nil, fmt.Errorf("%s: %w", it, err)
	}
	meta.base = u
	if meta.OS != "" && meta.OS != it.Platform.OS || meta.Arch != "" && meta.Arch != it.Platform.Arch {
		return nil, fmt.Errorf("%s: registry answered with a package for %s_%s", it, meta.OS, meta.Arch)
	}
	return &meta, nil
}

type statusError struct {
	code int
	url  string
}

func (e *statusError) Error() string {
	return fmt.Sprintf("GET %s: %d %s", e.url, e.code, http.StatusText(e.code))
}

func (c *Client) getJSON(ctx context.Context, u *url.URL, host string, v any) error {
	return c.get(ctx, u.String(), host, func(body io.Reader) error {
		dec := json.NewDecoder(io.LimitReader(body, maxJSON))
		if err := dec.Decode(v); err != nil {
			return fmt.Errorf("GET %s: decode response: %w", u.Redacted(), err)
		}
		return nil
	})
}

// Fetch GETs rawURL with retries and hands the body to consume. The bearer
// token for authHost is sent only when the URL is on that host, so it never
// follows a download link to an object store.
func (c *Client) Fetch(ctx context.Context, rawURL, authHost string, consume func(io.Reader) error) error {
	return c.get(ctx, rawURL, authHost, consume)
}

func (c *Client) get(ctx context.Context, rawURL, authHost string, consume func(io.Reader) error) error {
	sleep := c.sleep
	if sleep == nil {
		sleep = sleepCtx
	}
	for attempt := 1; ; attempt++ {
		wait, err := c.try(ctx, rawURL, authHost, consume)
		switch {
		case err == nil:
			return nil
		case wait < 0:
			return err
		case attempt >= c.attempts():
			if attempt == 1 {
				return err
			}
			return fmt.Errorf("%w (gave up after %d attempts)", err, attempt)
		}
		if wait == 0 {
			wait = min(c.backoff()<<(attempt-1), 30*time.Second)
		}
		if err := sleep(ctx, wait); err != nil {
			return err
		}
	}
}

// try makes one request. wait < 0 means the error is final; wait == 0 means
// retry with the default backoff; wait > 0 is a server-requested delay.
func (c *Client) try(ctx context.Context, rawURL, authHost string, consume func(io.Reader) error) (time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return -1, err
	}
	if req.URL.Host == authHost {
		if tok := c.token(authHost); tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return -1, ctx.Err()
		}
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		err := &statusError{code: resp.StatusCode, url: req.URL.Redacted()}
		if !retryable(resp.StatusCode) {
			return -1, err
		}
		return retryAfter(resp.Header.Get("Retry-After")), err
	}
	if err := consume(resp.Body); err != nil {
		if ctx.Err() != nil {
			return -1, ctx.Err()
		}
		// A body cut off mid-stream is worth another try; a body that
		// arrived whole but is wrong is not, and consume says so by
		// returning a permanentError.
		var pe *permanentError
		if errors.As(err, &pe) {
			return -1, pe.err
		}
		return 0, err
	}
	return 0, nil
}

// permanentError marks a consume failure that a retry would not fix.
type permanentError struct{ err error }

func (e *permanentError) Error() string { return e.err.Error() }
func (e *permanentError) Unwrap() error { return e.err }

func permanent(err error) error { return &permanentError{err: err} }

func retryable(code int) bool {
	switch code {
	case http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusBadGateway,
		http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	}
	return false
}

// retryAfter reads a Retry-After header in its delay-seconds form, capped at a
// minute so a hostile or confused server cannot park the run.
func retryAfter(v string) time.Duration {
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n <= 0 {
		if t, err := http.ParseTime(v); err == nil {
			if d := time.Until(t); d > 0 {
				return min(d, time.Minute)
			}
		}
		return 0
	}
	return min(time.Duration(n)*time.Second, time.Minute)
}
