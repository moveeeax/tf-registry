package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/moveeeax/tf-registry/internal/lockfile"
	"github.com/moveeeax/tf-registry/internal/provider"
)

// providerHTTP is the client used to talk to provider registries. Tests swap
// it for one that trusts their TLS test server.
var providerHTTP = &http.Client{
	Transport: &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout:   30 * time.Second,
		ResponseHeaderTimeout: time.Minute,
		MaxIdleConnsPerHost:   8,
	},
}

// listFlag collects a repeatable string flag.
type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }

// providerFlags are the flags cache-warm and mirror share.
type providerFlags struct {
	locks       listFlag
	platforms   listFlag
	concurrency int
	verifySigs  bool
}

func (pf *providerFlags) register(fs *flag.FlagSet) {
	fs.Var(&pf.locks, "lock", "lock file path or glob, e.g. 'envs/*/.terraform.lock.hcl' (repeatable)")
	fs.Var(&pf.platforms, "platform", "target platform as os_arch (repeatable; default "+runtime.GOOS+"_"+runtime.GOARCH+")")
	fs.IntVar(&pf.concurrency, "concurrency", 4, "packages fetched in parallel")
	fs.BoolVar(&pf.verifySigs, "verify-signatures", true, "also verify the publisher's GPG signature over SHA256SUMS")
}

// plan reads every lock file and returns the deduplicated fetch plan.
func (pf *providerFlags) plan() ([]provider.Item, int, error) {
	if len(pf.locks) == 0 {
		return nil, 0, errors.New("no lock files given; pass -lock .terraform.lock.hcl")
	}
	if pf.concurrency < 1 {
		return nil, 0, errors.New("-concurrency must be at least 1")
	}
	var files []string
	for _, pattern := range pf.locks {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			return nil, 0, fmt.Errorf("-lock %q: %w", pattern, err)
		}
		if len(matches) == 0 {
			return nil, 0, fmt.Errorf("-lock %q matches no files", pattern)
		}
		files = append(files, matches...)
	}
	var sets [][]lockfile.Provider
	seen := map[string]bool{}
	for _, f := range files {
		if seen[f] {
			continue
		}
		seen[f] = true
		ps, err := lockfile.ParseFile(f)
		if err != nil {
			return nil, 0, err
		}
		sets = append(sets, ps)
	}

	raw := pf.platforms
	if len(raw) == 0 {
		raw = listFlag{runtime.GOOS + "_" + runtime.GOARCH}
	}
	var platforms []provider.Platform
	for _, s := range raw {
		p, err := provider.ParsePlatform(s)
		if err != nil {
			return nil, 0, err
		}
		platforms = append(platforms, p)
	}
	return provider.Plan(lockfile.Merge(sets...), platforms), len(seen), nil
}

func (pf *providerFlags) install(root string, layout provider.Layout, items []provider.Item, stdout io.Writer) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	in := &provider.Installer{
		Client:           &provider.Client{HTTP: providerHTTP},
		Root:             root,
		Layout:           layout,
		VerifySignatures: pf.verifySigs,
		Concurrency:      pf.concurrency,
	}
	counts := map[provider.Status]int{}
	var warnings, failures []string
	for _, r := range in.Install(ctx, items) {
		counts[r.Status]++
		switch r.Status {
		case provider.Failed:
			failures = append(failures, r.Err.Error())
			continue
		}
		detail := shortHash(r.MatchedBy)
		if r.Signer != "" {
			detail += "  signed by " + r.Signer
		}
		fmt.Fprintf(stdout, "  %-8s %s  %s\n", r.Status, r.Item, detail)
		if r.Warning != "" {
			warnings = append(warnings, fmt.Sprintf("warn: %s: %s", r.Item, r.Warning))
		}
	}
	if len(warnings)+len(failures) > 0 {
		fmt.Fprintln(stdout)
		for _, w := range warnings {
			fmt.Fprintln(stdout, w)
		}
		for _, f := range failures {
			fmt.Fprintln(stdout, "error:", f)
		}
	}
	fmt.Fprintf(stdout, "\n%d fetched, %d already present, %d failed\n",
		counts[provider.Fetched], counts[provider.Present], counts[provider.Failed])
	if n := counts[provider.Failed]; n > 0 {
		return fmt.Errorf("%d package(s) could not be installed", n)
	}
	return nil
}

func shortHash(h string) string {
	if len(h) > 19 {
		return h[:19]
	}
	return h
}

// ---------------------------------------------------------------- cache-warm

// cmdCacheWarm pre-seeds a Terraform plugin cache from lock files, so a fan-out
// of parallel `terraform init` jobs reads providers from disk instead of each
// downloading the same ones.
func cmdCacheWarm(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("cache-warm", flag.ContinueOnError)
	fs.SetOutput(stdout)
	var pf providerFlags
	pf.register(fs)
	cacheDir := fs.String("cache-dir", os.Getenv("TF_PLUGIN_CACHE_DIR"), "plugin cache directory (default $TF_PLUGIN_CACHE_DIR)")
	keyOnly := fs.Bool("key-only", false, "print the cache key and exit without fetching anything")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}

	items, nfiles, err := pf.plan()
	if err != nil {
		return err
	}
	key := provider.CacheKey(items, provider.Unpacked)
	if *keyOnly {
		fmt.Fprintln(stdout, key)
		return nil
	}
	if *cacheDir == "" {
		return errors.New("no cache directory: pass -cache-dir or set TF_PLUGIN_CACHE_DIR")
	}

	fmt.Fprintf(stdout, "warming %s from %d lock file(s): %d package(s)\n\n", *cacheDir, nfiles, len(items))
	if err := pf.install(*cacheDir, provider.Unpacked, items, stdout); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "cache key: %s\n", key)
	return nil
}

// ---------------------------------------------------------------- mirror

// cmdMirror builds a filesystem_mirror tree from lock files, for runners that
// cannot reach the public registry at all.
func cmdMirror(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("mirror", flag.ContinueOnError)
	fs.SetOutput(stdout)
	var pf providerFlags
	pf.register(fs)
	out := fs.String("out", "", "mirror directory to build (required)")
	layoutName := fs.String("layout", "packed", "mirror layout: packed (release .zip files) or unpacked")
	pack := fs.String("pack", "", "also write the mirror as one .tar.gz bundle at this path, with a .sha256 file beside it")
	cliConfig := fs.String("cli-config", "", "also write the provider_installation block to this file")
	mirrorPath := fs.String("mirror-path", "", "path to put in the provider_installation block (default: the absolute -out)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	if *out == "" {
		return errors.New("-out is required")
	}
	layout, err := provider.ParseLayout(*layoutName)
	if err != nil {
		return err
	}
	items, nfiles, err := pf.plan()
	if err != nil {
		return err
	}

	fmt.Fprintf(stdout, "building %s mirror in %s from %d lock file(s): %d package(s)\n\n", layout, *out, nfiles, len(items))
	if err := pf.install(*out, layout, items, stdout); err != nil {
		return err
	}

	if *pack != "" {
		sum, err := provider.Pack(*out, layout, items, *pack)
		if err != nil {
			return err
		}
		line := fmt.Sprintf("%s  %s\n", sum, filepath.Base(*pack))
		if err := os.WriteFile(*pack+".sha256", []byte(line), 0o644); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "packed %s\n  sha256:%s\n  check on the other side with: sha256sum -c %s.sha256\n",
			*pack, sum, filepath.Base(*pack))
	}

	path := *mirrorPath
	if path == "" {
		if path, err = filepath.Abs(*out); err != nil {
			return err
		}
	}
	block := provider.CLIConfig(path, items)
	if *cliConfig != "" {
		if err := os.WriteFile(*cliConfig, []byte(block), 0o644); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "wrote %s\n", *cliConfig)
	}
	fmt.Fprintf(stdout, "\nCLI configuration (~/.terraformrc or TF_CLI_CONFIG_FILE):\n\n%s", block)
	return nil
}
