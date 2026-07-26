// Command tf-registry serves and validates a private Terraform/OpenTofu module
// registry.
//
//	tf-registry serve    -config registry.json
//	tf-registry validate -catalog ./catalog -key cosign.pub -require-signatures
//	tf-registry verify   -key cosign.pub module.tar.gz module.tar.gz.sig
//	tf-registry token
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/moveeeax/tf-registry/internal/auth"
	"github.com/moveeeax/tf-registry/internal/catalog"
	"github.com/moveeeax/tf-registry/internal/counter"
	"github.com/moveeeax/tf-registry/internal/registry"
	"github.com/moveeeax/tf-registry/internal/signature"
	"github.com/moveeeax/tf-registry/internal/storage"
)

// version is stamped at build time:
//
//	go build -ldflags "-X main.version=$(git describe --tags)" ./cmd/tf-registry
var version = "dev"

// signingKeyEnv holds the HMAC key for download links. Keeping it out of the
// config file means the config can live in git.
const signingKeyEnv = "TF_REGISTRY_URL_KEY"

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "tf-registry:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		usage(stderr)
		return errors.New("no command given")
	}
	switch args[0] {
	case "serve":
		return cmdServe(args[1:], stderr)
	case "validate":
		return cmdValidate(args[1:], stdout)
	case "verify":
		return cmdVerify(args[1:], stdout)
	case "token":
		return cmdToken(args[1:], stdout)
	case "version", "--version", "-version":
		fmt.Fprintln(stdout, "tf-registry", version)
		return nil
	case "help", "-h", "--help":
		usage(stdout)
		return nil
	default:
		usage(stderr)
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `tf-registry — private Terraform/OpenTofu module registry

Usage:
  tf-registry serve    -config registry.json
  tf-registry validate -catalog DIR [-key cosign.pub] [-require-signatures]
  tf-registry verify   -key cosign.pub ARCHIVE SIGNATURE
  tf-registry token    [-hash TOKEN]
  tf-registry version

Environment:
  `+signingKeyEnv+`  HMAC key for download links. If unset, an ephemeral key is
                       generated and links stop working when the process exits.
`)
}

// ---------------------------------------------------------------- serve

func cmdServe(args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "registry.json", "path to the registry config file")
	if err := fs.Parse(args); err != nil {
		return err
	}

	log := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := LoadConfig(*configPath)
	if err != nil {
		return err
	}
	store, err := auth.NewStore(cfg.Orgs)
	if err != nil {
		return err
	}
	counts, err := counter.New(cfg.Path(cfg.CountsFile))
	if err != nil {
		return err
	}

	key, ephemeral, err := signingKey()
	if err != nil {
		return err
	}
	if ephemeral {
		log.Warn("no "+signingKeyEnv+" set: generated an ephemeral download-link key",
			"effect", "links minted before a restart will stop working")
	}
	signer, err := storage.NewSigner(key, cfg.TTL())
	if err != nil {
		return err
	}

	cat, err := loadCatalog(cfg, log)
	if err != nil {
		return err
	}

	srv, err := registry.New(registry.Config{
		Catalog:  cat,
		Auth:     store,
		Signer:   signer,
		Counter:  counts,
		BaseURL:  cfg.BaseURL,
		Logger:   log,
		Requires: cfg.RequireSignatures,
	})
	if err != nil {
		return err
	}

	httpSrv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// SIGHUP reloads the catalog in place. Publishing drops files into the
	// catalog directory from CI; this is how they go live without a restart
	// dropping in-flight downloads.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			reloaded, err := loadCatalog(cfg, log)
			if err != nil {
				log.Error("catalog reload failed, keeping the previous catalog", "err", err)
				continue
			}
			srv.SetCatalog(reloaded)
			log.Info("catalog reloaded", "modules", reloaded.Len(), "versions", reloaded.VersionCount())
		}
	}()

	// Terraform performs service discovery over HTTPS and will not fall back to
	// plain HTTP, so a box without a TLS terminator in front of it has to serve
	// TLS itself.
	tls := cfg.TLSCertFile != ""

	errCh := make(chan error, 1)
	go func() {
		log.Info("listening",
			"addr", cfg.Listen, "base_url", cfg.BaseURL, "tls", tls,
			"orgs", store.Len(), "modules", cat.Len(), "versions", cat.VersionCount(),
			"require_signatures", cfg.RequireSignatures, "link_ttl", cfg.TTL().String())
		var err error
		if tls {
			err = httpSrv.ListenAndServeTLS(cfg.Path(cfg.TLSCertFile), cfg.Path(cfg.TLSKeyFile))
		} else {
			err = httpSrv.ListenAndServe()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		log.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return httpSrv.Shutdown(shutdownCtx)
	}
}

func loadCatalog(cfg *Config, log *slog.Logger) (*catalog.Catalog, error) {
	cat, issues, err := catalog.Load(cfg.Path(cfg.CatalogDir))
	if err != nil {
		return nil, err
	}
	if cfg.PublicKeyFile != "" {
		v, err := signature.LoadPublicKeyFile(cfg.Path(cfg.PublicKeyFile))
		if err != nil {
			return nil, err
		}
		issues = append(issues, cat.CheckSignatures(v, cfg.RequireSignatures)...)
	} else if cfg.RequireSignatures {
		return nil, errors.New("require_signatures is set but no public key was configured")
	}
	for _, i := range issues {
		if i.Fatal {
			log.Error("module version not served", "path", i.Path, "reason", i.Message)
		} else {
			log.Warn("catalog warning", "path", i.Path, "reason", i.Message)
		}
	}
	if cat.Len() == 0 {
		return nil, errors.New("catalog contains no servable modules")
	}
	return cat, nil
}

func signingKey() (key []byte, ephemeral bool, err error) {
	if raw := os.Getenv(signingKeyEnv); raw != "" {
		k := storage.DecodeKey(raw)
		if len(k) < 16 {
			return nil, false, fmt.Errorf("%s must decode to at least 16 bytes", signingKeyEnv)
		}
		return k, false, nil
	}
	k, err := storage.RandomKey()
	return k, true, err
}

// ---------------------------------------------------------------- validate

// cmdValidate is the pre-publish gate: it is what CI runs against a catalog
// directory before it is promoted, and what an operator runs when a
// `terraform init` fails for reasons nobody can explain.
func cmdValidate(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	fs.SetOutput(stdout)
	dir := fs.String("catalog", "./catalog", "catalog directory to validate")
	keyPath := fs.String("key", "", "cosign public key used to verify signatures")
	require := fs.Bool("require-signatures", false, "treat an unsigned version as an error")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *require && *keyPath == "" {
		return errors.New("-require-signatures needs -key")
	}

	cat, issues, err := catalog.Load(*dir)
	if err != nil {
		return err
	}
	if *keyPath != "" {
		v, err := signature.LoadPublicKeyFile(*keyPath)
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "verifying signatures with %s key %s\n\n", v.KeyType(), *keyPath)
		issues = append(issues, cat.CheckSignatures(v, *require)...)
	}

	for _, m := range cat.Modules() {
		fmt.Fprintf(stdout, "%s\n", m.ID())
		for _, v := range m.Versions {
			mark := "unsigned"
			if v.Signed {
				mark = "signed"
			}
			fmt.Fprintf(stdout, "  %-12s %8d bytes  sha256:%s  %s\n", v.Version, v.Size, v.SHA256[:16], mark)
		}
	}

	fatal := 0
	if len(issues) > 0 {
		fmt.Fprintln(stdout)
		for _, i := range issues {
			fmt.Fprintln(stdout, i)
			if i.Fatal {
				fatal++
			}
		}
	}
	fmt.Fprintf(stdout, "\n%d modules, %d servable versions, %d errors, %d warnings\n",
		cat.Len(), cat.VersionCount(), fatal, len(issues)-fatal)
	if fatal > 0 {
		return fmt.Errorf("%d version(s) cannot be served", fatal)
	}
	return nil
}

// ---------------------------------------------------------------- verify

func cmdVerify(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(stdout)
	keyPath := fs.String("key", "", "cosign public key (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyPath == "" || fs.NArg() != 2 {
		return errors.New("usage: tf-registry verify -key cosign.pub ARCHIVE SIGNATURE")
	}
	v, err := signature.LoadPublicKeyFile(*keyPath)
	if err != nil {
		return err
	}
	if err := v.VerifyFile(fs.Arg(0), fs.Arg(1)); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "OK: %s verified against %s (%s)\n", fs.Arg(0), *keyPath, v.KeyType())
	return nil
}

// ---------------------------------------------------------------- token

func cmdToken(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("token", flag.ContinueOnError)
	fs.SetOutput(stdout)
	hash := fs.String("hash", "", "print the digest of an existing token instead of minting one")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *hash != "" {
		fmt.Fprintln(stdout, auth.Digest(*hash))
		return nil
	}

	token, digest, err := auth.GenerateToken()
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, `token (give this to the customer, it is not recoverable):
  %s

config entry (safe to commit):
  { "name": "CUSTOMER", "namespaces": ["CUSTOMER"], "token_sha256": %q }

customer ~/.terraformrc:
  credentials "registry.example.com" {
    token = "%s"
  }
`, token, digest, token)
	return nil
}
