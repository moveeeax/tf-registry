# tf-registry

A private Terraform / OpenTofu **module** registry that refuses to serve an
artifact it cannot prove is the one that was signed.

It speaks the standard registry protocol, so `terraform init` and `tofu init`
talk to it with no plugin, no wrapper and no vendored provider — just a
`source = "registry.example.com/acme/vpc/aws"` and a token in `~/.terraformrc`.
Behind that, every version in the catalog carries a detached
[cosign](https://github.com/sigstore/cosign) signature, and the server verifies
all of them at startup. A version whose signature does not verify is not served;
with `require_signatures`, neither is one that was never signed.

That is the whole pitch: when an auditor asks how you know a module version was
not tampered with between publish and `terraform apply`, the answer is a
verifiable signature, not a git tag and a shrug.

**Status.** The read-only registry service and its CLI are done and tested.
Publishing is out of band — a CI job drops signed tarballs into the catalog
directory. See [Not built yet](#not-built-yet).

The same binary also stages the **providers** your lock files pin: it warms a
CI plugin cache and builds filesystem mirrors for air-gapped runners, verifying
every package against the lock file before it touches disk. See
[Providers: plugin cache and offline mirror](#providers-plugin-cache-and-offline-mirror).

## What it is not

No run/state/plan execution, no policy engine, no web UI, no provider registry
(the provider commands are clients of one), no SSO. One bearer token per org, modules only. If you want a TACOS, buy one.

## Install

```sh
go install github.com/moveeeax/tf-registry/cmd/tf-registry@latest
```

Or from a clone:

```sh
git clone https://github.com/moveeeax/tf-registry
cd tf-registry
make build        # ./tf-registry
```

Go 1.26+. No dependencies outside the standard library — the binary that
verifies your signatures pulls in nothing you have not audited.

## Try it in two minutes

The repo ships a real fixture catalog: three modules, five versions, genuine
ECDSA signatures over the actual tarballs. Everything below runs against it as
checked out.

### 1. Validate the catalog

```sh
$ ./tf-registry validate -catalog examples/catalog -key examples/keys/cosign.pub
verifying signatures with ecdsa-P-256 key examples/keys/cosign.pub

acme/aks/azurerm
  0.3.1             404 bytes  sha256:f09c0af7be33e00d  signed
acme/vpc/aws
  1.2.0             407 bytes  sha256:cae1a4fe88a1600f  signed
  1.10.0            408 bytes  sha256:cd01d212ffa8b1d3  signed
  2.0.0-rc.1        411 bytes  sha256:13bc70647698049f  unsigned
globex/object-store/oci
  1.0.0             402 bytes  sha256:0f54f85875a4d6d6  signed

warn: acme/vpc/aws/2.0.0-rc.1: unsigned: no module.tar.gz.sig alongside the archive

3 modules, 5 servable versions, 0 errors, 1 warnings
```

`validate` is the pre-publish gate. It opens every archive, checks it is a
gzipped tar with `.tf` files at the root, hashes it, and verifies its signature.
Add `-require-signatures` and the unsigned pre-release becomes an error and the
command exits non-zero — which is what CI runs.

### 2. Serve it

```sh
$ export TF_REGISTRY_URL_KEY="$(openssl rand -base64 32)"
$ ./tf-registry serve -config examples/registry.json
level=ERROR msg="module version not served" path=acme/vpc/aws/2.0.0-rc.1 reason="unsigned: ..."
level=INFO  msg=listening addr=127.0.0.1:8080 tls=false orgs=2 modules=3 versions=4 require_signatures=true
```

The unsigned pre-release is dropped on the way in: it is in the directory, it is
not in the registry.

### 3. Talk to it

```sh
$ curl -s localhost:8080/.well-known/terraform.json
{"modules.v1":"/v1/modules/"}

$ curl -s -H "Authorization: Bearer tfr_demo_acme_token" \
    localhost:8080/v1/modules/acme/vpc/aws/versions
{"modules":[{"versions":[{"version":"1.2.0"},{"version":"1.10.0"}]}]}

$ curl -si -H "Authorization: Bearer tfr_demo_acme_token" \
    localhost:8080/v1/modules/acme/vpc/aws/1.10.0/download
HTTP/1.1 204 No Content
X-Module-Sha256: cd01d212ffa8b1d353f8b018cc7da152e0a7e02a82340d179e26fc799526c909
X-Terraform-Get: http://localhost:8080/artifacts/acme/vpc/aws/1.10.0/module.tar.gz?exp=1785031187&sig=d4375ad7...
```

`acme`'s token cannot see `globex`'s namespace, and the refusal is a `404`, not
a `403` — the catalog is not an enumeration oracle:

```sh
$ curl -s -H "Authorization: Bearer tfr_demo_globex_token" \
    localhost:8080/v1/modules/acme/vpc/aws/versions
{"errors":["module not found"]}
```

Download counts, scoped to the calling org:

```sh
$ curl -s -H "Authorization: Bearer tfr_demo_acme_token" localhost:8080/counts
# tf-registry download counts for acme
# signatures required: true

MODULE/VERSION                            DOWNLOADS   SIGNED
acme/aks/azurerm/0.3.1                            0     true
acme/vpc/aws/1.2.0                                0     true
acme/vpc/aws/1.10.0                               1     true
```

### 4. Point Terraform at it

Terraform performs service discovery over HTTPS and will not fall back to plain
HTTP, so the registry needs TLS — either from the proxy in front of it or from
the server itself via `tls_cert_file` / `tls_key_file`.

```hcl
# main.tf
module "vpc" {
  source  = "registry.example.com/acme/vpc/aws"
  version = "~> 1.0"
  name    = "demo"
}
```

```hcl
# ~/.terraformrc
credentials "registry.example.com" {
  token = "tfr_demo_acme_token"
}
```

```
$ terraform init
Initializing modules...
Downloading registry.example.com/acme/vpc/aws 1.10.0 for vpc...
- vpc in .terraform/modules/vpc

Terraform has been successfully initialized!
```

That transcript is from a real run: stock `hashicorp/terraform` in a container
with no prior state, against this server serving `examples/catalog` over TLS.
Note the version it picked — `~> 1.0` resolves to `1.10.0`, not `1.2.0`, and not
the unsigned `2.0.0-rc.1`.

## Configuration

`examples/registry.json`:

```json
{
  "listen": "127.0.0.1:8080",
  "base_url": "https://registry.example.com",
  "catalog_dir": "catalog",
  "public_key_file": "keys/cosign.pub",
  "require_signatures": true,
  "download_url_ttl": "5m",
  "counts_file": "counts.json",
  "tls_cert_file": "",
  "tls_key_file": "",
  "orgs": [
    { "name": "acme", "namespaces": ["acme"], "token_sha256": "dca6e9a1..." }
  ]
}
```

The config file holds **no secrets** and is meant to be committed. Tokens appear
only as SHA-256 digests, and the HMAC key for download links comes from
`TF_REGISTRY_URL_KEY`. Relative paths resolve against the config file's own
directory. Unknown keys are a hard error, because a typo in `require_signatures`
should not silently disable it.

Mint a token:

```sh
$ ./tf-registry token
token (give this to the customer, it is not recoverable):
  tfr_9dQ...

config entry (safe to commit):
  { "name": "CUSTOMER", "namespaces": ["CUSTOMER"], "token_sha256": "8f2c..." }
```

`namespaces: ["*"]` grants every namespace — use it for your own break-glass
token, not for customers.

Send `SIGHUP` to reload the catalog after a publish. A reload that fails
validation is logged and discarded; the running catalog stays up.

## Catalog layout

```
catalog/<namespace>/<name>/<system>/<version>/module.tar.gz
catalog/<namespace>/<name>/<system>/<version>/module.tar.gz.sig
```

`<namespace>` is the customer org. `<name>` and `<system>` are the last two
segments of the usual `terraform-<system>-<name>` convention, so
`terraform-aws-vpc` published by `acme` is addressed `acme/vpc/aws`.
`<version>` is bare semver — no leading `v`.

Signatures are what `cosign sign-blob --key cosign.key module.tar.gz` writes:
base64 of an ASN.1 ECDSA signature over the archive's SHA-256 digest. Verifying
that needs only the public key, so the registry does it on every boot with no
network access and no sigstore toolchain installed. Keyless (Fulcio + Rekor)
signing is a different trust model and is not supported.

Check one by hand:

```sh
$ ./tf-registry verify -key examples/keys/cosign.pub \
    examples/catalog/acme/vpc/aws/1.2.0/module.tar.gz \
    examples/catalog/acme/vpc/aws/1.2.0/module.tar.gz.sig
OK: examples/catalog/acme/vpc/aws/1.2.0/module.tar.gz verified against examples/keys/cosign.pub (ecdsa-P-256)
```

## How downloads are authorised

Terraform authenticates to the registry with a bearer token, then follows the
`X-Terraform-Get` header **without carrying that token**. Reference registries
solve this with presigned object-store URLs; this one mints the same shape
itself: an HMAC-signed URL bound to the exact artifact path and an expiry, valid
for `download_url_ttl`. A link replayed against a different artifact, or with a
stretched `exp`, is rejected — and expired and forged links get the identical
`403`, so the response is not an oracle either.

Swapping the local filesystem for S3 later changes the backend, not the
protocol: the same handler would presign against a bucket instead of itself.

## Endpoints

| Method | Path | Auth | Purpose |
| ------ | ---- | ---- | ------- |
| `GET` | `/.well-known/terraform.json` | none | service discovery |
| `GET` | `/v1/modules/{ns}/{name}/{system}/versions` | bearer | version list |
| `GET` | `/v1/modules/{ns}/{name}/{system}/{version}/download` | bearer | `204` + `X-Terraform-Get` |
| `GET` | `/v1/modules/{ns}/{name}/{system}/download` | bearer | `302` to the latest stable version |
| `GET` | `/artifacts/{ns}/{name}/{system}/{version}/module.tar.gz` | signed URL | the tarball |
| `GET` | `/counts` | bearer | download counts for your namespaces |
| `GET` | `/healthz` | none | liveness |

## Providers: plugin cache and offline mirror

Two commands read `.terraform.lock.hcl` files and fetch exactly the provider
versions they pin, nothing newer, from the registry each lock entry names
(`registry.terraform.io`, `registry.opentofu.org` or a private one).

```sh
# CI: download each provider once per run, not once per parallel job
tf-registry cache-warm -lock 'envs/*/.terraform.lock.hcl' \
  -cache-dir "$HOME/.terraform.d/plugin-cache" -platform linux_amd64 -concurrency 4

# Air gap: build a filesystem_mirror, pack it, carry it over
tf-registry mirror -lock .terraform.lock.hcl \
  -platform linux_amd64 -platform darwin_arm64 -out ./mirror \
  -pack mirror.tar.gz -cli-config mirror.tfrc -mirror-path /opt/terraform-mirror
```

Lock files given together, or matched by one glob, are merged into one
deduplicated plan: ten stacks pinning `hashicorp/aws 5.31.0` cost one download
per platform. `-platform` repeats and defaults to the host's own.

### What a package has to pass

1. Its SHA-256 matches the `shasum` the registry returned for it.
2. Its `zh:` hash (SHA-256 of the .zip) or its `h1:` hash (the hash of its
   unpacked files) is one the lock file already records. This is the check that
   matters: the lock pins the bytes `terraform init` accepted. A lock entry with
   no hashes at all is refused, not trusted.
3. With `-verify-signatures` (the default), the release's `SHA256SUMS` carries
   a valid OpenPGP signature from one of the keys the registry returned, and
   lists this file with this digest. One `SHA256SUMS` covers all platforms of a
   release and is fetched once. RSA and Ed25519 keys are supported; signing
   subkeys need a valid binding and back-signature, and revoked or expired keys
   are rejected. `-verify-signatures=false` leaves the lock file as the only
   check.

Only then is the package written, and always via a temporary file or directory
renamed into place, so a concurrent `terraform init` or a crash never sees half
of one.

Registry requests are retried on 429, 5xx and network errors, up to five tries,
with exponential backoff from 1s capped at 30s; a `Retry-After` header (up to a
minute) takes precedence. A 404 is not retried. Private registries get their
token from `TF_TOKEN_<host>`, as with Terraform, and it is sent only to the
registry host, not to download URLs on other hosts.

### `cache-warm`

Writes the unpacked layout `plugin_cache_dir` reuses:
`<cache>/<host>/<namespace>/<type>/<version>/<os>_<arch>/`. `-cache-dir`
defaults to `$TF_PLUGIN_CACHE_DIR`. An entry already in the cache whose `h1:`
matches the lock is left alone.

Terraform will reuse an unpacked cache entry only when the lock file has an
`h1:` hash for it, and `terraform init` records `h1:` only for the platform it
ran on. A lock written on a Mac therefore warms a `linux_amd64` cache that
Linux runners ignore. `cache-warm` warns about each such entry; the fix is
`terraform providers lock -platform=linux_amd64 -platform=darwin_arm64` and
committing the result.

The last line of output is a cache key: the SHA-256 of every planned provider,
version, platform and locked hash. It is computed from the lock files alone, so
CI can get it before deciding to restore or warm:

```sh
key=$(tf-registry cache-warm -lock 'envs/*/.terraform.lock.hcl' -platform linux_amd64 -key-only)
```

### `mirror`

Builds a `filesystem_mirror` tree in `-out`. `-layout packed` (the default)
keeps the release zips at
`<host>/<namespace>/<type>/terraform-provider-<type>_<version>_<os>_<arch>.zip`;
`-layout unpacked` uses the same tree as the plugin cache. Packed is the
better choice for carrying: a zip stays checkable by its `zh:` hash, which the
lock file has for every platform.

Rebuilds are incremental. A file already in the mirror that matches the lock is
kept without asking the registry; one that does not match is fetched again.

`-pack mirror.tar.gz` writes the planned entries, and only those, into one
tarball, re-checking each against the lock file on the way in, plus
`mirror.tar.gz.sha256` for `sha256sum -c` on the other side. Packing the same
mirror twice gives the same digest.

The command prints the CLI configuration that points Terraform at the mirror
for exactly the mirrored providers (`-cli-config` also writes it to a file;
`-mirror-path` sets the path it names, for when the mirror lives somewhere else
after the move):

```hcl
provider_installation {
  filesystem_mirror {
    path    = "/opt/terraform-mirror"
    include = [
      "registry.terraform.io/hashicorp/aws",
    ]
  }
  direct {
    exclude = [
      "registry.terraform.io/hashicorp/aws",
    ]
  }
}
```

Providers outside the list are left to direct installation, which on an
air-gapped runner fails at `terraform init` and names the provider the mirror
is missing.

## Development

```sh
make test     # go test ./...
make race     # go test -race ./...
make validate # build, then validate the fixture catalog
```

The fixture catalog is shared between the tests and the README, on purpose: a
change that breaks the documented walkthrough breaks CI.

## Not built yet

Deliberately absent, and not stubbed:

- **The publish pipeline.** Tag → tarball → `cosign sign` → push needs a signing
  key and registry credentials in CI. Until then, publishing is `scp` plus
  `SIGHUP`, and `tf-registry validate -require-signatures` is the gate.
- **S3 / object-storage backend.** The signed-URL layer is backend-shaped
  already; the bucket half needs an account.
- **Billing.** Tokens are minted by hand. The first customers get invoiced by
  hand too, which is the point at that volume.

## License

MIT. See [LICENSE](LICENSE).
