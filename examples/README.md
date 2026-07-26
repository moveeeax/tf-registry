# Example catalog

A three-module, five-version catalog used by the README walkthrough and by the
test suite. It is real: the tarballs are valid Terraform modules and the `.sig`
files are genuine detached ECDSA signatures over them, verifiable with
`keys/cosign.pub`.

```
catalog/
  acme/vpc/aws/1.2.0/            signed
  acme/vpc/aws/1.10.0/           signed
  acme/vpc/aws/2.0.0-rc.1/       unsigned — dropped when signatures are required
  acme/aks/azurerm/0.3.1/        signed
  globex/object-store/oci/1.0.0/ signed
```

`registry.json` maps two demo tokens to two orgs:

| org      | namespace | demo token               |
| -------- | --------- | ------------------------ |
| `acme`   | `acme`    | `tfr_demo_acme_token`    |
| `globex` | `globex`  | `tfr_demo_globex_token`  |

These tokens are placeholders published on purpose so the walkthrough runs
without setup. They grant nothing anywhere. Mint real ones with
`tf-registry token`, which prints the token once and the digest you paste into
the config.

The private half of the signing key was discarded after the fixtures were
generated — only the public key is here, which is all verification needs.
