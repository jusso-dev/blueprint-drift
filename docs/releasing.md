# Releasing and Verifying Signed Artefacts

`blueprint-drift` publishes signed static binaries for Linux, macOS and Windows with SHA-256 checksums and a multi-architecture distroless container image on every `v*` Git tag via [.github/workflows/release.yml](../.github/workflows/release.yml).

> **Disclaimer:** This is an independent community project. It is not produced, endorsed or supported by ASD, ACSC or Microsoft.

## Release artefacts

Each tagged release publishes:

- Static binaries (`CGO_ENABLED=0`) for:
  - `blueprint-drift-linux-amd64`
  - `blueprint-drift-linux-arm64`
  - `blueprint-drift-darwin-amd64`
  - `blueprint-drift-darwin-arm64`
  - `blueprint-drift-windows-amd64.exe`
- `SHA256SUMS.txt` containing SHA-256 digests for every binary
- Sigstore Cosign keyless `.sigstore.json` signature bundles for `SHA256SUMS.txt` and each binary
- GitHub build provenance attestations (`actions/attest-build-provenance`)
- Multi-architecture OCI container image (`linux/amd64`, `linux/arm64`) published to `ghcr.io/jusso-dev/blueprint-drift:<version>` built on `gcr.io/distroless/static-debian12:nonroot`

## Verifying downloaded binaries

### 1. Verify SHA-256 checksum

```sh
sha256sum -c SHA256SUMS.txt --ignore-missing
```

### 2. Verify Sigstore Cosign signature bundle

```sh
cosign verify-blob \
  --bundle SHA256SUMS.txt.sigstore.json \
  --certificate-identity-regexp "^https://github.com/jusso-dev/blueprint-drift/.github/workflows/release.yml@" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  SHA256SUMS.txt
```

### 3. Verify GitHub build provenance attestation

```sh
gh attestation verify blueprint-drift-linux-amd64 --repo jusso-dev/blueprint-drift
```

## Running the container image

The container image runs as `nonroot` and bundles the validated Blueprint settings under `/etc/blueprint-drift/settings`:

```sh
docker run --rm ghcr.io/jusso-dev/blueprint-drift:v1.0.0 version
docker run --rm ghcr.io/jusso-dev/blueprint-drift:v1.0.0 validate --blueprint /etc/blueprint-drift/settings
```
