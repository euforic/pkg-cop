# Config Format

Use this reference when authoring or reviewing `pkg-cop` YAML configs.

## Minimal Shape

```yaml
ecosystems:
  npm:
    packages:
      - name: "@scope/package"
        versions:
          - "1.2.3"
        version_ranges:
          - ">=2.0.0 <=2.0.4"
        version_patterns:
          - "3.1.x"
    scan_filenames:
      - "package-lock.json"

ioc_strings:
  - "known-bad-domain.example"

payload_filenames:
  - "payload.js"
```

## Ecosystems

Supported ecosystem keys:

- `npm`: npm package manifests, lockfiles, npm/pnpm/Bun cache paths, and `node_modules` metadata.
- `pypi`: Python requirement files, Python lockfiles, `METADATA`, `PKG-INFO`, pip cache paths, and discovered Python site packages.
- `go`: `go.mod`, `go.sum`, and Go module cache paths.
- `rust`: `Cargo.toml`, `Cargo.lock`, Cargo registry sources, and Cargo git checkouts.

Top-level `packages` and `scan_filenames` remain supported as a generic compatibility bucket, but new configs should prefer ecosystem sections to avoid cross-language false positives.

## Package Selectors

Each package entry needs a `name` plus at least one selector field.

Use `versions` for sparse exact versions:

```yaml
versions:
  - "1.169.5"
  - "1.169.8"
```

Use `version_ranges` for contiguous semver-compatible runs:

```yaml
version_ranges:
  - ">=0.1.2 <=0.1.19"
  - ">=1.2.0 <1.3.0"
```

Use `version_patterns` only when the whole wildcard set is affected:

```yaml
version_patterns:
  - "1.2.x"
  - "0.9.*"
```

For exact Go module versions, keep the `v` prefix:

```yaml
ecosystems:
  go:
    packages:
      - name: "github.com/acme/compromised"
        versions:
          - "v1.2.3"
        version_ranges:
          - ">=1.2.0 <1.3.0"
```

## Global Indicators

Use `ioc_strings` for high-confidence strings that should not appear on clean systems:

```yaml
ioc_strings:
  - "https://bad.example/payload.js"
  - "malicious-domain.example"
  - "known malicious commit hash"
```

Use `payload_filenames` for suspicious basenames:

```yaml
payload_filenames:
  - "postinstall.js"
  - "runner.mjs"
  - "persistence.service"
```

Payload filename matches are reported even before file content is read.

## Validation Fixture Pattern

Create one minimal file that should match the config and scan only that fixture:

```sh
tmpdir="$(mktemp -d)"
printf 'compromised-package==4.2.2\n' > "$tmpdir/requirements.txt"
pkg-cop -config my-incident.yaml -no-caches -no-python -no-processes "$tmpdir"
```

Expected result: exit code `1` and an `affected-package-version`, `ioc-string`, or `payload-filename` finding. If it exits `0`, the fixture does not match the config.
