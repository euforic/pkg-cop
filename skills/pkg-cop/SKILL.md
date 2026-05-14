---
name: pkg-cop
description: "Use when working with the pkg-cop package supply-chain scanner: running scans, selecting or locating config files, authoring or updating YAML incident configs, interpreting pkg-cop output and exit codes, validating package/version indicators, or creating focused fixtures for npm, PyPI, Go, or Rust exposure checks."
---

# Pkg Cop

## Overview

Use `pkg-cop` to scan package manifests, lockfiles, caches, Python installations, and process command lines for supply-chain incident indicators. This skill is portable: it may be installed globally or inside any project, so do not assume it lives in the `pkg-cop` source repository.

For config syntax details, read [references/config-format.md](references/config-format.md).

## Locate The Scanner

Prefer the installed binary:

```sh
pkg-cop -h
```

If `pkg-cop` is not on `PATH`, and the current directory is the source repository with `cmd/pkg-cop/main.go`, use the source fallback:

```sh
go run ./cmd/pkg-cop -h
```

If neither works, ask the user for the binary path or installation location. Do not assume a repository checkout exists.

## Choose A Config

The CLI defaults only to generic local names:

- `config.yaml`
- `config.yml`
- the same names next to the executable

Named incident configs must be passed explicitly:

```sh
pkg-cop -config shai-hulud.yaml .
```

Do not assume `shai-hulud.yaml` exists unless it is present in the current project, bundled with the release archive, or supplied by the user.

## Run Scans

Normal scan:

```sh
pkg-cop -config path/to/incident.yaml ~/projects ~/Documents
```

JSON output for automation:

```sh
pkg-cop -config path/to/incident.yaml -json ~/projects > scan-report.json
```

Fast lockfile-oriented pass:

```sh
pkg-cop -config path/to/incident.yaml -skip-node-modules -no-caches -no-python -no-processes ~/projects
```

Source fallback from a `pkg-cop` checkout:

```sh
go run ./cmd/pkg-cop -config shai-hulud.yaml -no-caches -no-python -no-processes -skip-node-modules .
```

## Validate A Config With A Fixture

Before scanning real systems with a new config, create a tiny fixture that should match:

```sh
tmpdir="$(mktemp -d)"
printf 'compromised-package==4.2.2\n' > "$tmpdir/requirements.txt"
pkg-cop -config my-incident.yaml -no-caches -no-python -no-processes "$tmpdir"
```

Expected behavior for a positive fixture is exit code `1` with an exposure finding. If it exits `0`, fix the config or fixture before scanning real systems.

## Interpret Results

- Exit `0`: no configured indicators were found in scanned paths.
- Exit `1`: one or more indicators were found; treat as exposure evidence.
- Exit `2`: scanner, config, or runtime error.

Findings are indicators, not proof of compromise. A clean result is not proof that a host or CI runner is clean; it only means the configured indicators were not found in the scanned inputs.

## Author Or Update Configs

Use ecosystem-specific package lists by default:

- `ecosystems.npm`
- `ecosystems.pypi`
- `ecosystems.go`
- `ecosystems.rust`

Use selector fields carefully:

- `versions`: sparse exact versions.
- `version_ranges`: contiguous semver-compatible ranges.
- `version_patterns`: wildcard selectors only when the advisory intentionally affects that whole wildcard set.

Keep `ioc_strings` and `payload_filenames` at the top level. Keep custom `scan_filenames` focused; broad names such as `index.js` slow scans and increase false positives.
