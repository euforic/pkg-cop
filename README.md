# Supply Chain Exposure Scanner

Go 1.26+ scanner for package supply-chain incident indicators.

Indicators live in `config.yaml`, so future incidents can be handled by editing data instead of recompiling scanner logic.

## Build

```sh
go build -o supply-chain-scan .
```

## Run

```sh
./supply-chain-scan ~/projects ~/Documents
./supply-chain-scan -json ~/projects
./supply-chain-scan -config config.yaml ~/projects
```

Useful flags:

- `-config PATH`: YAML indicator config. Defaults to `./config.yaml`, then `config.yaml` beside the executable.
- `-json`: machine-readable report.
- `-skip-node-modules`: faster manifest/lockfile-focused scan.
- `-no-caches`: skip npm, Bun, pnpm, and pip cache roots.
- `-no-python`: skip Python site-package discovery.
- `-no-processes`: skip process command-line scan.

Exit codes:

- `0`: no indicators found
- `1`: one or more indicators found
- `2`: scanner/config/runtime error

## Config Shape

```yaml
packages:
  - name: "@scope/package"
    versions:
      - "1.2.3"

ioc_strings:
  - "known-bad-domain.example"

payload_filenames:
  - "payload.js"

scan_filenames:
  - "package-lock.json"
  - "requirements.txt"
  - "METADATA"
```

Any package/version or IOC entry is treated as exposure evidence.
