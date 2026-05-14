package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScannerDetectsNPMAndPyPIIndicators(t *testing.T) {
	if err := loadConfig("config.yaml"); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "package-lock.json"), `{
  "packages": {
    "node_modules/@opensearch-project/opensearch": { "version": "3.8.0" },
    "node_modules/@uipath/cli": { "version": "1.0.1" }
  }
}`)
	writeFile(t, filepath.Join(root, "pkg-1.0.dist-info", "METADATA"), "Name: mistralai\nVersion: 2.4.6\n")

	findings := []finding{}
	counts := counters{}
	walkRoot(root, options{
		roots:              []string{root},
		includeNodeModules: true,
		maxBytes:           defaultMaxBytes,
	}, &findings, &counts)

	rep := buildReport(findings, counts, []string{root})
	if !rep.Vulnerable {
		t.Fatalf("expected vulnerable report")
	}
	want := map[string]bool{
		"@opensearch-project/opensearch@3.8.0": false,
		"@uipath/cli@1.0.1":                    false,
		"mistralai@2.4.6":                      false,
	}
	for _, finding := range rep.Findings {
		if _, ok := want[finding.Detail]; ok {
			want[finding.Detail] = true
		}
	}
	for detail, found := range want {
		if !found {
			t.Fatalf("missing finding %q in %#v", detail, rep.Findings)
		}
	}
}

func TestScannerCleanFixture(t *testing.T) {
	if err := loadConfig("config.yaml"); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "package-lock.json"), `{
  "packages": {
    "node_modules/@tanstack/react-router": { "version": "1.168.23" }
  }
}`)
	writeFile(t, filepath.Join(root, "pkg-1.0.dist-info", "METADATA"), "Name: mistralai\nVersion: 2.4.5\n")

	findings := []finding{}
	counts := counters{}
	walkRoot(root, options{
		roots:              []string{root},
		includeNodeModules: true,
		maxBytes:           defaultMaxBytes,
	}, &findings, &counts)

	rep := buildReport(findings, counts, []string{root})
	if rep.Vulnerable {
		t.Fatalf("expected clean report, got %#v", rep.Findings)
	}
}

func TestScannerDetectsGoAndRustIndicators(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "test-config.yaml")
	writeFile(t, configPath, `packages:
  - name: "github.com/example/badmod"
    versions:
      - "v1.2.3"
  - name: "bad-crate"
    versions:
      - "0.9.0"
ioc_strings: []
payload_filenames: []
scan_filenames:
  - "go.mod"
  - "go.sum"
  - "Cargo.toml"
  - "Cargo.lock"
`)
	if err := loadConfig(configPath); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(root, "go.mod"), "module test\n\nrequire github.com/example/badmod v1.2.3\n")
	writeFile(t, filepath.Join(root, "go.sum"), "github.com/example/badmod v1.2.3 h1:abc\n")
	writeFile(t, filepath.Join(root, "Cargo.lock"), `[[package]]
name = "bad-crate"
version = "0.9.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
`)

	findings := []finding{}
	counts := counters{}
	walkRoot(root, options{
		roots:              []string{root},
		includeNodeModules: true,
		maxBytes:           defaultMaxBytes,
	}, &findings, &counts)

	rep := buildReport(findings, counts, []string{root})
	if !rep.Vulnerable {
		t.Fatalf("expected vulnerable report")
	}
	want := map[string]bool{
		"github.com/example/badmod@v1.2.3": false,
		"bad-crate@0.9.0":                  false,
	}
	for _, finding := range rep.Findings {
		if _, ok := want[finding.Detail]; ok {
			want[finding.Detail] = true
		}
	}
	for detail, found := range want {
		if !found {
			t.Fatalf("missing finding %q in %#v", detail, rep.Findings)
		}
	}
}

func writeFile(t *testing.T, path string, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
}
