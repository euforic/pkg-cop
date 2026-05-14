package scanner

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/euforic/pkg-cop/internal/config"
)

func TestScannerDetectsNPMAndPyPIIndicators(t *testing.T) {
	scan := newTestScanner(t, config.Config{
		Packages: []config.Package{
			{Name: "@opensearch-project/opensearch", Versions: []string{"3.8.0"}},
			{Name: "@uipath/cli", Versions: []string{"1.0.1"}},
			{Name: "mistralai", Versions: []string{"2.4.6"}},
		},
		ScanFilenames: []string{"package-lock.json", "METADATA"},
	})
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "package-lock.json"), `{
  "packages": {
    "node_modules/@opensearch-project/opensearch": { "version": "3.8.0" },
    "node_modules/@uipath/cli": { "version": "1.0.1" }
  }
}`)
	writeFile(t, filepath.Join(root, "pkg-1.0.dist-info", "METADATA"), "Name: mistralai\nVersion: 2.4.6\n")

	rep := scan.Run(testOptions(root))
	assertVulnerable(t, rep, map[string]bool{
		"@opensearch-project/opensearch@3.8.0": false,
		"@uipath/cli@1.0.1":                    false,
		"mistralai@2.4.6":                      false,
	})
}

func TestScannerDetectsGoAndRustIndicators(t *testing.T) {
	scan := newTestScanner(t, config.Config{
		Packages: []config.Package{
			{Name: "github.com/example/badmod", Versions: []string{"v1.2.3"}},
			{Name: "bad-crate", Versions: []string{"0.9.0"}},
		},
		ScanFilenames: []string{"go.mod", "go.sum", "Cargo.toml", "Cargo.lock"},
	})
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "go.mod"), "module test\n\nrequire github.com/example/badmod v1.2.3\n")
	writeFile(t, filepath.Join(root, "go.sum"), "github.com/example/badmod v1.2.3 h1:abc\n")
	writeFile(t, filepath.Join(root, "Cargo.lock"), `[[package]]
name = "bad-crate"
version = "0.9.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
`)

	rep := scan.Run(testOptions(root))
	assertVulnerable(t, rep, map[string]bool{
		"github.com/example/badmod@v1.2.3": false,
		"bad-crate@0.9.0":                  false,
	})
}

func TestScannerCleanFixture(t *testing.T) {
	scan := newTestScanner(t, config.Config{
		Packages: []config.Package{
			{Name: "@tanstack/react-router", Versions: []string{"1.169.8"}},
			{Name: "mistralai", Versions: []string{"2.4.6"}},
		},
		ScanFilenames: []string{"package-lock.json", "METADATA"},
	})
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "package-lock.json"), `{
  "packages": {
    "node_modules/@tanstack/react-router": { "version": "1.168.23" }
  }
}`)
	writeFile(t, filepath.Join(root, "pkg-1.0.dist-info", "METADATA"), "Name: mistralai\nVersion: 2.4.5\n")

	rep := scan.Run(testOptions(root))
	if rep.Vulnerable {
		t.Fatalf("expected clean report, got %#v", rep.Findings)
	}
}

func newTestScanner(t *testing.T, cfg config.Config) *Scanner {
	t.Helper()
	if err := cfg.Validate("test"); err != nil {
		t.Fatal(err)
	}
	return New(cfg)
}

func testOptions(root string) Options {
	return Options{
		Roots:              []string{root},
		IncludeNodeModules: true,
		MaxBytes:           DefaultMaxBytes,
	}
}

func assertVulnerable(t *testing.T, rep Report, want map[string]bool) {
	t.Helper()
	if !rep.Vulnerable {
		t.Fatalf("expected vulnerable report")
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
