package scanner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/euforic/pkg-cop/internal/config"
	"github.com/euforic/pkg-cop/internal/set"
)

type Scanner struct {
	indicators          map[Ecosystem]map[string]packageIndicator
	iocs                []string
	payloadNames        map[string]struct{}
	scanFileNames       map[string]struct{}
	scanFileEcosystems  map[string]map[Ecosystem]struct{}
	cachePathEcosystems map[string]Ecosystem
	skipDirs            map[string]struct{}
}

func New(cfg config.Config) *Scanner {
	scanner := &Scanner{
		indicators:          make(map[Ecosystem]map[string]packageIndicator),
		iocs:                append([]string{}, cfg.IOCStrings...),
		payloadNames:        set.New(cfg.PayloadFilenames...),
		scanFileNames:       set.New(cfg.ScanFilenames...),
		scanFileEcosystems:  make(map[string]map[Ecosystem]struct{}),
		cachePathEcosystems: defaultCachePathEcosystems(),
		skipDirs: set.New(
			".DS_Store",
			".Trash",
			".git",
			".hg",
			".svn",
			".next",
			".turbo",
			"Library",
			"Caches",
			"Photos Library.photoslibrary",
			"Photo Booth Library",
		),
	}
	scanner.indicators[EcosystemGeneric] = buildPackageIndicators(cfg.Packages, EcosystemGeneric)
	for _, name := range cfg.ScanFilenames {
		scanner.addScanFilename(name, EcosystemGeneric)
	}
	for ecosystem, filenames := range defaultScanFilenames() {
		for _, name := range filenames {
			scanner.addScanFilename(name, ecosystem)
		}
	}
	for ecosystemName, ecosystemCfg := range cfg.Ecosystems {
		ecosystem := parseEcosystem(strings.ToLower(strings.TrimSpace(ecosystemName)))
		scanner.indicators[ecosystem] = mergePackageIndicators(
			scanner.indicators[ecosystem],
			buildPackageIndicators(ecosystemCfg.Packages, ecosystem),
		)
		for _, name := range ecosystemCfg.ScanFilenames {
			scanner.addScanFilename(name, ecosystem)
		}
	}
	return scanner
}

func (s *Scanner) Run(opts Options) Report {
	if opts.MaxBytes == 0 {
		opts.MaxBytes = DefaultMaxBytes
	}
	roots := append([]string{}, opts.Roots...)
	if opts.ScanCaches {
		roots = append(roots, cacheRoots()...)
	}
	if opts.ScanPython {
		roots = append(roots, pythonRoots()...)
	}
	roots = uniqueExistingDirs(roots)

	var findings []Finding
	counts := Counters{}
	for _, root := range roots {
		s.walkRoot(root, opts, &findings, &counts)
	}
	if opts.ScanProcesses {
		s.scanProcesses(&findings)
	}
	return buildReport(findings, counts, roots)
}

func cacheRoots() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	candidates := []string{
		filepath.Join(home, ".npm"),
		filepath.Join(home, ".bun", "install", "cache"),
		filepath.Join(home, ".cache", "pip"),
		filepath.Join(home, ".cargo", "registry", "src"),
		filepath.Join(home, ".cargo", "git", "checkouts"),
		filepath.Join(home, "Library", "pnpm"),
		filepath.Join(home, "Library", "Caches", "pnpm"),
		filepath.Join(home, ".pnpm-store"),
	}
	candidates = append(candidates, goCacheRoots()...)
	return existingDirs(candidates)
}

func defaultScanFilenames() map[Ecosystem][]string {
	return map[Ecosystem][]string{
		EcosystemNPM: {
			"package.json",
			"package-lock.json",
			"npm-shrinkwrap.json",
			"pnpm-lock.yaml",
			"yarn.lock",
			"bun.lock",
		},
		EcosystemPyPI: {
			"requirements.txt",
			"requirements-dev.txt",
			"constraints.txt",
			"pyproject.toml",
			"poetry.lock",
			"pdm.lock",
			"uv.lock",
			"Pipfile",
			"Pipfile.lock",
			"METADATA",
			"PKG-INFO",
		},
		EcosystemGo: {
			"go.mod",
			"go.sum",
		},
		EcosystemRust: {
			"Cargo.toml",
			"Cargo.lock",
		},
	}
}

func defaultCachePathEcosystems() map[string]Ecosystem {
	sep := string(filepath.Separator)
	return map[string]Ecosystem{
		sep + ".bun" + sep:              EcosystemNPM,
		sep + ".npm" + sep:              EcosystemNPM,
		sep + ".pnpm-store" + sep:       EcosystemNPM,
		sep + "pnpm" + sep:              EcosystemNPM,
		sep + "pip" + sep:               EcosystemPyPI,
		sep + ".cargo" + sep:            EcosystemRust,
		sep + "pkg" + sep + "mod" + sep: EcosystemGo,
	}
}

func (s *Scanner) addScanFilename(name string, ecosystem Ecosystem) {
	if name == "" {
		return
	}
	s.scanFileNames[name] = struct{}{}
	if s.scanFileEcosystems[name] == nil {
		s.scanFileEcosystems[name] = make(map[Ecosystem]struct{})
	}
	s.scanFileEcosystems[name][ecosystem] = struct{}{}
}

func goCacheRoots() []string {
	var roots []string
	for _, envName := range []string{"GOMODCACHE", "GOPATH"} {
		out, err := exec.Command("go", "env", envName).Output()
		if err != nil {
			continue
		}
		value := strings.TrimSpace(string(out))
		if value == "" {
			continue
		}
		if envName == "GOPATH" {
			value = filepath.Join(value, "pkg", "mod")
		}
		roots = append(roots, value)
	}
	return roots
}

func pythonRoots() []string {
	const code = `import json, site, sysconfig
roots = []
roots.extend(getattr(site, "getsitepackages", lambda: [])())
roots.append(site.getusersitepackages())
for key in ("purelib", "platlib"):
    value = sysconfig.get_paths().get(key)
    if value:
        roots.append(value)
print(json.dumps(sorted(set(filter(None, roots)))))`
	var roots []string
	for _, py := range []string{"python3", "python"} {
		out, err := exec.Command(py, "-c", code).Output()
		if err != nil {
			continue
		}
		var decoded []string
		if err := json.Unmarshal(bytes.TrimSpace(out), &decoded); err == nil {
			roots = append(roots, decoded...)
		}
	}
	return existingDirs(roots)
}

func existingDirs(paths []string) []string {
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		info, err := os.Stat(p)
		if err == nil && info.IsDir() {
			out = append(out, p)
		}
	}
	return out
}

func uniqueExistingDirs(paths []string) []string {
	seen := make(map[string]struct{}, len(paths))
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		if p == "" {
			continue
		}
		info, err := os.Stat(p)
		if err != nil || !info.IsDir() {
			continue
		}
		real, err := filepath.EvalSymlinks(p)
		if err != nil {
			real = p
		}
		if _, ok := seen[real]; ok {
			continue
		}
		seen[real] = struct{}{}
		out = append(out, p)
	}
	return out
}

func (s *Scanner) walkRoot(root string, opts Options, findings *[]Finding, counts *Counters) {
	visited := make(map[string]struct{})
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if s.shouldSkipDir(d.Name(), path, opts) {
				return filepath.SkipDir
			}
			real, err := filepath.EvalSymlinks(path)
			if err == nil {
				if _, ok := visited[real]; ok {
					return filepath.SkipDir
				}
				visited[real] = struct{}{}
			}
			return nil
		}
		if d.Type().IsRegular() {
			s.scanFile(path, opts, findings, counts)
		}
		return nil
	})
}

func (s *Scanner) shouldSkipDir(name, path string, opts Options) bool {
	if set.Has(s.skipDirs, name) {
		return true
	}
	if !opts.IncludeNodeModules && name == "node_modules" {
		return true
	}
	return !opts.IncludeNodeModules && strings.Contains(path, string(filepath.Separator)+"node_modules"+string(filepath.Separator))
}

func (s *Scanner) scanFile(path string, opts Options, findings *[]Finding, counts *Counters) {
	counts.FilesSeen++
	base := filepath.Base(path)
	if set.Has(s.payloadNames, base) {
		addFinding(findings, "critical", "payload-filename", path, base)
	}
	if !s.shouldReadFile(path, base) {
		return
	}
	info, err := os.Stat(path)
	if err != nil || info.Size() > opts.MaxBytes {
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	counts.FilesScanned++

	switch base {
	case "package.json":
		s.scanPackageJSON(path, data, findings)
	case "package-lock.json", "npm-shrinkwrap.json":
		s.scanPackageLock(path, data, findings)
	default:
		s.scanText(path, string(data), findings)
	}
}

func (s *Scanner) shouldReadFile(path, base string) bool {
	if set.Has(s.scanFileNames, base) || strings.HasSuffix(base, ".lock") || set.Has(s.payloadNames, base) {
		return true
	}
	return strings.Contains(path, string(filepath.Separator)+".bun"+string(filepath.Separator)) ||
		strings.Contains(path, string(filepath.Separator)+".npm"+string(filepath.Separator)) ||
		strings.Contains(path, string(filepath.Separator)+"pip"+string(filepath.Separator))
}

func (s *Scanner) scanPackageJSON(path string, data []byte, findings *[]Finding) {
	var doc struct {
		Name                 string            `json:"name"`
		Version              string            `json:"version"`
		Dependencies         map[string]string `json:"dependencies"`
		DevDependencies      map[string]string `json:"devDependencies"`
		OptionalDependencies map[string]string `json:"optionalDependencies"`
		PeerDependencies     map[string]string `json:"peerDependencies"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		s.scanText(path, string(data), findings)
		return
	}
	name := doc.Name
	if name == "" {
		name = packageNameFromNodeModulesPath(path)
	}
	s.checkPackageVersion(path, []Ecosystem{EcosystemNPM, EcosystemGeneric}, name, doc.Version, findings)
	for _, deps := range []map[string]string{doc.Dependencies, doc.DevDependencies, doc.OptionalDependencies, doc.PeerDependencies} {
		for depName, spec := range deps {
			indicator, ok := s.indicator(EcosystemNPM, depName)
			if !ok {
				indicator, ok = s.indicator(EcosystemGeneric, depName)
				if !ok {
					continue
				}
			}
			for _, affected := range indicator.specs {
				if affected.mayIncludeDependencySpec(spec) {
					addFinding(findings, "high", "dependency-range-includes-affected-version", path, depName+": "+spec+" intersects "+affected.raw)
				}
			}
		}
	}
	s.scanText(path, string(data), findings)
}

func (s *Scanner) scanPackageLock(path string, data []byte, findings *[]Finding) {
	var doc struct {
		Packages map[string]struct {
			Version string `json:"version"`
		} `json:"packages"`
		Dependencies map[string]struct {
			Version string `json:"version"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		s.scanText(path, string(data), findings)
		return
	}
	for pkgPath, meta := range doc.Packages {
		name := ""
		if strings.HasPrefix(pkgPath, "node_modules/") {
			name = packageNameFromNodeModulesPath(pkgPath)
		}
		s.checkPackageVersion(path, []Ecosystem{EcosystemNPM, EcosystemGeneric}, name, meta.Version, findings)
	}
	for name, meta := range doc.Dependencies {
		s.checkPackageVersion(path, []Ecosystem{EcosystemNPM, EcosystemGeneric}, name, meta.Version, findings)
	}
	s.scanText(path, string(data), findings)
}

func (s *Scanner) scanText(path, text string, findings *[]Finding) {
	for _, ioc := range s.iocs {
		if strings.Contains(text, ioc) {
			addFinding(findings, "critical", "ioc-string", path, ioc)
		}
	}
	for _, ecosystem := range s.ecosystemsForPath(path) {
		for name, indicator := range s.indicators[ecosystem] {
			if !strings.Contains(text, name) {
				continue
			}
			for _, match := range indicator.matches(text) {
				addFinding(findings, "critical", "affected-package-version", path, match.name+"@"+match.version)
			}
		}
	}
}

func (s *Scanner) checkPackageVersion(path string, ecosystems []Ecosystem, name, version string, findings *[]Finding) {
	if name == "" || version == "" {
		return
	}
	for _, ecosystem := range ecosystems {
		indicator, ok := s.indicator(ecosystem, name)
		if ok && indicator.versionMatches(version) {
			addFinding(findings, "critical", "affected-package-version", path, name+"@"+version)
			return
		}
	}
}

func (s *Scanner) indicator(ecosystem Ecosystem, name string) (packageIndicator, bool) {
	indicators := s.indicators[ecosystem]
	if indicators == nil {
		return packageIndicator{}, false
	}
	indicator, ok := indicators[name]
	return indicator, ok
}

func (s *Scanner) ecosystemsForPath(path string) []Ecosystem {
	base := filepath.Base(path)
	ecosystems := map[Ecosystem]struct{}{EcosystemGeneric: {}}
	for ecosystem := range s.scanFileEcosystems[base] {
		ecosystems[ecosystem] = struct{}{}
	}
	for marker, ecosystem := range s.cachePathEcosystems {
		if strings.Contains(path, marker) {
			ecosystems[ecosystem] = struct{}{}
		}
	}
	out := make([]Ecosystem, 0, len(ecosystems))
	for ecosystem := range ecosystems {
		out = append(out, ecosystem)
	}
	slices.Sort(out)
	return out
}

func (s *Scanner) scanProcesses(findings *[]Finding) {
	name := "ps"
	args := []string{"-axo", "pid,ppid,command"}
	if runtime.GOOS == "windows" {
		name = "wmic"
		args = []string{"process", "get", "ProcessId,CommandLine"}
	}
	out, err := exec.Command(name, args...).Output()
	if err != nil {
		return
	}
	text := string(out)
	for _, ioc := range s.iocs {
		if strings.Contains(text, ioc) {
			addFinding(findings, "critical", "process-ioc", "<process-list>", ioc)
		}
	}
}

func packageNameFromNodeModulesPath(path string) string {
	parts := strings.FieldsFunc(path, func(r rune) bool { return r == '/' || r == '\\' })
	for i, part := range parts {
		if part != "node_modules" || i+1 >= len(parts) {
			continue
		}
		first := parts[i+1]
		if strings.HasPrefix(first, "@") && i+2 < len(parts) {
			return first + "/" + parts[i+2]
		}
		return first
	}
	return ""
}

func versionSpecMentions(spec, version string) bool {
	if spec == "" {
		return false
	}
	if spec == version || spec == "="+version {
		return true
	}
	index := strings.Index(spec, version)
	if index == -1 {
		return false
	}
	beforeOK := index == 0 || !isVersionChar(rune(spec[index-1]))
	after := index + len(version)
	afterOK := after >= len(spec) || !isVersionChar(rune(spec[after]))
	return beforeOK && afterOK
}

func isVersionChar(r rune) bool {
	return r == '.' || r == '-' || r == '_' || r == '+' ||
		(r >= '0' && r <= '9') ||
		(r >= 'A' && r <= 'Z') ||
		(r >= 'a' && r <= 'z')
}

func addFinding(findings *[]Finding, severity, kind, file, detail string) {
	*findings = append(*findings, Finding{
		Severity: severity,
		Type:     kind,
		File:     file,
		Detail:   detail,
	})
}

func buildReport(findings []Finding, counts Counters, roots []string) Report {
	findings = uniqueFindings(findings)
	critical := 0
	high := 0
	for _, f := range findings {
		switch f.Severity {
		case "critical":
			critical++
		case "high":
			high++
		}
	}
	slices.SortFunc(findings, func(a, b Finding) int {
		if a.File == b.File {
			return strings.Compare(a.Detail, b.Detail)
		}
		return strings.Compare(a.File, b.File)
	})
	guidance := "No known exposure indicators were found in scanned paths."
	if critical > 0 || high > 0 {
		guidance = "Treat the host as potentially compromised if installs ran on affected versions. Rotate reachable credentials and inspect audit logs."
	}
	return Report{
		Vulnerable: critical > 0 || high > 0,
		Critical:   critical,
		High:       high,
		Findings:   findings,
		Counters:   counts,
		Roots:      roots,
		Guidance:   guidance,
	}
}

func uniqueFindings(findings []Finding) []Finding {
	seen := make(map[Finding]struct{}, len(findings))
	out := make([]Finding, 0, len(findings))
	for _, finding := range findings {
		if _, ok := seen[finding]; ok {
			continue
		}
		seen[finding] = struct{}{}
		out = append(out, finding)
	}
	return out
}

func FormatHuman(rep Report, quiet bool) string {
	var out strings.Builder
	if !quiet {
		fmt.Fprintln(&out, "Pkg Cop")
		fmt.Fprintf(&out, "Scanned files: %d text files (%d seen)\n", rep.Counters.FilesScanned, rep.Counters.FilesSeen)
		fmt.Fprintf(&out, "Roots: %s\n\n", strings.Join(rep.Roots, ", "))
	}
	if len(rep.Findings) == 0 {
		fmt.Fprintln(&out, "Status: CLEAN - no known indicators found.")
		return out.String()
	}
	fmt.Fprintln(&out, "Status: EXPOSED - indicators found.")
	for _, f := range rep.Findings {
		fmt.Fprintf(&out, "[%s] %s: %s :: %s\n", f.Severity, f.Type, f.File, f.Detail)
	}
	fmt.Fprintln(&out)
	fmt.Fprintln(&out, rep.Guidance)
	return out.String()
}
