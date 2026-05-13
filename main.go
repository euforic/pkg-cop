package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

const defaultMaxBytes int64 = 8 * 1024 * 1024

var affectedPackages map[string][]string
var iocStrings []string
var payloadNames map[string]struct{}
var scanFileNames map[string]struct{}

var skipDirs = setOf(
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
)

type stringList []string

func (s *stringList) String() string {
	return strings.Join(*s, ",")
}

func (s *stringList) Set(value string) error {
	if value == "" {
		return errors.New("empty root")
	}
	*s = append(*s, value)
	return nil
}

type options struct {
	roots              []string
	jsonOutput         bool
	quiet              bool
	includeNodeModules bool
	scanCaches         bool
	scanPython         bool
	scanProcesses      bool
	maxBytes           int64
	configPath         string
}

type scannerConfig struct {
	Packages         []packageConfig `yaml:"packages"`
	IOCStrings       []string        `yaml:"ioc_strings"`
	PayloadFilenames []string        `yaml:"payload_filenames"`
	ScanFilenames    []string        `yaml:"scan_filenames"`
}

type packageConfig struct {
	Name     string   `yaml:"name"`
	Versions []string `yaml:"versions"`
}

type finding struct {
	Severity string `json:"severity"`
	Type     string `json:"type"`
	File     string `json:"file"`
	Detail   string `json:"detail"`
}

type counters struct {
	FilesSeen    int `json:"filesSeen"`
	FilesScanned int `json:"filesScanned"`
}

type report struct {
	Vulnerable bool      `json:"vulnerable"`
	Critical   int       `json:"critical"`
	High       int       `json:"high"`
	Findings   []finding `json:"findings"`
	Counters   counters  `json:"counters"`
	Roots      []string  `json:"roots"`
	Guidance   string    `json:"guidance"`
}

func main() {
	opts, err := parseArgs(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if err := loadConfig(opts.configPath); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	findings := make([]finding, 0)
	counts := counters{}
	roots := append([]string{}, opts.roots...)
	if opts.scanCaches {
		roots = append(roots, cacheRoots()...)
	}
	if opts.scanPython {
		roots = append(roots, pythonRoots()...)
	}
	roots = uniqueExistingDirs(roots)

	for _, root := range roots {
		walkRoot(root, opts, &findings, &counts)
	}
	if opts.scanProcesses {
		scanProcesses(&findings)
	}

	rep := buildReport(findings, counts, roots)
	if opts.jsonOutput {
		encoded, err := json.MarshalIndent(rep, "", "  ")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		fmt.Println(string(encoded))
	} else {
		printHuman(rep, opts.quiet)
	}
	if rep.Vulnerable {
		os.Exit(1)
	}
}

func parseArgs(args []string) (options, error) {
	opts := options{
		includeNodeModules: true,
		scanCaches:         true,
		scanPython:         true,
		scanProcesses:      true,
		maxBytes:           defaultMaxBytes,
	}
	var roots stringList
	fs := flag.NewFlagSet("mini-shai-hulud-scan", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.Var(&roots, "root", "Add a root to scan. Positional paths also work.")
	fs.BoolVar(&opts.jsonOutput, "json", false, "Emit machine-readable JSON.")
	fs.BoolVar(&opts.quiet, "quiet", false, "Only print findings and final status.")
	fs.BoolVar(&opts.includeNodeModules, "include-node-modules", true, "Scan node_modules directories.")
	fs.BoolFunc("skip-node-modules", "Do not scan node_modules directories.", func(string) error {
		opts.includeNodeModules = false
		return nil
	})
	fs.BoolFunc("no-caches", "Do not add npm/Bun/pnpm/pip cache paths.", func(string) error {
		opts.scanCaches = false
		return nil
	})
	fs.BoolFunc("no-python", "Do not add Python site-package roots.", func(string) error {
		opts.scanPython = false
		return nil
	})
	fs.BoolFunc("no-processes", "Do not inspect running process command lines.", func(string) error {
		opts.scanProcesses = false
		return nil
	})
	fs.Int64Var(&opts.maxBytes, "max-bytes", defaultMaxBytes, "Maximum text file size to inspect.")
	fs.StringVar(&opts.configPath, "config", "", "YAML indicator config path. Defaults to ./config.yaml or config.yaml next to the executable.")
	fs.Usage = printUsage

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		return opts, err
	}
	opts.roots = append(opts.roots, roots...)
	opts.roots = append(opts.roots, fs.Args()...)
	if len(opts.roots) == 0 {
		cwd, err := os.Getwd()
		if err != nil {
			return opts, err
		}
		opts.roots = []string{cwd}
	}
	for i, root := range opts.roots {
		abs, err := filepath.Abs(root)
		if err == nil {
			opts.roots[i] = abs
		}
	}
	return opts, nil
}

func printUsage() {
	fmt.Println(`Mini Shai-Hulud exposure scanner

Usage:
  mini-shai-hulud-scan [roots...] [options]

Options:
  -root PATH              Add a root to scan. Positional paths also work.
  -json                   Emit machine-readable JSON.
  -quiet                  Only print findings and final status.
  -skip-node-modules      Do not scan node_modules directories.
  -no-caches              Do not add npm/Bun/pnpm/pip cache paths.
  -no-python              Do not add Python site-package roots.
  -no-processes           Do not inspect running process command lines.
  -config PATH            YAML indicator config. Defaults to ./config.yaml or next to the executable.
  -max-bytes N            Maximum text file size to inspect. Default: 8388608.
  -h, -help               Show this help.

Exit codes:
  0  No indicators found.
  1  One or more exposure indicators found.
  2  Scanner error.`)
}

func loadConfig(configPath string) error {
	resolved, err := resolveConfigPath(configPath)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(resolved)
	if err != nil {
		return fmt.Errorf("read config %s: %w", resolved, err)
	}
	var cfg scannerConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("parse config %s: %w", resolved, err)
	}
	if len(cfg.Packages) == 0 && len(cfg.IOCStrings) == 0 && len(cfg.PayloadFilenames) == 0 {
		return fmt.Errorf("config %s has no indicators", resolved)
	}
	affectedPackages = make(map[string][]string, len(cfg.Packages))
	for _, pkg := range cfg.Packages {
		if strings.TrimSpace(pkg.Name) == "" || len(pkg.Versions) == 0 {
			return fmt.Errorf("config %s has package entry with missing name or versions", resolved)
		}
		affectedPackages[pkg.Name] = append([]string{}, pkg.Versions...)
	}
	iocStrings = append([]string{}, cfg.IOCStrings...)
	payloadNames = setOf(cfg.PayloadFilenames...)
	scanFileNames = setOf(cfg.ScanFilenames...)
	return nil
}

func resolveConfigPath(configPath string) (string, error) {
	candidates := []string{}
	if configPath != "" {
		candidates = append(candidates, configPath)
	} else {
		candidates = append(candidates, "config.yaml")
		if exe, err := os.Executable(); err == nil {
			candidates = append(candidates, filepath.Join(filepath.Dir(exe), "config.yaml"))
		}
	}
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate, nil
		}
	}
	if configPath != "" {
		return "", fmt.Errorf("config file not found: %s", configPath)
	}
	return "", errors.New("config file not found: pass -config or place config.yaml in the working directory")
}

func setOf(values ...string) map[string]struct{} {
	out := make(map[string]struct{}, len(values))
	for _, value := range values {
		out[value] = struct{}{}
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

func cacheRoots() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	candidates := []string{
		filepath.Join(home, ".npm"),
		filepath.Join(home, ".bun", "install", "cache"),
		filepath.Join(home, ".cache", "pip"),
		filepath.Join(home, "Library", "pnpm"),
		filepath.Join(home, "Library", "Caches", "pnpm"),
		filepath.Join(home, ".pnpm-store"),
	}
	return existingDirs(candidates)
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

func walkRoot(root string, opts options, findings *[]finding, counts *counters) {
	visited := make(map[string]struct{})
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		if d.IsDir() {
			if shouldSkipDir(name, path, opts) {
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
			scanFile(path, opts, findings, counts)
		}
		return nil
	})
}

func shouldSkipDir(name, path string, opts options) bool {
	if _, ok := skipDirs[name]; ok {
		return true
	}
	if !opts.includeNodeModules && name == "node_modules" {
		return true
	}
	if !opts.includeNodeModules && strings.Contains(path, string(filepath.Separator)+"node_modules"+string(filepath.Separator)) {
		return true
	}
	return false
}

func scanFile(path string, opts options, findings *[]finding, counts *counters) {
	counts.FilesSeen++
	base := filepath.Base(path)
	if _, ok := payloadNames[base]; ok {
		addFinding(findings, "critical", "payload-filename", path, base)
	}

	if !shouldReadFile(path, base) {
		return
	}
	info, err := os.Stat(path)
	if err != nil || info.Size() > opts.maxBytes {
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	counts.FilesScanned++

	switch base {
	case "package.json":
		scanPackageJSON(path, data, findings)
	case "package-lock.json", "npm-shrinkwrap.json":
		scanPackageLock(path, data, findings)
	default:
		scanText(path, string(data), findings)
	}
}

func shouldReadFile(path, base string) bool {
	if _, ok := scanFileNames[base]; ok {
		return true
	}
	if strings.HasSuffix(base, ".lock") {
		return true
	}
	if _, ok := payloadNames[base]; ok {
		return true
	}
	return strings.Contains(path, string(filepath.Separator)+".bun"+string(filepath.Separator)) ||
		strings.Contains(path, string(filepath.Separator)+".npm"+string(filepath.Separator)) ||
		strings.Contains(path, string(filepath.Separator)+"pip"+string(filepath.Separator))
}

func scanPackageJSON(path string, data []byte, findings *[]finding) {
	var doc struct {
		Name                 string            `json:"name"`
		Version              string            `json:"version"`
		Dependencies         map[string]string `json:"dependencies"`
		DevDependencies      map[string]string `json:"devDependencies"`
		OptionalDependencies map[string]string `json:"optionalDependencies"`
		PeerDependencies     map[string]string `json:"peerDependencies"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		scanText(path, string(data), findings)
		return
	}
	name := doc.Name
	if name == "" {
		name = packageNameFromNodeModulesPath(path)
	}
	checkPackageVersion(path, name, doc.Version, findings)
	for _, deps := range []map[string]string{doc.Dependencies, doc.DevDependencies, doc.OptionalDependencies, doc.PeerDependencies} {
		for depName, spec := range deps {
			if depName == "@tanstack/setup" || strings.Contains(spec, "79ac49eedf774dd4b0cfa308722bc463cfe5885c") {
				addFinding(findings, "critical", "malicious-optional-dependency", path, depName+": "+spec)
			}
			for _, version := range affectedPackages[depName] {
				if versionSpecMentions(spec, version) {
					addFinding(findings, "high", "dependency-range-includes-affected-version", path, depName+": "+spec+" includes "+version)
				}
			}
		}
	}
	scanText(path, string(data), findings)
}

func scanPackageLock(path string, data []byte, findings *[]finding) {
	var doc struct {
		Packages map[string]struct {
			Version string `json:"version"`
		} `json:"packages"`
		Dependencies map[string]struct {
			Version string `json:"version"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		scanText(path, string(data), findings)
		return
	}
	for pkgPath, meta := range doc.Packages {
		name := ""
		if strings.HasPrefix(pkgPath, "node_modules/") {
			name = packageNameFromNodeModulesPath(pkgPath)
		}
		checkPackageVersion(path, name, meta.Version, findings)
	}
	for name, meta := range doc.Dependencies {
		checkPackageVersion(path, name, meta.Version, findings)
	}
	scanText(path, string(data), findings)
}

func scanText(path, text string, findings *[]finding) {
	for _, ioc := range iocStrings {
		if strings.Contains(text, ioc) {
			addFinding(findings, "critical", "ioc-string", path, ioc)
		}
	}
	for name, versions := range affectedPackages {
		if !strings.Contains(text, name) {
			continue
		}
		for _, version := range versions {
			if textIndicatesVersion(text, name, version) {
				addFinding(findings, "critical", "affected-package-version", path, name+"@"+version)
			}
		}
	}
}

func textIndicatesVersion(text, name, version string) bool {
	tarball := regexp.QuoteMeta(packageBasename(name))
	escapedName := regexp.QuoteMeta(name)
	escapedVersion := regexp.QuoteMeta(version)
	if strings.Contains(text, name+"@"+version) || strings.Contains(text, "/"+packageBasename(name)+"-"+version) {
		return true
	}
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?m)node_modules/` + escapedName + `[^\n\r]{0,300}"version"\s*:\s*"` + escapedVersion + `"`),
		regexp.MustCompile(`(?im)(^|[\s"'=,;\[]|name\s*[:=]\s*["']?)` + escapedName + `(["']?\s*(?:==|===|=|@|version\s*[:=])\s*["']?` + escapedVersion + `)([^\w.-]|$)`),
		regexp.MustCompile(`(?i)(?:^|\n)Name:\s*` + escapedName + `\s*\nVersion:\s*` + escapedVersion + `([^\w.-]|$)`),
		regexp.MustCompile(`(?is)name\s*=\s*["']` + escapedName + `["'].{0,500}?version\s*=\s*["']` + escapedVersion + `["']`),
		regexp.MustCompile(`(?is)version\s*=\s*["']` + escapedVersion + `["'].{0,500}?name\s*=\s*["']` + escapedName + `["']`),
		regexp.MustCompile(`/` + tarball + `-` + escapedVersion + `([^\w.-]|$)`),
	}
	for _, pattern := range patterns {
		if pattern.MatchString(text) {
			return true
		}
	}
	return false
}

func checkPackageVersion(path, name, version string, findings *[]finding) {
	if name == "" || version == "" {
		return
	}
	for _, affected := range affectedPackages[name] {
		if version == affected {
			addFinding(findings, "critical", "affected-package-version", path, name+"@"+version)
			return
		}
	}
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
	return r == '.' || r == '-' || r == '_' || r == '+' || (r >= '0' && r <= '9') || (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z')
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

func packageBasename(name string) string {
	if idx := strings.LastIndex(name, "/"); idx >= 0 {
		return name[idx+1:]
	}
	return name
}

func scanProcesses(findings *[]finding) {
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
	for _, ioc := range iocStrings {
		if strings.Contains(text, ioc) {
			addFinding(findings, "critical", "process-ioc", "<process-list>", ioc)
		}
	}
}

func addFinding(findings *[]finding, severity, kind, file, detail string) {
	*findings = append(*findings, finding{
		Severity: severity,
		Type:     kind,
		File:     file,
		Detail:   detail,
	})
}

func buildReport(findings []finding, counts counters, roots []string) report {
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
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].File == findings[j].File {
			return findings[i].Detail < findings[j].Detail
		}
		return findings[i].File < findings[j].File
	})
	guidance := "No known Mini Shai-Hulud exposure indicators were found in scanned paths."
	if critical > 0 || high > 0 {
		guidance = "Treat the host as potentially compromised if installs ran on affected versions. Rotate reachable credentials and inspect audit logs."
	}
	return report{
		Vulnerable: critical > 0 || high > 0,
		Critical:   critical,
		High:       high,
		Findings:   findings,
		Counters:   counts,
		Roots:      roots,
		Guidance:   guidance,
	}
}

func printHuman(rep report, quiet bool) {
	if !quiet {
		fmt.Println("Mini Shai-Hulud exposure scanner")
		fmt.Printf("Scanned files: %d text files (%d seen)\n", rep.Counters.FilesScanned, rep.Counters.FilesSeen)
		fmt.Printf("Roots: %s\n\n", strings.Join(rep.Roots, ", "))
	}
	if len(rep.Findings) == 0 {
		fmt.Println("Status: CLEAN - no known indicators found.")
		return
	}
	fmt.Println("Status: EXPOSED - indicators found.")
	for _, f := range rep.Findings {
		fmt.Printf("[%s] %s: %s :: %s\n", f.Severity, f.Type, f.File, f.Detail)
	}
	fmt.Println()
	fmt.Println(rep.Guidance)
}
