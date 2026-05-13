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
)

const defaultMaxBytes int64 = 8 * 1024 * 1024

var affectedPackages = map[string][]string{
	"@beproduct/nestjs-auth":                         {"0.1.2", "0.1.3", "0.1.4", "0.1.5", "0.1.6", "0.1.7", "0.1.8", "0.1.9", "0.1.10", "0.1.11", "0.1.12", "0.1.13", "0.1.14", "0.1.15", "0.1.16", "0.1.17", "0.1.18", "0.1.19"},
	"@dirigible-ai/sdk":                              {"0.6.2", "0.6.3"},
	"@draftauth/client":                              {"0.2.1", "0.2.2"},
	"@draftauth/core":                                {"0.13.1", "0.13.2"},
	"@draftlab/auth":                                 {"0.24.1", "0.24.2"},
	"@draftlab/auth-router":                          {"0.5.1", "0.5.2"},
	"@draftlab/db":                                   {"0.16.1", "0.16.2"},
	"@mesadev/rest":                                  {"0.28.3"},
	"@mesadev/saguaro":                               {"0.4.22"},
	"@mesadev/sdk":                                   {"0.28.3"},
	"@mistralai/mistralai":                           {"2.2.2", "2.2.3", "2.2.4"},
	"@mistralai/mistralai-azure":                     {"1.7.1", "1.7.2", "1.7.3"},
	"@mistralai/mistralai-gcp":                       {"1.7.1", "1.7.2", "1.7.3"},
	"@ml-toolkit-ts/preprocessing":                   {"1.0.2", "1.0.3"},
	"@ml-toolkit-ts/xgboost":                         {"1.0.3", "1.0.4"},
	"@opensearch-project/opensearch":                 {"3.5.3", "3.6.2", "3.7.0", "3.8.0"},
	"@squawk/airport-data":                           {"0.7.4", "0.7.5", "0.7.6", "0.7.7", "0.7.8"},
	"@squawk/airports":                               {"0.6.2", "0.6.3", "0.6.4", "0.6.5", "0.6.6"},
	"@squawk/airspace":                               {"0.8.1", "0.8.2", "0.8.3", "0.8.4", "0.8.5"},
	"@squawk/airspace-data":                          {"0.5.3", "0.5.4", "0.5.5", "0.5.6", "0.5.7"},
	"@squawk/airway-data":                            {"0.5.4", "0.5.5", "0.5.6", "0.5.7", "0.5.8"},
	"@squawk/airways":                                {"0.4.2", "0.4.3", "0.4.4", "0.4.5", "0.4.6"},
	"@squawk/fix-data":                               {"0.6.4", "0.6.5", "0.6.6", "0.6.7", "0.6.8"},
	"@squawk/fixes":                                  {"0.3.2", "0.3.3", "0.3.4", "0.3.5", "0.3.6"},
	"@squawk/flight-math":                            {"0.5.4", "0.5.5", "0.5.6", "0.5.7", "0.5.8"},
	"@squawk/flightplan":                             {"0.5.2", "0.5.3", "0.5.4", "0.5.5", "0.5.6"},
	"@squawk/geo":                                    {"0.4.4", "0.4.5", "0.4.6", "0.4.7", "0.4.8"},
	"@squawk/icao-registry":                          {"0.5.2", "0.5.3", "0.5.4", "0.5.5", "0.5.6"},
	"@squawk/icao-registry-data":                     {"0.8.4", "0.8.5", "0.8.6", "0.8.7", "0.8.8"},
	"@squawk/mcp":                                    {"0.9.1", "0.9.2", "0.9.3", "0.9.4", "0.9.5"},
	"@squawk/navaid-data":                            {"0.6.4", "0.6.5", "0.6.6", "0.6.7", "0.6.8"},
	"@squawk/navaids":                                {"0.4.2", "0.4.3", "0.4.4", "0.4.5", "0.4.6"},
	"@squawk/notams":                                 {"0.3.6", "0.3.7", "0.3.8", "0.3.9", "0.3.10"},
	"@squawk/procedure-data":                         {"0.7.3", "0.7.4", "0.7.5", "0.7.6", "0.7.7"},
	"@squawk/procedures":                             {"0.5.2", "0.5.3", "0.5.4", "0.5.5", "0.5.6"},
	"@squawk/types":                                  {"0.8.1", "0.8.2", "0.8.3", "0.8.4", "0.8.5"},
	"@squawk/units":                                  {"0.4.3", "0.4.4", "0.4.5", "0.4.6", "0.4.7"},
	"@squawk/weather":                                {"0.5.6", "0.5.7", "0.5.8", "0.5.9", "0.5.10"},
	"@supersurkhet/cli":                              {"0.0.2", "0.0.3", "0.0.4", "0.0.5", "0.0.6", "0.0.7"},
	"@supersurkhet/sdk":                              {"0.0.2", "0.0.3", "0.0.4", "0.0.5", "0.0.6", "0.0.7"},
	"@tallyui/components":                            {"1.0.1", "1.0.2", "1.0.3"},
	"@tallyui/connector-medusa":                      {"1.0.1", "1.0.2", "1.0.3"},
	"@tallyui/connector-shopify":                     {"1.0.1", "1.0.2", "1.0.3"},
	"@tallyui/connector-vendure":                     {"1.0.1", "1.0.2", "1.0.3"},
	"@tallyui/connector-woocommerce":                 {"1.0.1", "1.0.2", "1.0.3"},
	"@tallyui/core":                                  {"0.2.1", "0.2.2", "0.2.3"},
	"@tallyui/database":                              {"1.0.1", "1.0.2", "1.0.3"},
	"@tallyui/pos":                                   {"0.1.1", "0.1.2", "0.1.3"},
	"@tallyui/storage-sqlite":                        {"0.2.1", "0.2.2", "0.2.3"},
	"@tallyui/theme":                                 {"0.2.1", "0.2.2", "0.2.3"},
	"@tanstack/arktype-adapter":                      {"1.166.12", "1.166.15"},
	"@tanstack/eslint-plugin-router":                 {"1.161.9", "1.161.12"},
	"@tanstack/eslint-plugin-start":                  {"0.0.4", "0.0.7"},
	"@tanstack/history":                              {"1.161.9", "1.161.12"},
	"@tanstack/nitro-v2-vite-plugin":                 {"1.154.12", "1.154.15"},
	"@tanstack/react-router":                         {"1.169.5", "1.169.8"},
	"@tanstack/react-router-devtools":                {"1.166.16", "1.166.19"},
	"@tanstack/react-router-ssr-query":               {"1.166.15", "1.166.18"},
	"@tanstack/react-start":                          {"1.167.68", "1.167.71"},
	"@tanstack/react-start-client":                   {"1.166.51", "1.166.54"},
	"@tanstack/react-start-rsc":                      {"0.0.47", "0.0.50"},
	"@tanstack/react-start-server":                   {"1.166.55", "1.166.58"},
	"@tanstack/router-cli":                           {"1.166.46", "1.166.49"},
	"@tanstack/router-core":                          {"1.169.5", "1.169.8"},
	"@tanstack/router-devtools":                      {"1.166.16", "1.166.19"},
	"@tanstack/router-devtools-core":                 {"1.167.6", "1.167.9"},
	"@tanstack/router-generator":                     {"1.166.45", "1.166.48"},
	"@tanstack/router-plugin":                        {"1.167.38", "1.167.41"},
	"@tanstack/router-ssr-query-core":                {"1.168.3", "1.168.6"},
	"@tanstack/router-utils":                         {"1.161.11", "1.161.14"},
	"@tanstack/router-vite-plugin":                   {"1.166.53", "1.166.56"},
	"@tanstack/solid-router":                         {"1.169.5", "1.169.8"},
	"@tanstack/solid-router-devtools":                {"1.166.16", "1.166.19"},
	"@tanstack/solid-router-ssr-query":               {"1.166.15", "1.166.18"},
	"@tanstack/solid-start":                          {"1.167.65", "1.167.68"},
	"@tanstack/solid-start-client":                   {"1.166.50", "1.166.53"},
	"@tanstack/solid-start-server":                   {"1.166.54", "1.166.57"},
	"@tanstack/start-client-core":                    {"1.168.5", "1.168.8"},
	"@tanstack/start-fn-stubs":                       {"1.161.9", "1.161.12"},
	"@tanstack/start-plugin-core":                    {"1.169.23", "1.169.26"},
	"@tanstack/start-server-core":                    {"1.167.33", "1.167.36"},
	"@tanstack/start-static-server-functions":        {"1.166.44", "1.166.47"},
	"@tanstack/start-storage-context":                {"1.166.38", "1.166.41"},
	"@tanstack/valibot-adapter":                      {"1.166.12", "1.166.15"},
	"@tanstack/virtual-file-routes":                  {"1.161.10", "1.161.13"},
	"@tanstack/vue-router":                           {"1.169.5", "1.169.8"},
	"@tanstack/vue-router-devtools":                  {"1.166.16", "1.166.19"},
	"@tanstack/vue-router-ssr-query":                 {"1.166.15", "1.166.18"},
	"@tanstack/vue-start":                            {"1.167.61", "1.167.64"},
	"@tanstack/vue-start-client":                     {"1.166.46", "1.166.49"},
	"@tanstack/vue-start-server":                     {"1.166.50", "1.166.53"},
	"@tanstack/zod-adapter":                          {"1.166.12", "1.166.15"},
	"@taskflow-corp/cli":                             {"0.1.24", "0.1.25", "0.1.26", "0.1.27", "0.1.28", "0.1.29"},
	"@tolka/cli":                                     {"1.0.2", "1.0.3", "1.0.4", "1.0.5", "1.0.6"},
	"@uipath/access-policy-sdk":                      {"0.3.1"},
	"@uipath/access-policy-tool":                     {"0.3.1"},
	"@uipath/admin-tool":                             {"0.1.1"},
	"@uipath/agent-sdk":                              {"1.0.2"},
	"@uipath/agent-tool":                             {"1.0.1"},
	"@uipath/agent.sdk":                              {"0.0.18"},
	"@uipath/aops-policy-tool":                       {"0.3.1"},
	"@uipath/ap-chat":                                {"1.5.7"},
	"@uipath/api-workflow-tool":                      {"1.0.1"},
	"@uipath/apollo-core":                            {"5.9.2"},
	"@uipath/apollo-react":                           {"4.24.5"},
	"@uipath/apollo-wind":                            {"2.16.2"},
	"@uipath/auth":                                   {"1.0.1"},
	"@uipath/case-tool":                              {"1.0.1"},
	"@uipath/cli":                                    {"1.0.1"},
	"@uipath/codedagent-tool":                        {"1.0.1"},
	"@uipath/codedagents-tool":                       {"0.1.12"},
	"@uipath/codedapp-tool":                          {"1.0.1"},
	"@uipath/common":                                 {"1.0.1"},
	"@uipath/context-grounding-tool":                 {"0.1.1"},
	"@uipath/data-fabric-tool":                       {"1.0.2"},
	"@uipath/docsai-tool":                            {"1.0.1"},
	"@uipath/filesystem":                             {"1.0.1"},
	"@uipath/flow-tool":                              {"1.0.2"},
	"@uipath/functions-tool":                         {"1.0.1"},
	"@uipath/gov-tool":                               {"0.3.1"},
	"@uipath/identity-tool":                          {"0.1.1"},
	"@uipath/insights-sdk":                           {"1.0.1"},
	"@uipath/insights-tool":                          {"1.0.1"},
	"@uipath/integrationservice-sdk":                 {"1.0.2"},
	"@uipath/integrationservice-tool":                {"1.0.2"},
	"@uipath/llmgw-tool":                             {"1.0.1"},
	"@uipath/maestro-sdk":                            {"1.0.1"},
	"@uipath/maestro-tool":                           {"1.0.1"},
	"@uipath/orchestrator-tool":                      {"1.0.1"},
	"@uipath/packager-tool-apiworkflow":              {"0.0.19"},
	"@uipath/packager-tool-bpmn":                     {"0.0.9"},
	"@uipath/packager-tool-case":                     {"0.0.9"},
	"@uipath/packager-tool-connector":                {"0.0.19"},
	"@uipath/packager-tool-flow":                     {"0.0.19"},
	"@uipath/packager-tool-functions":                {"0.1.1"},
	"@uipath/packager-tool-webapp":                   {"1.0.6"},
	"@uipath/packager-tool-workflowcompiler":         {"0.0.16"},
	"@uipath/packager-tool-workflowcompiler-browser": {"0.0.34"},
	"@uipath/platform-tool":                          {"1.0.1"},
	"@uipath/project-packager":                       {"1.1.16"},
	"@uipath/resource-tool":                          {"1.0.1"},
	"@uipath/resourcecatalog-tool":                   {"0.1.1"},
	"@uipath/resources-tool":                         {"0.1.11"},
	"@uipath/robot":                                  {"1.3.4"},
	"@uipath/rpa-legacy-tool":                        {"1.0.1"},
	"@uipath/rpa-tool":                               {"0.9.5"},
	"@uipath/solution-packager":                      {"0.0.35"},
	"@uipath/solution-tool":                          {"1.0.1"},
	"@uipath/solutionpackager-sdk":                   {"1.0.11"},
	"@uipath/solutionpackager-tool-core":             {"0.0.34"},
	"@uipath/tasks-tool":                             {"1.0.1"},
	"@uipath/telemetry":                              {"0.0.7"},
	"@uipath/test-manager-tool":                      {"1.0.2"},
	"@uipath/tool-workflowcompiler":                  {"0.0.12"},
	"@uipath/traces-tool":                            {"1.0.1"},
	"@uipath/ui-widgets-multi-file-upload":           {"1.0.1"},
	"@uipath/uipath-python-bridge":                   {"1.0.1"},
	"@uipath/vertical-solutions-tool":                {"1.0.1"},
	"@uipath/vss":                                    {"0.1.6"},
	"@uipath/widget.sdk":                             {"1.2.3"},
	"agentwork-cli":                                  {"0.1.4", "0.1.5"},
	"cmux-agent-mcp":                                 {"0.1.3", "0.1.4", "0.1.5", "0.1.6", "0.1.7", "0.1.8"},
	"cross-stitch":                                   {"1.1.3", "1.1.4", "1.1.5", "1.1.6", "1.1.7"},
	"git-branch-selector":                            {"1.3.3", "1.3.4", "1.3.5", "1.3.6", "1.3.7"},
	"git-git-git":                                    {"1.0.8", "1.0.9", "1.0.10", "1.0.11", "1.0.12"},
	"guardrails-ai":                                  {"0.10.1"},
	"mistralai":                                      {"2.4.6"},
	"ml-toolkit-ts":                                  {"1.0.4", "1.0.5"},
	"nextmove-mcp":                                   {"0.1.3", "0.1.4", "0.1.5", "0.1.6", "0.1.7"},
	"safe-action":                                    {"0.8.3", "0.8.4"},
	"ts-dna":                                         {"3.0.1", "3.0.2", "3.0.3", "3.0.4", "3.0.5"},
	"wot-api":                                        {"0.8.1", "0.8.2", "0.8.3", "0.8.4"},
}

var iocStrings = []string{
	"@tanstack/setup",
	"github:tanstack/router#79ac49eedf774dd4b0cfa308722bc463cfe5885c",
	"79ac49eedf774dd4b0cfa308722bc463cfe5885c",
	"router_init.js",
	"router_runtime.js",
	"tanstack_runner.js",
	"bun run tanstack_runner.js",
	"filev2.getsession.org",
	"seed1.getsession.org",
	"seed2.getsession.org",
	"seed3.getsession.org",
	"litter.catbox.moe/h8nc9u.js",
	"litter.catbox.moe/7rrc6l.mjs",
	"git-tanstack.com",
	"83.142.209.194/transformers.pyz",
	"transformers.pyz",
	"Shai-Hulud: Here We Go Again",
	"IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner",
	"gh-token-monitor",
	"com.user.gh-token-monitor.plist",
	"gh-token-monitor.service",
	"Linux-pnpm-store-6f9233a50def742c09fde54f56553d6b449a535adf87d4083690539f49ae4da11",
}

var payloadNames = setOf(
	"router_init.js",
	"router_runtime.js",
	"tanstack_runner.js",
	"vite_setup.mjs",
	"setup.mjs",
	"transformers.pyz",
	"com.user.gh-token-monitor.plist",
	"gh-token-monitor.service",
)

var scanFileNames = setOf(
	"package.json",
	"package-lock.json",
	"npm-shrinkwrap.json",
	"pnpm-lock.yaml",
	"yarn.lock",
	"bun.lock",
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
)

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
  -max-bytes N            Maximum text file size to inspect. Default: 8388608.
  -h, -help               Show this help.

Exit codes:
  0  No indicators found.
  1  One or more exposure indicators found.
  2  Scanner error.`)
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
