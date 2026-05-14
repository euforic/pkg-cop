package scanner

import (
	"regexp"
	"strings"

	"github.com/euforic/pkg-cop/internal/config"
)

type packageIndicator struct {
	name     string
	versions map[string]struct{}
	matchers []versionMatcher
}

type versionMatcher struct {
	version string
	detail  string
	regexps []*regexp.Regexp
	needles []string
}

func buildPackageIndicators(packages []config.Package) map[string]packageIndicator {
	out := make(map[string]packageIndicator, len(packages))
	for _, pkg := range packages {
		indicator := out[pkg.Name]
		if indicator.name == "" {
			indicator.name = pkg.Name
			indicator.versions = make(map[string]struct{}, len(pkg.Versions))
		}
		for _, version := range pkg.Versions {
			if _, exists := indicator.versions[version]; exists {
				continue
			}
			indicator.versions[version] = struct{}{}
			indicator.matchers = append(indicator.matchers, newVersionMatcher(pkg.Name, version))
		}
		out[pkg.Name] = indicator
	}
	return out
}

func newVersionMatcher(name, version string) versionMatcher {
	escapedName := regexp.QuoteMeta(name)
	escapedVersion := regexp.QuoteMeta(version)
	tarball := regexp.QuoteMeta(packageBasename(name))
	return versionMatcher{
		version: version,
		detail:  name + "@" + version,
		needles: []string{
			name + "@" + version,
			"/" + packageBasename(name) + "-" + version,
		},
		regexps: []*regexp.Regexp{
			regexp.MustCompile(`(?m)node_modules/` + escapedName + `[^\n\r]{0,300}"version"\s*:\s*"` + escapedVersion + `"`),
			regexp.MustCompile(`(?im)(^|[\s"'=,;\[]|name\s*[:=]\s*["']?)` + escapedName + `(["']?\s*(?:==|===|=|@|version\s*[:=])\s*["']?` + escapedVersion + `)([^\w.-]|$)`),
			regexp.MustCompile(`(?i)(?:^|\n)Name:\s*` + escapedName + `\s*\nVersion:\s*` + escapedVersion + `([^\w.-]|$)`),
			regexp.MustCompile(`(?is)name\s*=\s*["']` + escapedName + `["'].{0,500}?version\s*=\s*["']` + escapedVersion + `["']`),
			regexp.MustCompile(`(?is)version\s*=\s*["']` + escapedVersion + `["'].{0,500}?name\s*=\s*["']` + escapedName + `["']`),
			regexp.MustCompile(`(?m)^\s*` + escapedName + `\s+` + escapedVersion + `(?:\s|/|$)`),
			regexp.MustCompile(`(?m)^\s*require\s+` + escapedName + `\s+` + escapedVersion + `(?:\s|$)`),
			regexp.MustCompile(`/` + tarball + `-` + escapedVersion + `([^\w.-]|$)`),
		},
	}
}

func (m versionMatcher) matches(text string) bool {
	for _, needle := range m.needles {
		if strings.Contains(text, needle) {
			return true
		}
	}
	for _, pattern := range m.regexps {
		if pattern.MatchString(text) {
			return true
		}
	}
	return false
}

func packageBasename(name string) string {
	if idx := strings.LastIndex(name, "/"); idx >= 0 {
		return name[idx+1:]
	}
	return name
}
