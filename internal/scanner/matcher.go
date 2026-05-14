package scanner

import (
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/Masterminds/semver/v3"
	"github.com/euforic/pkg-cop/internal/config"
)

type packageIndicator struct {
	name   string
	specs  []versionSpec
	shapes []textShape
}

type versionSpec struct {
	raw        string
	kind       string
	constraint *semver.Constraints
	glob       string
}

type textShape struct {
	nameRegex *regexp.Regexp
	extract   *regexp.Regexp
}

type textMatch struct {
	name    string
	version string
}

func buildPackageIndicators(packages []config.Package, ecosystem Ecosystem) map[string]packageIndicator {
	out := make(map[string]packageIndicator, len(packages))
	for _, pkg := range packages {
		indicator := out[pkg.Name]
		if indicator.name == "" {
			indicator.name = pkg.Name
			indicator.shapes = newTextShapes(pkg.Name, ecosystem)
		}
		for _, version := range pkg.Versions {
			indicator.specs = append(indicator.specs, newVersionSpec(version))
		}
		for _, pattern := range pkg.VersionPatterns {
			indicator.specs = append(indicator.specs, newPatternSpec(pattern))
		}
		for _, versionRange := range pkg.VersionRanges {
			indicator.specs = append(indicator.specs, newRangeSpec(versionRange))
		}
		out[pkg.Name] = indicator
	}
	return out
}

func mergePackageIndicators(dst map[string]packageIndicator, src map[string]packageIndicator) map[string]packageIndicator {
	if dst == nil {
		dst = make(map[string]packageIndicator, len(src))
	}
	for name, incoming := range src {
		existing := dst[name]
		if existing.name == "" {
			dst[name] = incoming
			continue
		}
		existing.specs = append(existing.specs, incoming.specs...)
		dst[name] = existing
	}
	return dst
}

func newVersionSpec(value string) versionSpec {
	if looksLikeRange(value) {
		return newRangeSpec(value)
	}
	if looksLikePattern(value) {
		return newPatternSpec(value)
	}
	return newExactSpec(value)
}

func newExactSpec(version string) versionSpec {
	return versionSpec{raw: version, kind: "exact"}
}

func newPatternSpec(pattern string) versionSpec {
	return versionSpec{raw: pattern, kind: "pattern", glob: normalizeGlob(pattern)}
}

func newRangeSpec(versionRange string) versionSpec {
	constraint, err := semver.NewConstraint(normalizeConstraint(versionRange))
	if err != nil {
		return versionSpec{raw: versionRange, kind: "range"}
	}
	return versionSpec{raw: versionRange, kind: "range", constraint: constraint}
}

func newTextShapes(name string, ecosystem Ecosystem) []textShape {
	escapedName := regexp.QuoteMeta(name)
	tarball := regexp.QuoteMeta(packageBasename(name))
	all := []textShape{
		{extract: regexp.MustCompile(`(?m)` + escapedName + `@([A-Za-z0-9][A-Za-z0-9.+_-]*)`)},
		{extract: regexp.MustCompile(`(?m)/` + tarball + `-([A-Za-z0-9][A-Za-z0-9.+_-]*)(?:[^\w.-]|$)`)},
	}
	switch ecosystem {
	case EcosystemNPM:
		return append(all,
			textShape{extract: regexp.MustCompile(`(?m)node_modules/` + escapedName + `[^\n\r]{0,300}"version"\s*:\s*"([^"]+)"`)},
			textShape{extract: regexp.MustCompile(`(?im)(?:^|[\s"'=,;\[]|name\s*[:=]\s*["']?)` + escapedName + `["']?\s*(?:==|===|=|@|version\s*[:=])\s*["']?([A-Za-z0-9][A-Za-z0-9.+_-]*)(?:[^\w.-]|$)`)},
		)
	case EcosystemPyPI:
		return append(all,
			textShape{extract: regexp.MustCompile(`(?im)(?:^|[\s"'=,;\[]|name\s*[:=]\s*["']?)` + escapedName + `["']?\s*(?:==|===|=|@|version\s*[:=])\s*["']?([A-Za-z0-9][A-Za-z0-9.+_-]*)(?:[^\w.-]|$)`)},
			textShape{nameRegex: regexp.MustCompile(`(?im)(?:^|\n)Name:\s*` + escapedName + `\s*\nVersion:\s*([A-Za-z0-9][A-Za-z0-9.+_-]*)`)},
			textShape{nameRegex: regexp.MustCompile(`(?is)name\s*=\s*["']` + escapedName + `["'].{0,500}?version\s*=\s*["']([^"']+)["']`)},
			textShape{nameRegex: regexp.MustCompile(`(?is)version\s*=\s*["']([^"']+)["'].{0,500}?name\s*=\s*["']` + escapedName + `["']`)},
		)
	case EcosystemGo:
		return append(all,
			textShape{extract: regexp.MustCompile(`(?m)^\s*` + escapedName + `\s+([A-Za-z0-9][A-Za-z0-9.+_-]*)(?:\s|/|$)`)},
			textShape{extract: regexp.MustCompile(`(?m)^\s*require\s+` + escapedName + `\s+([A-Za-z0-9][A-Za-z0-9.+_-]*)(?:\s|$)`)},
		)
	case EcosystemRust:
		return append(all,
			textShape{nameRegex: regexp.MustCompile(`(?is)name\s*=\s*["']` + escapedName + `["'].{0,500}?version\s*=\s*["']([^"']+)["']`)},
			textShape{nameRegex: regexp.MustCompile(`(?is)version\s*=\s*["']([^"']+)["'].{0,500}?name\s*=\s*["']` + escapedName + `["']`)},
			textShape{extract: regexp.MustCompile(`(?im)(?:^|[\s"'=,;\[]|name\s*[:=]\s*["']?)` + escapedName + `["']?\s*(?:==|===|=|@|version\s*[:=])\s*["']?([A-Za-z0-9][A-Za-z0-9.+_-]*)(?:[^\w.-]|$)`)},
		)
	default:
		return append(all,
			textShape{extract: regexp.MustCompile(`(?m)node_modules/` + escapedName + `[^\n\r]{0,300}"version"\s*:\s*"([^"]+)"`)},
			textShape{extract: regexp.MustCompile(`(?im)(?:^|[\s"'=,;\[]|name\s*[:=]\s*["']?)` + escapedName + `["']?\s*(?:==|===|=|@|version\s*[:=])\s*["']?([A-Za-z0-9][A-Za-z0-9.+_-]*)(?:[^\w.-]|$)`)},
			textShape{extract: regexp.MustCompile(`(?im)(?:^|\n)Name:\s*` + escapedName + `\s*\nVersion:\s*([A-Za-z0-9][A-Za-z0-9.+_-]*)`)},
			textShape{extract: regexp.MustCompile(`(?is)name\s*=\s*["']` + escapedName + `["'].{0,500}?version\s*=\s*["']([^"']+)["']`)},
			textShape{extract: regexp.MustCompile(`(?is)version\s*=\s*["']([^"']+)["'].{0,500}?name\s*=\s*["']` + escapedName + `["']`)},
			textShape{extract: regexp.MustCompile(`(?m)^\s*` + escapedName + `\s+([A-Za-z0-9][A-Za-z0-9.+_-]*)(?:\s|/|$)`)},
			textShape{extract: regexp.MustCompile(`(?m)^\s*require\s+` + escapedName + `\s+([A-Za-z0-9][A-Za-z0-9.+_-]*)(?:\s|$)`)},
		)
	}
}

func (i packageIndicator) matches(text string) []textMatch {
	var matches []textMatch
	for _, shape := range i.shapes {
		for _, submatches := range shape.findAll(text) {
			version := submatches
			if i.versionMatches(version) {
				matches = append(matches, textMatch{name: i.name, version: version})
			}
		}
	}
	return matches
}

func (s textShape) findAll(text string) []string {
	re := s.extract
	if re == nil {
		re = s.nameRegex
	}
	if re == nil {
		return nil
	}
	raw := re.FindAllStringSubmatch(text, -1)
	out := make([]string, 0, len(raw))
	for _, match := range raw {
		if len(match) < 2 {
			continue
		}
		out = append(out, match[len(match)-1])
	}
	return out
}

func normalizeGlob(pattern string) string {
	parts := strings.FieldsFunc(pattern, func(r rune) bool {
		return r == '.' || r == '-' || r == '_' || r == '+'
	})
	if !slices.ContainsFunc(parts, func(part string) bool { return part == "x" || part == "X" }) {
		return pattern
	}
	var out strings.Builder
	for i := 0; i < len(pattern); i++ {
		if (pattern[i] == 'x' || pattern[i] == 'X') && isWildcardSegment(pattern, i) {
			out.WriteByte('*')
			continue
		}
		out.WriteByte(pattern[i])
	}
	return out.String()
}

func isWildcardSegment(pattern string, i int) bool {
	before := i == 0 || isVersionDelimiter(pattern[i-1])
	after := i+1 == len(pattern) || isVersionDelimiter(pattern[i+1])
	return before && after
}

func isVersionDelimiter(b byte) bool {
	return b == '.' || b == '-' || b == '_' || b == '+'
}

func (i packageIndicator) versionMatches(version string) bool {
	for _, spec := range i.specs {
		if spec.matches(version) {
			return true
		}
	}
	return false
}

func (s versionSpec) matches(version string) bool {
	switch s.kind {
	case "exact":
		return version == s.raw
	case "pattern":
		for _, candidate := range []string{version, strings.TrimPrefix(version, "v")} {
			ok, err := filepath.Match(s.glob, candidate)
			if err == nil && ok {
				return true
			}
		}
		return false
	case "range":
		if s.constraint == nil {
			return false
		}
		parsed, err := semver.NewVersion(strings.TrimPrefix(version, "v"))
		return err == nil && s.constraint.Check(parsed)
	default:
		return false
	}
}

func (s versionSpec) mayIncludeDependencySpec(spec string) bool {
	switch s.kind {
	case "exact":
		return versionSpecMentions(spec, s.raw)
	case "pattern":
		return versionSpecMentions(spec, s.raw)
	case "range":
		constraint, err := semver.NewConstraint(normalizeConstraint(spec))
		if err != nil {
			return false
		}
		for _, probe := range rangeProbeVersions(s.raw) {
			version, err := semver.NewVersion(probe)
			if err == nil && s.constraint != nil && s.constraint.Check(version) && constraint.Check(version) {
				return true
			}
		}
		return false
	default:
		return false
	}
}

func looksLikePattern(value string) bool {
	segments := strings.FieldsFunc(value, func(r rune) bool {
		return r == '.' || r == '-' || r == '_' || r == '+'
	})
	return strings.Contains(value, "*") || slices.ContainsFunc(segments, func(segment string) bool {
		return segment == "x" || segment == "X"
	})
}

func looksLikeRange(value string) bool {
	if strings.ContainsAny(value, "<>~^") || strings.Contains(value, "||") {
		return true
	}
	return strings.Contains(value, " ")
}

func rangeProbeVersions(versionRange string) []string {
	re := regexp.MustCompile(`v?([0-9]+(?:\.[0-9]+){0,2}(?:[-+][0-9A-Za-z.-]+)?)`)
	raw := re.FindAllStringSubmatch(versionRange, -1)
	probes := make([]string, 0, len(raw))
	for _, match := range raw {
		if len(match) > 1 {
			probes = append(probes, match[1])
		}
	}
	return probes
}

func normalizeConstraint(value string) string {
	re := regexp.MustCompile(`(^|[<>=~^,\s|])v([0-9])`)
	return re.ReplaceAllString(strings.TrimSpace(value), `${1}${2}`)
}

func packageBasename(name string) string {
	if idx := strings.LastIndex(name, "/"); idx >= 0 {
		return name[idx+1:]
	}
	return name
}
