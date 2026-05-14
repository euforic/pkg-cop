package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Packages         []Package                  `yaml:"packages"`
	Ecosystems       map[string]EcosystemConfig `yaml:"ecosystems"`
	IOCStrings       []string                   `yaml:"ioc_strings"`
	PayloadFilenames []string                   `yaml:"payload_filenames"`
	ScanFilenames    []string                   `yaml:"scan_filenames"`
}

type Package struct {
	Name            string   `yaml:"name"`
	Versions        []string `yaml:"versions"`
	VersionPatterns []string `yaml:"version_patterns"`
	VersionRanges   []string `yaml:"version_ranges"`
}

type EcosystemConfig struct {
	Packages      []Package `yaml:"packages"`
	ScanFilenames []string  `yaml:"scan_filenames"`
}

func Load(path string) (Config, error) {
	resolved, err := ResolvePath(path)
	if err != nil {
		return Config{}, err
	}
	data, err := os.ReadFile(resolved)
	if err != nil {
		return Config{}, fmt.Errorf("read config %s: %w", resolved, err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config %s: %w", resolved, err)
	}
	if err := cfg.Validate(resolved); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func ResolvePath(path string) (string, error) {
	candidates := []string{}
	if path != "" {
		candidates = append(candidates, path)
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
	if path != "" {
		return "", fmt.Errorf("config file not found: %s", path)
	}
	return "", errors.New("config file not found: pass -config or place config.yaml in the working directory")
}

func (c Config) Validate(source string) error {
	if len(c.Packages) == 0 && len(c.Ecosystems) == 0 && len(c.IOCStrings) == 0 && len(c.PayloadFilenames) == 0 {
		return fmt.Errorf("config %s has no indicators", source)
	}
	for _, pkg := range c.Packages {
		if err := validatePackage(source, pkg); err != nil {
			return err
		}
	}
	for ecosystem, cfg := range c.Ecosystems {
		ecosystem = strings.ToLower(strings.TrimSpace(ecosystem))
		if ecosystem == "" {
			return fmt.Errorf("config %s has ecosystem entry with missing name", source)
		}
		if !isSupportedEcosystem(ecosystem) {
			return fmt.Errorf("config %s has unsupported ecosystem %q", source, ecosystem)
		}
		for _, pkg := range cfg.Packages {
			if err := validatePackage(source, pkg); err != nil {
				return err
			}
		}
	}
	return nil
}

func isSupportedEcosystem(ecosystem string) bool {
	switch ecosystem {
	case "generic", "npm", "pypi", "go", "rust":
		return true
	default:
		return false
	}
}

func validatePackage(source string, pkg Package) error {
	if strings.TrimSpace(pkg.Name) == "" {
		return fmt.Errorf("config %s has package entry with missing name", source)
	}
	if len(pkg.Versions) == 0 && len(pkg.VersionPatterns) == 0 && len(pkg.VersionRanges) == 0 {
		return fmt.Errorf("config %s has package %s with no versions, version_patterns, or version_ranges", source, pkg.Name)
	}
	return nil
}
