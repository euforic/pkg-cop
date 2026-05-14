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
	Packages         []Package `yaml:"packages"`
	IOCStrings       []string  `yaml:"ioc_strings"`
	PayloadFilenames []string  `yaml:"payload_filenames"`
	ScanFilenames    []string  `yaml:"scan_filenames"`
}

type Package struct {
	Name     string   `yaml:"name"`
	Versions []string `yaml:"versions"`
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
	if len(c.Packages) == 0 && len(c.IOCStrings) == 0 && len(c.PayloadFilenames) == 0 {
		return fmt.Errorf("config %s has no indicators", source)
	}
	for _, pkg := range c.Packages {
		if strings.TrimSpace(pkg.Name) == "" || len(pkg.Versions) == 0 {
			return fmt.Errorf("config %s has package entry with missing name or versions", source)
		}
	}
	return nil
}
