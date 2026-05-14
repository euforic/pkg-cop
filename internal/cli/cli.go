package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/euforic/pkg-cop/internal/config"
	"github.com/euforic/pkg-cop/internal/scanner"
)

type Options struct {
	Roots              []string
	JSONOutput         bool
	Quiet              bool
	IncludeNodeModules bool
	ScanCaches         bool
	ScanPython         bool
	ScanProcesses      bool
	MaxBytes           int64
	ConfigPath         string
}

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

type ExitError struct {
	Code    int
	Message string
}

func (e ExitError) Error() string {
	return e.Message
}

func Run(_ context.Context, args []string, stdout, stderr io.Writer) error {
	opts, err := Parse(args, stdout)
	if err != nil {
		return ExitError{Code: 2, Message: err.Error()}
	}
	cfg, err := config.Load(opts.ConfigPath)
	if err != nil {
		return ExitError{Code: 2, Message: err.Error()}
	}
	scan := scanner.New(cfg)
	rep := scan.Run(scanner.Options{
		Roots:              opts.Roots,
		IncludeNodeModules: opts.IncludeNodeModules,
		ScanCaches:         opts.ScanCaches,
		ScanPython:         opts.ScanPython,
		ScanProcesses:      opts.ScanProcesses,
		MaxBytes:           opts.MaxBytes,
	})
	if opts.JSONOutput {
		encoded, err := json.MarshalIndent(rep, "", "  ")
		if err != nil {
			return ExitError{Code: 2, Message: err.Error()}
		}
		if _, err := fmt.Fprintln(stdout, string(encoded)); err != nil {
			return ExitError{Code: 2, Message: err.Error()}
		}
	} else {
		if _, err := fmt.Fprint(stdout, scanner.FormatHuman(rep, opts.Quiet)); err != nil {
			return ExitError{Code: 2, Message: err.Error()}
		}
	}
	if rep.Vulnerable {
		return ExitError{Code: 1}
	}
	_ = stderr
	return nil
}

func Parse(args []string, output io.Writer) (Options, error) {
	opts := Options{
		IncludeNodeModules: true,
		ScanCaches:         true,
		ScanPython:         true,
		ScanProcesses:      true,
		MaxBytes:           scanner.DefaultMaxBytes,
	}
	var roots stringList
	fs := flag.NewFlagSet("pkg-cop", flag.ContinueOnError)
	fs.SetOutput(output)
	fs.Var(&roots, "root", "Add a root to scan. Positional paths also work.")
	fs.BoolVar(&opts.JSONOutput, "json", false, "Emit machine-readable JSON.")
	fs.BoolVar(&opts.Quiet, "quiet", false, "Only print findings and final status.")
	fs.BoolVar(&opts.IncludeNodeModules, "include-node-modules", true, "Scan node_modules directories.")
	fs.BoolFunc("skip-node-modules", "Do not scan node_modules directories.", func(string) error {
		opts.IncludeNodeModules = false
		return nil
	})
	fs.BoolFunc("no-caches", "Do not add npm/Bun/pnpm/pip cache paths.", func(string) error {
		opts.ScanCaches = false
		return nil
	})
	fs.BoolFunc("no-python", "Do not add Python site-package roots.", func(string) error {
		opts.ScanPython = false
		return nil
	})
	fs.BoolFunc("no-processes", "Do not inspect running process command lines.", func(string) error {
		opts.ScanProcesses = false
		return nil
	})
	fs.Int64Var(&opts.MaxBytes, "max-bytes", scanner.DefaultMaxBytes, "Maximum text file size to inspect.")
	fs.StringVar(&opts.ConfigPath, "config", "", "YAML indicator config path. Defaults to ./config.yaml or config.yaml next to the executable.")
	fs.Usage = func() { printUsage(output) }

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		return opts, err
	}
	opts.Roots = append(opts.Roots, roots...)
	opts.Roots = append(opts.Roots, fs.Args()...)
	if len(opts.Roots) == 0 {
		cwd, err := os.Getwd()
		if err != nil {
			return opts, err
		}
		opts.Roots = []string{cwd}
	}
	for i, root := range opts.Roots {
		abs, err := filepath.Abs(root)
		if err == nil {
			opts.Roots[i] = abs
		}
	}
	return opts, nil
}

func printUsage(out io.Writer) {
	_, _ = fmt.Fprintln(out, `Pkg Cop

Usage:
  pkg-cop [roots...] [options]

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
