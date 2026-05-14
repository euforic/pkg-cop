package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/euforic/pkg-cop/internal/cli"
)

func main() {
	if err := cli.Run(context.Background(), os.Args[1:], os.Stdout, os.Stderr); err != nil {
		var exitErr cli.ExitError
		if errors.As(err, &exitErr) {
			if exitErr.Message != "" {
				fmt.Fprintln(os.Stderr, exitErr.Message)
			}
			os.Exit(exitErr.Code)
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}
