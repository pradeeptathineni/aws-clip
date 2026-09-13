// main.go - Provide the aws-clip process entry point

// Command aws-clip provides guarded profile and session operations backed by
// an installed AWS CLI v2
package main

import (
	"os"

	"github.com/pradeeptathineni/aws-clip/internal/cli"
)

// main preserves the command status returned by the CLI package
// Standard process streams remain attached for native AWS CLI behavior
func main() {
	os.Exit(cli.Main(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
