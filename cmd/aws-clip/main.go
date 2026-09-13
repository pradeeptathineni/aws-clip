// Command aws-clip provides a transparent execution boundary around AWS CLI v2.
package main

import (
	"os"

	"github.com/pradeeptathineni/aws-clip/internal/cli"
)

func main() {
	os.Exit(cli.Main(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
