package main

import (
	"fmt"
	"os"

	"github.com/yourorg/janus/internal/verification"
)

func main() {
	if err := verification.RunVerifierCLI(os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}
