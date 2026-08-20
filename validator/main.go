package main

import (
	"fmt"
	"os"

	tinfoilconfig "github.com/tinfoilsh/tinfoil-config"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "usage: %s CONFIG.yml\n", os.Args[0])
		os.Exit(2)
	}
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "read config: %v\n", err)
		os.Exit(1)
	}
	if err := tinfoilconfig.ValidateBytes(data, tinfoilconfig.Options{}); err != nil {
		fmt.Fprintf(os.Stderr, "invalid tinfoil config: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("validated tinfoil config: %s\n", os.Args[1])
}
