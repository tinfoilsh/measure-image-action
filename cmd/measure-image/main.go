package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/tinfoilsh/measure-image-action/internal/orchestrator"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := orchestrator.DefaultRunner().Run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "measure image: %v\n", err)
		os.Exit(1)
	}
}
