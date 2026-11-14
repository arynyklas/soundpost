// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

// soundpost-agent collects policy-approved host metrics and system logs and
// submits them to a Soundpost installation over HTTPS. It is not required to
// run the server, accepts no remote commands and reads no command lines or
// process environments.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/arynyklas/soundpost/internal/agent"
)

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	flags := flag.NewFlagSet("soundpost-agent", flag.ContinueOnError)
	configPath := flags.String("config", "", "path of the agent configuration file (JSON)")
	once := flags.Bool("once", false, "run one collection cycle and exit non-zero if any component failed")
	validate := flags.Bool("validate", false, "validate the configuration and exit")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *configPath == "" {
		fmt.Fprintln(os.Stderr, "soundpost-agent: -config is required")
		return 2
	}
	cfg, err := agent.LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if *validate {
		return 0
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	a, err := agent.New(cfg, log)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *once {
		if a.Cycle(ctx).Failed() {
			return 1
		}
		return 0
	}
	if err := a.Run(ctx); err != nil {
		return 1
	}
	return 0
}
