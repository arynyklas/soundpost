// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

// soundpost-config validates a typed installation file and renders the per-node cluster
// configuration `soundpost serve --mode distributed --cluster-config` reads.
//
//	go run ./internal/config/cmd/soundpost-config validate install.yaml
//	go run ./internal/config/cmd/soundpost-config render   install.yaml --out DIR
//
// It prints only the safe summary and field names; it never reads or prints a secret.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"

	"github.com/arynyklas/soundpost/internal/config"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "soundpost-config:", err)
		os.Exit(1)
	}
}

func run(args []string, out io.Writer) error {
	if len(args) < 2 || (args[0] != "validate" && args[0] != "render") {
		return errors.New("usage: soundpost-config validate FILE | render FILE --out DIR")
	}
	raw, err := os.ReadFile(args[1])
	if err != nil {
		return errors.New("cannot read the installation file")
	}
	cfg, err := config.Parse(raw)
	if err != nil {
		return err
	}
	if err = config.Validate(cfg); err != nil {
		return err
	}
	fmt.Fprintln(out, cfg.Summary())
	fmt.Fprintln(out, config.Qualification(cfg))
	if args[0] == "validate" {
		return nil
	}
	f := flag.NewFlagSet("render", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	dir := f.String("out", "", "directory for node-<id>.json (created, mode 0700)")
	if err = f.Parse(args[2:]); err != nil || *dir == "" {
		return errors.New("render needs --out DIR")
	}
	files, err := config.NodeConfigs(cfg)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(*dir, 0o700); err != nil {
		return err
	}
	for id, content := range files {
		name := filepath.Join(*dir, "node-"+strconv.FormatUint(id, 10)+".json")
		if err = os.WriteFile(name, content, 0o600); err != nil {
			return err
		}
		fmt.Fprintln(out, "wrote", name)
	}
	return nil
}
