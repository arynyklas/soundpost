// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

// soundpost-config validates a typed installation file and renders the per-node cluster
// configuration `soundpost serve --mode distributed --cluster-config` reads.
//
//	go run ./internal/config/cmd/soundpost-config validate install.yaml
//	go run ./internal/config/cmd/soundpost-config render   install.yaml --out DIR
//	go run ./internal/config/cmd/soundpost-config check    install.yaml
//
// check is the only command that may name an off-host backup deletion-safe: it opens the
// configured authority store with the restricted keys and requires conditional create and a
// fresh verified head (config.BackupChecker); any other outcome exits non-zero with the reason.
// validate and render state that the label is unverified until check passes.
//
// It prints only the safe summary and field names and never prints a secret; check reads the
// referenced credentials and key file only to open the authority store.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/arynyklas/soundpost/internal/config"
	"github.com/arynyklas/soundpost/internal/model"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "soundpost-config:", err)
		os.Exit(1)
	}
}

func run(args []string, out io.Writer) error {
	return runAt(args, out, time.Now)
}

func runAt(args []string, out io.Writer, now func() time.Time) error {
	if len(args) < 2 || (args[0] != "validate" && args[0] != "render" && args[0] != "check") {
		return errors.New("usage: soundpost-config validate FILE | render FILE --out DIR | check FILE")
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
	if args[0] == "check" {
		return checkBackup(cfg, out, now)
	}
	if cfg.Backup.Mode == config.BackupOffhost {
		fmt.Fprintln(out, "backup label: unverified (run `check`: only a passing authority check may call an off-host backup deletion-safe)")
	}
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

// checkBackup prints the label an operator may show for the configured backup, and fails unless
// the configuration can be used as configured (an off-host backup needs a passing authority check).
func checkBackup(cfg config.InstallConfig, out io.Writer, now func() time.Time) error {
	checker, err := config.OpenBackupChecker(cfg, now)
	if err != nil {
		return errors.New("backup authority cannot be opened: " + safeOpenError(err))
	}
	status, err := checker.Check(context.Background(), cfg)
	var notReady *config.NotReadyError
	if errors.As(err, &notReady) {
		fmt.Fprintf(out, "backup label: %s\n", status.Label)
		return fmt.Errorf("backup authority not ready: %s", notReady.Reason)
	}
	if err != nil {
		return errors.New("backup check failed")
	}
	if status.Label == config.LabelDeletionSafeDisasterBackup {
		fmt.Fprintf(out, "backup label: %s (authority %s sequence %d generation %d)\n", status.Label, status.Head.Authority, status.Head.Sequence, status.Head.Generation)
	} else {
		fmt.Fprintf(out, "backup label: %s\n", status.Label)
	}
	return nil
}

// safeOpenError keeps only the closed part of an open failure: store errors can name endpoints
// and paths.
func safeOpenError(err error) string {
	var fault *model.Fault
	if errors.As(err, &fault) {
		return string(fault.Code)
	}
	return "see the secret and key references"
}
