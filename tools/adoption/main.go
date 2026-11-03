// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

func inside(path, root string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && (rel == "." || rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel))
}
func privateDirectory(ctx context.Context, dir string, roots []string, acl bool) (string, error) {
	resolved, err := canonical(dir)
	if err != nil {
		return "", errors.New("private directory must already exist")
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.IsDir() {
		return "", errors.New("invalid private directory")
	}
	if runtime.GOOS == "windows" {
		if !acl {
			return "", errors.New("verified restrictive private directory ACL required")
		}
	} else if info.Mode().Perm()&0077 != 0 {
		return "", errors.New("private directory must deny group and other access")
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	roots = append(append([]string{}, roots...), cwd)
	for _, root := range roots {
		r, err := canonical(root)
		if err != nil {
			return "", errors.New("cannot resolve repository root")
		}
		if inside(resolved, r) {
			return "", errors.New("private output cannot be inside repository")
		}
		// Worktree metadata is read locally; no remote discovery or shell execution.
		cmd := exec.CommandContext(ctx, "git", "--no-optional-locks", "-C", r, "worktree", "list", "--porcelain")
		cmd.Env = cleanGitEnvironment()
		out, err := cmd.Output()
		if err != nil {
			return "", errors.New("cannot verify repository worktrees; valid local Git context required")
		}
		for _, line := range strings.Split(string(out), "\n") {
			if strings.HasPrefix(line, "worktree ") {
				worktree, err := canonical(strings.TrimPrefix(line, "worktree "))
				if err != nil {
					return "", errors.New("cannot resolve public worktree")
				}
				if inside(resolved, worktree) {
					return "", errors.New("private output cannot be inside worktree")
				}
			}
		}
	}
	for p := resolved; ; p = filepath.Dir(p) {
		if _, err := os.Lstat(filepath.Join(p, ".git")); err == nil {
			return "", errors.New("private output cannot be in a Git checkout")
		}
		if filepath.Dir(p) == p {
			break
		}
	}
	return resolved, nil
}
func cleanGitEnvironment() []string {
	env := []string{}
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(strings.ToUpper(kv), "GIT_") {
			env = append(env, kv)
		}
	}
	return env
}
func writeExclusive(path string, value any) error {
	b, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		f.Close()
		if !ok {
			os.Remove(path)
		}
	}()
	if _, err = f.Write(append(b, '\n')); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	ok = true
	return nil
}
func writePrivate(ctx context.Context, dir string, roots []string, acl bool, intake PrivateIntake) error {
	resolved, err := privateDirectory(ctx, dir, roots, acl)
	if err != nil {
		return err
	}
	return writeExclusive(filepath.Join(resolved, "intake.json"), intake)
}
func readInput(path string, value any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return decodeStrict(f, value)
}
func run(ctx context.Context, args []string) error {
	if len(args) == 0 || args[0] != "intake" {
		return errors.New("usage: adoption intake --targets FILE --authorization FILE --private-output DIRECTORY --public-summary FILE")
	}
	fs := flag.NewFlagSet("intake", flag.ContinueOnError)
	targetsPath := fs.String("targets", "", "private targets JSON")
	grantPath := fs.String("authorization", "", "private grant JSON")
	output := fs.String("private-output", "", "external private directory")
	summaryPath := fs.String("public-summary", "", "new public summary file")
	acl := fs.Bool("private-directory-acl-confirmed", false, "operator verified restrictive NTFS ACL")
	timeout := fs.Duration("timeout", 2*time.Minute, "overall operator deadline (positive, at most 1h)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 || !nonempty(*targetsPath, *grantPath, *output, *summaryPath) {
		return errors.New("all intake paths required")
	}
	if *timeout <= 0 || *timeout > time.Hour {
		return errors.New("timeout must be positive and at most 1h")
	}
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	var targets ReadOnlyTargets
	var grant Authorization
	if readInput(*targetsPath, &targets) != nil || readInput(*grantPath, &grant) != nil {
		return errors.New("invalid private operator input")
	}
	roots := []string{}
	for _, t := range targets.Targets {
		roots = append(roots, t.Repository)
	}
	if _, err := privateDirectory(ctx, *output, roots, *acl); err != nil {
		return err
	}
	intake, err := CollectIntake(ctx, targets, grant)
	if err != nil {
		return err
	}
	summary, err := PublicSummary(intake)
	if err != nil {
		return err
	}
	if ctx.Err() != nil {
		return errors.New("intake cancelled or deadline exceeded")
	}
	if err := writePrivate(ctx, *output, roots, *acl, intake); err != nil {
		return errors.New("private output creation failed")
	}
	if err := writeExclusive(*summaryPath, summary); err != nil {
		return errors.New("summary creation failed; private evidence retained")
	}
	return nil
}
func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
