//go:build !(linux && amd64)

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"errors"
	"io"
	"os/exec"
	"time"
)

const dcFaultExecEnv = "SOUNDPOST_DRILL_FAULT_EXEC"

var errNoInjector = errors.New("the storage fault injector needs Linux amd64 (unprivileged seccomp user notification)")

func dcFaultExecMain() int { return 3 }

type dcDisk struct{}

type dcDiskStats struct {
	Syncs, SyncsFailed, SyncsOnGone, PathOpsDenied, DirSyncs, Renames int
}

type dcCutStats struct {
	RenamesUndone, EntriesRemoved, FilesTruncated int
	BytesLost                                     int64
}

func newDCDisk(root, shadow string) (*dcDisk, error) { return nil, errNoInjector }
func (d *dcDisk) setFailSync(bool)                   {}
func (d *dcDisk) detach(string) error                { return errNoInjector }
func (d *dcDisk) reattachOriginal(string) error      { return errNoInjector }
func (d *dcDisk) reattachBlank(string) error         { return errNoInjector }
func (d *dcDisk) discardBlank(string) error          { return errNoInjector }
func (d *dcDisk) Stats() dcDiskStats                 { return dcDiskStats{} }
func (d *dcDisk) stop()                              {}
func (d *dcDisk) PowerCut(bool) (dcCutStats, error)  { return dcCutStats{}, errNoInjector }
func dcSpawnFaulted(*dcDisk, string, []string, io.Writer) (*exec.Cmd, error) {
	return nil, errNoInjector
}
func dcKillGroup(cmd *exec.Cmd) error { return cmd.Process.Kill() }

func dcOwnGroup(*exec.Cmd) {}

func (d *dcDisk) armHold()                    {}
func (d *dcDisk) waitHeld(time.Duration) bool { return false }
