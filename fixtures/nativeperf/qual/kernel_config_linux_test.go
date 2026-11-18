//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package qual

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

const sampleKernelConfig = "# Automatically generated file\nCONFIG_PERF_EVENTS=y\n# CONFIG_FRAME_POINTER is not set\nCONFIG_FTRACE=y\nCONFIG_UNWINDER_ORC=y\n"

func digest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// A Debian or Ubuntu kernel does not export /proc/config.gz; its configuration is /boot/config-<release>.
// The 6.1 and 6.6 qualification hosts are exactly that, so a report from them must still carry the digest of the
// configuration the kernel was built with (the plan's "exact uname/build and config digest" evidence).
func TestKernelConfigFallsBackToTheBootConfigOfTheRunningRelease(t *testing.T) {
	dir := t.TempDir()
	boot := filepath.Join(dir, "config-6.1.0-54-amd64")
	if err := os.WriteFile(boot, []byte(sampleKernelConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	got := readKernelConfig([]string{filepath.Join(dir, "no-proc-config.gz"), boot})
	if got.Source != boot || got.SHA256 != digest([]byte(sampleKernelConfig)) {
		t.Fatalf("source %q sha %q, want the boot config and its digest", got.Source, got.SHA256)
	}
	if got.PerfEvents != "y" || got.Ftrace != "y" {
		t.Fatalf("perf %q ftrace %q, want y y", got.PerfEvents, got.Ftrace)
	}
	if got.FramePointer != "" {
		t.Fatalf("frame pointer %q: an unset option must stay empty, not be invented", got.FramePointer)
	}
}

func TestKernelConfigPrefersTheKernelsOwnExportAndReadsItCompressed(t *testing.T) {
	dir := t.TempDir()
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write([]byte("CONFIG_PERF_EVENTS=y\nCONFIG_FRAME_POINTER=y\nCONFIG_FTRACE=y\n"))
	_ = zw.Close()
	proc := filepath.Join(dir, "config.gz")
	boot := filepath.Join(dir, "config-6.6.162")
	if err := os.WriteFile(proc, gz.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(boot, []byte(sampleKernelConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	got := readKernelConfig([]string{proc, boot})
	if got.Source != proc || got.SHA256 != digest(gz.Bytes()) || got.FramePointer != "y" {
		t.Fatalf("got %+v, want the compressed export read through gzip", got)
	}
}

func TestKernelConfigUnavailableNamesTheErrnoOfTheFirstCandidate(t *testing.T) {
	dir := t.TempDir()
	got := readKernelConfig([]string{filepath.Join(dir, "a"), filepath.Join(dir, "b")})
	if got.Source != "unavailable: ENOENT" || got.SHA256 != "" {
		t.Fatalf("got %+v, want an explicit unavailable source and no digest", got)
	}
}

// On the real host the report must carry the digest of the configuration the kernel was built with whenever either file exists
// (the Debian 6.1 and mainline 6.6 qualification hosts have only /boot/config-<release>); the options it names must be read.
func TestReadKernelConfigOfThisHostCarriesADigestWhenTheKernelConfigIsReadable(t *testing.T) {
	var path string
	for _, candidate := range []string{"/proc/config.gz", "/boot/config-" + KernelRelease()} {
		if _, err := os.ReadFile(candidate); err == nil {
			path = candidate
			break
		}
	}
	if path == "" {
		t.Skip("this host exposes no readable kernel configuration")
	}
	got := ReadKernelConfig()
	if got.Source != path || len(got.SHA256) != 64 || got.PerfEvents == "" || got.Ftrace == "" {
		t.Fatalf("got %+v for readable %s", got, path)
	}
}
