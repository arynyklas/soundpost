// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// A bad SMTP or Telegram delivery flag fails serve before storage is opened:
// the data directory is not even created.
func TestServeRefusesABadDeliveryFlagBeforeOpeningStorage(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes")
	}
	for name, flags := range map[string][]string{
		"smtp sender missing":    {"--notify-smtp-host", "smtp.example.test", "--notify-smtp-from", ""},
		"smtp sender malformed":  {"--notify-smtp-host", "smtp.example.test", "--notify-smtp-from", "not an address"},
		"smtp auth without user": {"--notify-smtp-host", "smtp.example.test", "--notify-smtp-from", "ops@example.test", "--notify-smtp-require-auth"},
		"smtp port out of range": {"--notify-smtp-host", "smtp.example.test", "--notify-smtp-from", "ops@example.test", "--notify-smtp-port", "70000"},
		"telegram api not https": {"--notify-telegram-api", "http://api.example.test"},
	} {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "data")
			args := append([]string{"serve", "--data-dir", dir, "--listen", "127.0.0.1:0"}, flags...)
			stderr, exit := runSoundpost(t, args...)
			if exit == 0 || !strings.Contains(stderr, "startup or service failed") {
				t.Fatalf("exit %d stderr %q", exit, stderr)
			}
			if _, err := os.Stat(dir); err == nil {
				t.Error("storage was opened (the data directory exists) although the delivery flags were refused")
			}
		})
	}
}
