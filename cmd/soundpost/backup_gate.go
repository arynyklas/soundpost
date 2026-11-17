// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/arynyklas/soundpost/internal/config"
)

// The installation-file gate in front of `backup create` (docs/operations/backup-authority.md). The messages are
// static: a refusal never carries a path, an endpoint, a key reference or the text of a store error.
const (
	errInstallConfigRequired = cliError("install_config_required: an S3 (off-host) destination is taken only under --install-config FILE whose backup gate passes (see docs/operations/backup-authority.md)")
	errInstallConfigInvalid  = cliError("install_config_invalid: --install-config does not name a readable, valid installation file (run soundpost-config validate)")
	errInstallConfigMode     = cliError("install_config_mode: an S3 destination needs backup.mode offhost in the installation file; a local or absent backup mode is never taken to a remote store")
	errInstallConfigMismatch = cliError("install_config_mismatch: the installation file's off-host backup destination and authority store are not the stores named on the command line")
	errInstallConfigOpen     = cliError("install_config_authority_unopenable: the authority store or its restricted keys named by the installation file cannot be opened (see the secret and key references)")
	errInstallConfigKeys     = cliError("install_config_authority_keys_mismatch: --authority-keys is not the authority key file the installation file declares (backup.authority.keys)")
	errBackupGateFailed      = cliError("backup_gate_failed: the backup gate could not be evaluated")

	// labelUnverified is what a run without an installation file may be called: nothing was checked.
	labelUnverified = "unverified"
)

// backupGate decides, before anything is opened or written, what the backup about to be taken may be
// called. Without an installation file only a local directory is taken, and it is labelled unverified.
// With one, the file must validate; an S3 destination needs an off-host backup block; an off-host block must
// name exactly the stores of the command line; and config.BackupChecker must prove conditional create and a
// fresh verified authority head now. Every failure is typed and nothing has been written yet.
func backupGate(path string, dest, authority *destinationFlags, keysPath string, now func() time.Time) (string, error) {
	remote := *dest.endpoint != ""
	if path == "" {
		if remote {
			return "", errInstallConfigRequired
		}
		return labelUnverified, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", errInstallConfigInvalid
	}
	cfg, err := config.Parse(raw)
	if err != nil {
		return "", errInstallConfigInvalid
	}
	if err = config.Validate(cfg); err != nil {
		return "", errInstallConfigInvalid
	}
	if remote && cfg.Backup.Mode != config.BackupOffhost {
		return "", errInstallConfigMode
	}
	if cfg.Backup.Mode != config.BackupOffhost {
		status, err := (&config.BackupChecker{Now: now}).Check(context.Background(), cfg)
		if err != nil {
			return "", errBackupGateFailed
		}
		return string(status.Label), nil
	}
	if !sameStore(dest, cfg.Backup.Destination) || !sameStore(authority, cfg.Backup.Authority.Store) {
		return "", errInstallConfigMismatch
	}
	if !sameKeysFile(keysPath, cfg.Backup.Authority.Keys) {
		return "", errInstallConfigKeys
	}
	checker, err := config.OpenBackupChecker(cfg, now)
	if err != nil {
		return "", errInstallConfigOpen
	}
	status, err := checker.Check(context.Background(), cfg)
	var notReady *config.NotReadyError
	if errors.As(err, &notReady) {
		return "", cliError("backup_not_ready: " + string(notReady.Reason))
	}
	if err != nil {
		return "", errBackupGateFailed
	}
	return string(status.Label), nil
}

// sameStore reports whether the command-line destination is the installation file's declared store.
func sameStore(flags *destinationFlags, store config.Store) bool {
	switch store.Kind {
	case "dir":
		if *flags.dir == "" || store.Path == "" {
			return false
		}
		a, errA := filepath.Abs(*flags.dir)
		b, errB := filepath.Abs(store.Path)
		return errA == nil && errB == nil && filepath.Clean(a) == filepath.Clean(b)
	case "s3":
		return *flags.endpoint != "" && *flags.endpoint == string(store.Endpoint) && *flags.bucket == store.Bucket && *flags.prefix == store.Prefix &&
			*flags.region == store.Region
	}
	return false
}

// sameKeysFile reports whether --authority-keys is the file the installation file's backup.authority.keys
// reference names. A reference that is not a file: path (env:, k8s:) is never the same as a path on the command line.
func sameKeysFile(keysPath string, declared config.SecretRef) bool {
	declaredPath, ok := declared.FilePath()
	if !ok || keysPath == "" {
		return false
	}
	a, errA := filepath.Abs(keysPath)
	b, errB := filepath.Abs(declaredPath)
	return errA == nil && errB == nil && filepath.Clean(a) == filepath.Clean(b)
}
