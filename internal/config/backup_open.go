// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package config

import (
	"errors"
	"os"
	"strings"
	"time"

	"github.com/arynyklas/soundpost/internal/backup"
)

// defaultS3Region is the region a store without a region field signs for (S3-compatible
// stores that ignore the region accept any).
const defaultS3Region = "us-east-1"

// Secret resolves a env:NAME or file:/path reference to its value, for a process that must use
// the secret. The reference stays redacted everywhere else; the value is never returned inside
// an error. k8s: references are mounted into the pod by the platform and are not resolvable here.
func (r SecretRef) Secret() (string, error) {
	if !r.valid() {
		return "", errors.New("config: not a secret reference")
	}
	scheme, target, _ := strings.Cut(r.ref, ":")
	switch scheme {
	case "env":
		v, ok := os.LookupEnv(target)
		if !ok || v == "" {
			return "", errors.New("config: secret environment variable is not set")
		}
		return v, nil
	case "file":
		raw, err := os.ReadFile(target)
		if err != nil {
			return "", errors.New("config: secret file is not readable")
		}
		return strings.TrimRight(string(raw), "\r\n"), nil
	}
	return "", errors.New("config: only env: and file: references can be resolved by this process")
}

// OpenStore opens a configured off-host store as a backup destination.
func OpenStore(s Store) (backup.Destination, error) {
	switch s.Kind {
	case "dir":
		return backup.NewLocalDestination(s.Path)
	case "s3":
		access, err := s.AccessKey.Secret()
		if err != nil {
			return nil, err
		}
		secret, err := s.SecretKey.Secret()
		if err != nil {
			return nil, err
		}
		region := s.Region
		if region == "" {
			region = defaultS3Region
		}
		return backup.NewS3Destination(backup.S3Config{Endpoint: s.Endpoint.Reveal(), Region: region, Bucket: s.Bucket, Prefix: s.Prefix, AccessKey: access, SecretKey: secret})
	}
	return nil, errors.New("config: store kind must be s3 or dir")
}

// OpenBackupChecker builds the checker for an off-host configuration from the real authority
// store (cfg.Backup.Authority.Store) and the restricted (verify-only) authority keys, which are
// all a node needs to read and verify the journal head. Local and absent backup modes need no
// probe and get a checker that can only label them as what they are.
func OpenBackupChecker(cfg InstallConfig, now func() time.Time) (*BackupChecker, error) {
	checker := &BackupChecker{Now: now}
	if cfg.Backup.Mode != BackupOffhost {
		return checker, nil
	}
	path, ok := cfg.Backup.Authority.RestrictedKeys.FilePath()
	if !ok {
		return nil, errors.New("config: backup.authority.restricted_keys must be a file: reference for the check")
	}
	keys, err := backup.ReadAuthorityKeys(path)
	if err != nil {
		return nil, err
	}
	dest, err := OpenStore(cfg.Backup.Authority.Store)
	if err != nil {
		return nil, err
	}
	if checker.Probe, err = NewBackupProbe(dest, keys, now); err != nil {
		return nil, err
	}
	return checker, nil
}
