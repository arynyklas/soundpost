// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"errors"
	"flag"
	"fmt"

	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/backup"
	"github.com/arynyklas/soundpost/internal/model"
)

// The static reasons serve prints for an unusable restore-authority configuration. They
// carry no path, key or runtime value.
const (
	errAuthorityIncomplete = cliError("--authority-keys and --authority-dir (or the --authority-s3-* set) must be given together: both or neither")
	errAuthorityRestricted = cliError("--authority-keys holds restricted keys that cannot checkpoint deletions; serve needs the full authority keys")
	errAuthorityInsecure   = cliError("--authority-keys must be a private file (no group or other access, mode 0600)")
	errAuthorityUnusable   = cliError("the restore authority named by --authority-keys and --authority-dir could not be opened")
)

// authorityFlags are the serve flags that name the independent restore authority: the
// same --authority-keys and authority destination flags the backup CLI takes, parsed and
// opened by the same code (openAuthority). Credentials for an S3 destination come only
// from SOUNDPOST_AUTHORITY_S3_ACCESS_KEY and SOUNDPOST_AUTHORITY_S3_SECRET_KEY.
type authorityFlags struct {
	keys *string
	dest *destinationFlags
}

func addAuthorityFlags(f *flag.FlagSet) *authorityFlags {
	return &authorityFlags{keys: f.String("authority-keys", "", "FULL restore-authority keys (private file); with the authority destination, serve checkpoints every deletion to the authority"), dest: newDestinationFlags(f, "authority")}
}

func (a *authorityFlags) any() bool {
	return *a.dest.dir != "" || *a.dest.endpoint != "" || *a.dest.region != "" || *a.dest.bucket != "" || *a.dest.prefix != ""
}

// open returns nil, nil when no authority flag is given. Keys without a destination, a
// destination without keys, restricted keys and a key file other users can read are
// refused with a static reason; there is no silent fallback to running without one.
func (a *authorityFlags) open() (*backup.Authority, error) {
	if *a.keys == "" && !a.any() {
		return nil, nil
	}
	if *a.keys == "" || !a.any() {
		return nil, errAuthorityIncomplete
	}
	authority, err := openAuthorityKeys(a.dest, *a.keys, true)
	if err != nil {
		var message cliError
		var fault *model.Fault
		switch {
		case errors.As(err, &message):
			return nil, err
		case errors.As(err, &fault) && fault.Code == model.Forbidden:
			return nil, errAuthorityInsecure
		}
		return nil, errAuthorityUnusable
	}
	return authority, nil
}

// installServeAuthority makes the opened authority the one retention checkpoints every
// deletion to, before any route can begin a deletion.
func installServeAuthority(core *appcore.App, authority *backup.Authority) error {
	if authority == nil {
		return nil
	}
	return core.Retention.UseAuthority(authority)
}

func serveAuthorityNotice(err error) string {
	var message cliError
	if errors.As(err, &message) {
		return "soundpost serve: " + string(message)
	}
	return fmt.Sprint("soundpost serve: the restore authority could not be configured")
}
