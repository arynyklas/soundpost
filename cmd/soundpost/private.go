// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"errors"
	"github.com/arynyklas/soundpost/internal/durablefs"
	"github.com/arynyklas/soundpost/internal/privacl"
	"os"
	"path/filepath"
	"runtime"
)

// errInsecureMode means a directory or key that must be private is reachable by other users.
var errInsecureMode = errors.New("insecure file mode")

// errLegacyVolumeLayout means the data directory is the data/ subdirectory of a volume whose
// root still holds a data directory of the earlier chart layout.
var errLegacyVolumeLayout = errors.New("data of the earlier volume-root layout")

// legacyVolumeLayoutLine is what serve prints for errLegacyVolumeLayout: a typed code, what to do,
// and no path.
const legacyVolumeLayoutLine = "soundpost: legacy_volume_layout: the volume root next to this data directory still holds a data directory of the earlier layout (control.db or raft/ beside data/); starting here would run this member on a fresh state while its real data sits one level up. Nothing was opened or changed. With the member stopped, move the whole old root, including its own data/, into data/ (or delete a stale copy when data/ already holds the member's data), then start it again: docs/operations/upgrade.md"

// refuseLegacyVolumeLayout refuses to start a member on data/ when the volume it sits in holds
// control.db or raft/ at its root. Earlier charts passed the volume root itself as --data-dir;
// the chart now passes its data/ subdirectory (a PVC root cannot be private, see
// docs/operations/upgrade.md). The old root holds the storage engine's own data/ directory, so
// the new data directory is that engine directory: a member upgraded without the one-time move
// would start with a fresh control state there while its control.db and raft/ sit unread one
// level up. Only a directory named data is judged: any other layout has no such history. The
// check runs before preparePrivate creates or opens anything, so the refusal leaves the volume
// exactly as the operator left it.
func refuseLegacyVolumeLayout(dir string) error {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	if filepath.Base(abs) != "data" {
		return nil
	}
	root := filepath.Dir(abs)
	for _, marker := range []string{"control.db", "raft"} {
		_, err = os.Lstat(filepath.Join(root, marker))
		if err == nil {
			return errLegacyVolumeLayout
		}
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

// preparePrivate makes sure the data directory exists as a private (0700) directory. A
// directory this process may chmod (a hand-made or volume-provided 0755 one) is tightened to
// 0700; one it cannot make private is refused, and so is an operator-supplied TLS private
// key that group or other users can read (it is shared material this process must not chmod).
// The files the process creates itself (envelope keys, bootstrap.token, generated server.key)
// are already 0600; the directory mode is what keeps them unreachable. POSIX modes say nothing
// about Windows ACLs, so there the directory's DACL is read instead and, when it grants
// anyone but the owner, SYSTEM and Administrators access, replaced with exactly that
// (docs/operations/bootstrap.md). A data/ directory on a volume that still holds the earlier
// volume-root layout is refused first (refuseLegacyVolumeLayout), before anything is created.
func preparePrivate(dir, tlsKey string) error {
	if err := refuseLegacyVolumeLayout(dir); err != nil {
		return err
	}
	if err := durablefs.MkdirAll(dir); err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		return preparePrivateACL(dir, tlsKey)
	}
	dir = filepath.Clean(dir)
	info, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if info.Mode().Perm()&0o077 != 0 {
		if err = os.Chmod(dir, 0o700); err != nil {
			return errInsecureMode
		}
		if info, err = os.Stat(dir); err != nil {
			return err
		}
		if info.Mode().Perm()&0o077 != 0 {
			return errInsecureMode
		}
	}
	if tlsKey != "" {
		keyInfo, err := os.Stat(tlsKey)
		if err != nil {
			return err
		}
		if gid, known := fileGID(keyInfo); !keyModePrivate(keyInfo.Mode().Perm(), gid, known) {
			return errInsecureMode
		}
	}
	return nil
}

// keyModePrivate decides whether an operator-supplied private key can be read by nobody but
// its owner and root. Any "other" bit refuses. Group bits are accepted only when the file's
// group is root (gid 0): systemd materialises LoadCredential= files as 0440 root:root and
// grants the service user read access through an ACL, whose mask is what the group bits then
// show; the only group members are root-equivalent. A key in any other group (the service
// user's own, "users", ...) is readable by that group's other members and is refused, as is
// a group whose identity cannot be read.
func keyModePrivate(perm os.FileMode, gid uint32, gidKnown bool) bool {
	if perm&0o007 != 0 {
		return false
	}
	return perm&0o070 == 0 || (gidKnown && gid == 0)
}

// preparePrivateACL is preparePrivate for Windows: the Windows counterpart of the 0700
// tightening. A data directory whose DACL admits other users is restricted to the current
// user, SYSTEM and Administrators; one that cannot be made private is refused, and so is an
// operator-supplied TLS private key whose DACL admits anyone else (shared material this
// process must not re-ACL).
func preparePrivateACL(dir, tlsKey string) error {
	dir = filepath.Clean(dir)
	if privacl.Check(dir) != nil {
		if err := privacl.Restrict(dir); err != nil || privacl.Check(dir) != nil {
			return errInsecureMode
		}
	}
	if tlsKey != "" {
		if _, err := os.Stat(tlsKey); err != nil {
			return err
		}
		if privacl.Check(tlsKey) != nil {
			return errInsecureMode
		}
	}
	return nil
}
