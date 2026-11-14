// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

// Package privacl verifies that a directory or file holding a secret is
// reachable by nobody but its owner. On POSIX systems the mode is checked; on
// Windows the object's DACL is read and every access-allowed entry must name the
// owner, the current user, SYSTEM, Administrators or CREATOR OWNER. The check is
// made by the process that is about to rely on the path, so no operator
// assertion stands in for it.
package privacl

import "errors"

// ErrNotPrivate means the path is reachable by someone other than its owner.
var ErrNotPrivate = errors.New("privacl: path is reachable by other users")

// Check refuses a path that other users can reach. A path that cannot be
// examined is refused as well: the check fails closed.
func Check(path string) error { return check(path) }

// Restrict replaces the path's access list with full control for the current
// user, SYSTEM and Administrators only, inherited by everything below it: the
// Windows counterpart of chmod 0700 on a directory this process owns. On POSIX
// systems modes are tightened with os.Chmod by the caller and Restrict is not
// available.
func Restrict(path string) error { return restrict(path) }
