//go:build !linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package durablefs

import "os"

// DropCachedPages has no portable equivalent outside Linux: the verification reads whatever the
// platform serves, and the sync that follows it decides.
func DropCachedPages(*os.File) {}
