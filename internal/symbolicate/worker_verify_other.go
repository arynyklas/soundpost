//go:build !linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package symbolicate

import "os"

// identityOf: no reliable change identity off Linux, so the hash is never reused.
func identityOf(*os.File) (fileIdentity, bool) { return fileIdentity{}, false }
