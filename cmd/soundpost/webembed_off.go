// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

//go:build !webembed

package main

import "io/fs"

// embeddedWeb is empty in a development build: serve then needs --web-dir to host the UI.
func embeddedWeb() (fs.FS, bool) { return nil, false }
