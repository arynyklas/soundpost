//go:build !linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import "os"

// dropPayloadRange has no portable equivalent outside Linux.
func dropPayloadRange(*os.File, int64, int64) {}

// adviseRandomReads has no portable equivalent outside Linux.
func adviseRandomReads(*os.File) {}
