//go:build !linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import "net"

// peerIsOwner: no kernel peer credentials off Linux (the release is linux/amd64 only); the data
// directory's own permissions are the only barrier there.
func peerIsOwner(net.Conn) bool { return true }
