// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"net"
	"os"
	"syscall"
)

// peerIsOwner admits a client of the membership socket only when the kernel says its process runs
// as the user of this node (or root): the directory and socket modes already keep other users out,
// this is the second, independent check on the connection itself (SO_PEERCRED).
func peerIsOwner(c net.Conn) bool {
	unixConn, ok := c.(*net.UnixConn)
	if !ok {
		return false
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return false
	}
	var uid uint32
	var credErr error
	if err = raw.Control(func(fd uintptr) {
		cred, e := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		if e != nil {
			credErr = e
			return
		}
		uid = cred.Uid
	}); err != nil || credErr != nil {
		return false
	}
	return uid == uint32(os.Geteuid()) || uid == 0
}
