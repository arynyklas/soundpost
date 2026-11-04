//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"soundpost/internal/nativeperf"
	"syscall"
)

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, "native helper:", e)
		os.Exit(1)
	}
}
func run() error {
	cycles := flag.Bool("cpu-cycles", false, "Explicitly acquire hardware cycles instead of software CPU-clock (no fallback)")
	flag.Parse()
	if flag.NArg() != 0 {
		return nativeperf.ErrInvalid
	}
	fd, e := syscall.Open("/etc/soundpost/perf-policy.json", syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if e != nil {
		return nativeperf.ErrAuthorization
	}
	f := os.NewFile(uintptr(fd), "operator policy")
	defer f.Close()
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0022 != 0 {
		return nativeperf.ErrAuthorization
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != 0 {
		return nativeperf.ErrAuthorization
	}
	var p nativeperf.OperatorPolicy
	d := json.NewDecoder(io.LimitReader(f, 65537))
	d.DisallowUnknownFields()
	if e = d.Decode(&p); e != nil {
		return nativeperf.ErrAuthorization
	}
	if d.Decode(new(any)) != io.EOF {
		return nativeperf.ErrAuthorization
	}
	if p.UID != uint32(os.Geteuid()) {
		return nativeperf.ErrAuthorization
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	l, e := nativeperf.ListenHelper()
	if e != nil {
		return e
	}
	defer l.Close()
	acquire := nativeperf.NewNativeAcquisition
	if *cycles {
		acquire = nativeperf.NewCyclesAcquisition
	}
	h := nativeperf.Helper{Policy: p, Budget: nativeperf.NewResourceBudget(), Acquire: acquire}
	return h.Serve(ctx, l)
}
