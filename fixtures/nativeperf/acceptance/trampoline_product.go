//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/arynyklas/soundpost/internal/nativeperf"
)

// closingSource closes the mapping reader together with the acquisition it guards.
type closingSource struct {
	nativeperf.EventSource
	reader *nativeperf.MappingReader
}

func (s *closingSource) Close() error {
	err := s.EventSource.Close()
	s.reader.Close()
	return err
}

// productMappingTable is the mapping table the product's own MappingReader builds from the live process: the executable
// ranges of an object whose GNU build ID the target's policy approves become modules with file offsets, every other range
// (a library the policy omits, anonymous memory where a JIT or a perf trampoline keeps its code) a closed reason. The
// reader can only be made by an acquisition the signed-grant helper path authorizes, so this runs a real in-process
// helper for one short capture request of the target, exactly as fixtures/nativeperf/identity/smoke does, and hands back
// the table the acquisition derived. The target has to be alive and unchanged.
func productMappingTable(ctx context.Context, target nativeperf.Target) (nativeperf.MappingTable, error) {
	var none nativeperf.MappingTable
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return none, err
	}
	cfg := nativeperf.DefaultConfig(1)
	targets := []nativeperf.Target{target}
	grant, err := nativeperf.SignStart(nativeperf.StartAuthorization{Installation: "python-trampolines-fixture", UID: uint32(os.Getuid()), Revision: 1, Expires: time.Now().Add(time.Minute).Unix(), Targets: targets, Config: cfg, Mode: nativeperf.ModeCPU}, private)
	if err != nil {
		return none, err
	}
	dir, err := os.MkdirTemp("", "soundpost-trampoline-socket-")
	if err != nil {
		return none, err
	}
	defer os.RemoveAll(dir)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(dir, "acquire.sock"), Net: "unix"})
	if err != nil {
		return none, err
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	tables := make(chan nativeperf.MappingTable, 1)
	helper := nativeperf.Helper{
		Policy: nativeperf.OperatorPolicy{Installation: "python-trampolines-fixture", UID: uint32(os.Getuid()), Revision: 1, PublicKey: public, Allowlist: targets},
		Budget: nativeperf.NewResourceBudget(),
		Acquire: func(ctx context.Context, a nativeperf.AuthorizedTargets, c nativeperf.Config, r *nativeperf.Reservation) (nativeperf.EventSource, error) {
			policy := nativeperf.DefaultSymbolPolicy(uint64(c.PolicyRevision))
			policy.AllowMappedELF = true
			reader, err := nativeperf.NewMappingReader(a, target, 1, policy)
			if err != nil {
				return nil, err
			}
			table, err := reader.Read(ctx)
			if err != nil {
				reader.Close()
				return nil, err
			}
			source, err := nativeperf.NewCPUAcquisition(ctx, a, c, r)
			if err != nil {
				reader.Close()
				return nil, err
			}
			tables <- table
			return &closingSource{source, reader}, nil
		},
	}
	go helper.Serve(ctx, listener)
	conn, err := net.DialUnix("unix", nil, listener.Addr().(*net.UnixAddr))
	if err != nil {
		return none, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	request, err := json.Marshal(nativeperf.CaptureRequest{Authorization: grant, Targets: targets, Config: cfg, Mode: nativeperf.ModeCPU})
	if err != nil {
		return none, err
	}
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(request)))
	if _, err = conn.Write(append(length[:], request...)); err != nil {
		return none, err
	}
	for {
		if _, err = io.ReadFull(conn, length[:]); err != nil {
			return none, fmt.Errorf("the in-process helper ended before it was ready: %w", err)
		}
		size := binary.BigEndian.Uint32(length[:])
		if size == 0 || size > 64<<10 {
			return none, errors.New("invalid helper frame")
		}
		payload := make([]byte, size)
		if _, err = io.ReadFull(conn, payload); err != nil {
			return none, err
		}
		var reply struct {
			Ready bool
			Error string
		}
		if json.Unmarshal(payload, &reply) != nil {
			return none, errors.New("invalid helper reply")
		}
		if reply.Error != "" {
			return none, fmt.Errorf("the in-process helper refused the capture: %s", reply.Error)
		}
		if reply.Ready {
			break
		}
	}
	select {
	case table := <-tables:
		return table, nil
	case <-ctx.Done():
		return none, errors.New("the product's mapping table was not produced")
	}
}
