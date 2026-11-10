//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"time"

	"soundpost/fixtures/nativeperf/privacy/privnode"
	"soundpost/fixtures/nativeperf/privacy/scan"
	"soundpost/internal/model"
	"soundpost/internal/nativeperf"
	"soundpost/internal/profiles"
)

// captured is what the real acquisition session produced.
type captured struct {
	events   []nativeperf.SanitizedEvent
	mappings []nativeperf.MappingTable
	wall     model.UnixNano
	mono     model.MonoNano
}

// fixtureLease is the exporter's own 2MiB working reservation (the exporter is a
// separate budget from the helper's acquisition reservation).
type fixtureLease struct{}

func (fixtureLease) Bytes() uint64 { return 2 << 20 }
func (fixtureLease) Close() error  { return nil }

// captureSession: signed grant -> helper socket -> real perf events -> sanitized
// stream, auditing the socket frames and (inside the helper) the owned staging
// copy. It checks genuine CPU evidence and returns the events.
func captureSession(ctx context.Context, env *fixtureEnv, h *helperHandle, o options, symbol func(uint64) string, rep *report) (*captured, error) {
	request, e := h.request(2 * time.Minute)
	if e != nil {
		return nil, e
	}
	conn, e := net.DialUnix("unix", nil, &net.UnixAddr{Name: h.sock, Net: "unix"})
	if e != nil {
		return nil, errors.New("helper unreachable")
	}
	defer conn.Close()
	out := &captured{wall: model.UnixNano(time.Now().UnixNano())}
	if out.mono, e = monotonicNow(); e != nil {
		return nil, e
	}
	if e = writeFrame(conn, request); e != nil {
		return nil, e
	}
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	ready, e := env.readFrame(conn)
	if e != nil || !ready.Ready || ready.Error != "" {
		code := ready.Error
		if code == "" {
			code = "no ready frame"
		}
		env.diagnostic(code)
		return nil, errors.New("helper refused the signed request: " + code)
	}
	var source *nativeperf.ProfileSource
	select {
	case source = <-h.active:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	conn.SetReadDeadline(time.Now().Add(time.Duration(o.seconds) * time.Second))
	threads := map[uint32]bool{}
	for len(out.events) < 200 {
		reply, err := env.readFrame(conn)
		if err != nil {
			var timeout net.Error
			if errors.As(err, &timeout) && timeout.Timeout() {
				break
			}
			return nil, errors.New("helper stream failed: " + err.Error())
		}
		if reply.Error != "" {
			env.diagnostic(reply.Error)
			return nil, errors.New("helper reported " + reply.Error)
		}
		if reply.Proof != nil || reply.Complete {
			continue
		}
		if reply.Event == nil {
			return nil, errors.New("helper frame had no event")
		}
		out.events = append(out.events, *reply.Event)
		if reply.Event.CPUEvent != nil {
			threads[reply.Event.Task.TID] = true
		}
	}
	out.mappings = source.FramesMappings()
	row := &rep.CPU
	row.ThreadsObserved = len(threads)
	row.GenuineNumericOK = true
	resolved := map[string]bool{}
	for _, ev := range out.events {
		switch {
		case ev.CPUEvent != nil:
			row.Samples++
			s := ev.CPUEvent
			if s.Period == 0 || s.RequestedHz != 99 || s.Method != nativeperf.MethodSoftwareCPUClock {
				row.GenuineNumericOK = false
			}
			if name := symbol(uint64(s.IP)); name == "spcnry_hot" {
				row.HotFunction++
				resolved[name] = true
			}
			frames := 0
			for _, f := range s.Callchain {
				if f.IP == 0 {
					continue
				}
				frames++
				if name := symbol(uint64(f.IP)); name == "spcnry_handle_request" || name == "spcnry_hash_text" {
					row.ResolvedCallers++
					resolved[name] = true
				}
			}
			if frames >= 3 {
				row.DeepStacks++
			}
		case ev.Loss != nil:
			row.LossEvents++
		case ev.Switch != nil:
			rep.Scheduler.Switches++
		case ev.Wakeup != nil:
			rep.Scheduler.Wakeups++
		}
	}
	for name := range resolved {
		row.SymbolsResolved = append(row.SymbolsResolved, name)
	}
	sort.Strings(row.SymbolsResolved)
	if row.Samples == 0 || row.HotFunction == 0 || row.DeepStacks == 0 || row.ResolvedCallers == 0 || !row.GenuineNumericOK {
		return nil, fmt.Errorf("CPU evidence is not genuine: samples=%d hot=%d deep=%d callers=%d numeric=%v", row.Samples, row.HotFunction, row.DeepStacks, row.ResolvedCallers, row.GenuineNumericOK)
	}
	if rep.Scheduler.Status == string(nativeperf.Supported) && (rep.Scheduler.Switches == 0 || rep.Scheduler.Wakeups == 0) {
		return nil, errors.New("scheduler capability is supported but no scheduler events arrived")
	}
	return out, nil
}

// exportAndRead: assembly -> real exporter -> real gzip batch route -> storage
// scan -> real scoped read, auditing the queue, wire, storage, read and export.
func exportAndRead(ctx context.Context, env *fixtureEnv, n *privnode.Node, c *captured, rep *report, caps nativeperf.Capabilities) error {
	domain := c.events[0].Domain
	clock := model.TraceClock{Wall: c.wall, Mono: c.mono, Domain: model.ClockDomain{Host: fixedID("host", domain.HostID), Boot: fixedID("boot", domain.BootID), Runtime: n.Producer}}
	now := model.UnixNano(time.Now().UnixNano())
	root := model.NewID()
	limits := nativeperf.ProfileLimits{Profile: root, Process: model.NewID(), Capability: model.NewID(), Domain: domain, PolicyRevision: 1, Sequence: 1, Start: c.wall, End: now, Clock: clock, Complete: false, MaxBytes: 8 << 20, MaxSamples: 8192, MaxIntervals: 8192, MaxFrames: 4096, MaxStacks: 4096, Mappings: c.mappings}
	admitter := &privnode.Admitter{N: n, Audit: env.audit}
	exporter, e := nativeperf.NewExporter(admitter, privnode.Lookup{N: n}, nativeperf.ExportConfig{Project: n.Project, Source: n.Source, Producer: n.Producer, Resource: n.Resource, Limits: limits, Capabilities: caps}, fixtureLease{})
	if e != nil {
		return errors.New("exporter composition refused")
	}
	defer exporter.Close()
	grant, e := n.Grant(ctx)
	if e != nil {
		return errors.New("source grant refused")
	}
	events := c.events
	if len(events) > 200 {
		events = events[:200]
	}
	if _, e = exporter.Send(ctx, grant, nativeperf.ProfileChunk{ProfileID: root, PolicyRevision: 1, Domain: domain, Events: events}); e != nil {
		env.diagnostic(e.Error())
		return errors.New("export failed: " + e.Error())
	}
	rep.Export.Batches = admitter.Count
	rep.Export.QueueObserved = true
	if !exporter.Stats().Admitted {
		return errors.New("exporter did not report the capture admitted")
	}
	for _, v := range []any{exporter.Stats(), exporter.DropReport(), exporter.LastReceiptRequest()} {
		raw, _ := json.Marshal(v)
		env.observe(scan.StageExporterQueue, raw)
	}
	files, octets, positive, e := n.ScanStorage(env.audit, []byte(domain.BootID))
	if e != nil {
		return errors.New("storage scan failed")
	}
	rep.Export.StorageFiles, rep.Export.StorageBytes, rep.Export.StoragePositive = files, octets, positive
	service := n.App.NewNativeProfiles()
	cursor := ""
	for page := 0; page < 64; page++ {
		view, e := service.Read(ctx, n.Reader, root, profiles.Window{Start: c.wall, End: now + 1, MaxSamples: 64, Cursor: cursor})
		if e != nil {
			return errors.New("scoped read failed")
		}
		raw, _ := json.Marshal(view)
		env.observe(scan.StageRead, raw)
		pretty, _ := json.MarshalIndent(view, "", "  ")
		env.observe(scan.StageExport, pretty)
		rep.Export.ReadPages++
		rep.Export.ReadSamples += len(view.Samples)
		rep.Export.ReadCapabilities = len(view.Capabilities)
		for _, s := range view.Samples {
			if s.Native == nil || s.Native.Period == 0 || s.Count != 1 || s.Native.RequestedHz != 99 {
				return errors.New("read profile lost its native period/rate")
			}
		}
		for _, l := range view.Links {
			if l.Available || l.Reference != nil {
				return errors.New("artifact link available without an artifact grant")
			}
			rep.Export.ArtifactLinks++
		}
		if view.NextCursor == "" {
			break
		}
		cursor = view.NextCursor
	}
	if rep.Export.ReadSamples == 0 {
		return errors.New("scoped read returned no samples")
	}
	return nil
}
