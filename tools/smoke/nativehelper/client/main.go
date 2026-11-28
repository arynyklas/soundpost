//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

// client is the in-container half of the native-helper container smoke (tools/smoke/native_helper_container.go). The
// helper listens on a root-only unix socket and refuses a peer it cannot see in its own PID namespace, so the driver
// has to run inside the namespaces of the helper container. Three modes, each printing one JSON line on stdout:
//
//	prepare                    make the shared socket directory the private 0700 directory the helper requires
//	policy  --pid P --binary B --out DIR
//	                           write the root-owned operator policy that allowlists exactly the live target P
//	capture --pid P --binary B --seconds N
//	                           send a signed CPU capture request to the helper, count and symbolize the samples, and
//	                           report the typed outcome (never an invented one: a refusal is a refusal)
//	remove  --dir /w           delete the root-owned files the previous modes left in a bind-mounted host directory
//
// The operator key is the documented public fixture key of fixtures/nativeperf/helper-e2e (never a production key).
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync/atomic"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/nativeperf"
)

const (
	fixtureSeedText = "soundpost helper-e2e fixture seed v1: public test seed, not a secret"
	installation    = "l5w24-container"
	hotSymbol       = "main.soundpostHotLoop"
	socketDir       = "/run/soundpost-perf"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: client prepare | policy | capture")
		os.Exit(2)
	}
	var out any
	var err error
	switch os.Args[1] {
	case "prepare":
		out, err = prepare()
	case "policy":
		out, err = policy(os.Args[2:])
	case "capture":
		out, err = capture(os.Args[2:])
	case "remove":
		out, err = remove(os.Args[2:])
	default:
		err = errors.New("unknown mode " + os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "client:", err)
		os.Exit(1)
	}
	_ = json.NewEncoder(os.Stdout).Encode(out)
}

func fixtureKey() ed25519.PrivateKey {
	seed := sha256.Sum256([]byte(fixtureSeedText))
	return ed25519.NewKeyFromSeed(seed[:])
}

func prepare() (any, error) {
	if err := os.Chmod(socketDir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chown(socketDir, 0, 0); err != nil {
		return nil, err
	}
	st, err := os.Stat(socketDir)
	if err != nil {
		return nil, err
	}
	return map[string]any{"mode": "prepare", "socket_dir_perm": fmt.Sprintf("%04o", st.Mode().Perm())}, nil
}

// target resolves the live process the way the helper will check it: PID namespace, process start, cgroup and the GNU
// build ID of the executable the operator names with --binary.
func target(pid int, binary string) (nativeperf.Target, error) {
	t, err := nativeperf.ResolveLocalTarget(pid)
	if err != nil {
		return t, err
	}
	// the same resolution the helper applies (host namespace, or a private one with an ancestor mount)
	cgroupID, err := nativeperf.ResolveCgroupID(pid)
	if err != nil {
		return t, fmt.Errorf("cgroup of the target is not resolvable from this container: %w", err)
	}
	t.CgroupID = model.Uint64(cgroupID)
	build, err := buildID(binary)
	if err != nil {
		return t, err
	}
	t.AllowedBuildIDs = []string{build}
	return t, nil
}

func buildID(path string) (string, error) {
	f, err := elf.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if f.Type != elf.ET_EXEC {
		return "", errors.New("the workload must be a non-PIE executable")
	}
	note := f.Section(".note.gnu.build-id")
	if note == nil {
		return "", errors.New("the workload has no GNU build ID")
	}
	b, err := note.Data()
	if err != nil || len(b) < 16 {
		return "", errors.New("unreadable build ID note")
	}
	nameSize, descSize := binary.LittleEndian.Uint32(b), binary.LittleEndian.Uint32(b[4:])
	start := 12 + (uint64(nameSize)+3)&^3
	if descSize == 0 || start+uint64(descSize) > uint64(len(b)) {
		return "", errors.New("invalid build ID note bounds")
	}
	return hex.EncodeToString(b[start : start+uint64(descSize)]), nil
}

func policy(args []string) (any, error) {
	f := flag.NewFlagSet("policy", flag.ContinueOnError)
	pid := f.Int("pid", 0, "target process id in the shared PID namespace")
	binary := f.String("binary", "", "the target's executable (for its GNU build ID)")
	out := f.String("out", "", "directory that receives perf-policy.json")
	if err := f.Parse(args); err != nil {
		return nil, err
	}
	if *pid <= 0 || *binary == "" || *out == "" {
		return nil, errors.New("--pid, --binary and --out are required")
	}
	t, err := target(*pid, *binary)
	if err != nil {
		return nil, err
	}
	p := nativeperf.OperatorPolicy{Installation: installation, PublicKey: fixtureKey().Public().(ed25519.PublicKey), UID: uint32(os.Geteuid()), Revision: 1, Allowlist: []nativeperf.Target{t}}
	raw, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return nil, err
	}
	path := filepath.Join(*out, "perf-policy.json")
	if err = os.WriteFile(path, append(raw, '\n'), 0o644); err != nil {
		return nil, err
	}
	if err = os.Chown(path, 0, 0); err != nil {
		return nil, err
	}
	return map[string]any{"mode": "policy", "target": t, "policy_uid": p.UID}, nil
}

func remove(args []string) (any, error) {
	f := flag.NewFlagSet("remove", flag.ContinueOnError)
	dir := f.String("dir", "", "bind-mounted directory to empty (must be /w)")
	if err := f.Parse(args); err != nil {
		return nil, err
	}
	if *dir != "/w" {
		return nil, errors.New("--dir must be /w")
	}
	entries, err := os.ReadDir(*dir)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if err = os.RemoveAll(filepath.Join(*dir, e.Name())); err != nil {
			return nil, err
		}
	}
	return map[string]any{"mode": "remove", "removed": len(entries)}, nil
}

type symbol struct {
	name        string
	start, size uint64
}

// symbols reads the function symbols of the (non-stripped, non-PIE) workload: its link addresses are its runtime
// addresses, which is how the verifier resolves the helper's addresses without the target's memory.
func symbols(path string) ([]symbol, error) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	syms, err := f.Symbols()
	if err != nil {
		return nil, err
	}
	var out []symbol
	for _, s := range syms {
		if elf.ST_TYPE(s.Info) == elf.STT_FUNC && s.Size > 0 {
			out = append(out, symbol{s.Name, s.Value, s.Size})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].start < out[j].start })
	return out, nil
}

func lookup(syms []symbol, ip uint64) (string, bool) {
	i := sort.Search(len(syms), func(i int) bool { return syms[i].start > ip })
	if i == 0 {
		return "", false
	}
	s := syms[i-1]
	return s.name, ip < s.start+s.size
}

type captureResult struct {
	Mode               string  `json:"mode"`
	Outcome            string  `json:"outcome"` // samples, refused
	Error              string  `json:"error,omitempty"`
	ErrorStatus        string  `json:"error_status,omitempty"` // typed capability status of a refusal: denied, unsupported
	ErrorReason        string  `json:"error_reason,omitempty"`
	AuthorizationError bool    `json:"authorization_denied,omitempty"`
	ResourceError      bool    `json:"resource_limit,omitempty"`
	Samples            uint64  `json:"cpu_samples"`
	TargetSamples      uint64  `json:"samples_of_target_process"`
	WithUserFrames     uint64  `json:"samples_with_user_frames"`
	HotSymbol          string  `json:"hot_symbol"`
	HotSymbolSamples   uint64  `json:"samples_resolved_to_hot_symbol"`
	TopSymbols         []top   `json:"top_symbols,omitempty"`
	Threads            int     `json:"threads_observed"`
	MappingUpdates     uint64  `json:"mapping_updates"`
	MappingBuildOK     uint64  `json:"mapping_updates_with_target_build_id"`
	LossEvents         uint64  `json:"loss_events"`
	LostRecords        uint64  `json:"lost_records"`
	Proofs             uint64  `json:"progress_proofs"`
	StreamEnd          string  `json:"stream_end,omitempty"`
	CaptureSeconds     float64 `json:"capture_seconds"`
	MethodUnit         string  `json:"method_unit,omitempty"`
}

type top struct {
	Symbol  string `json:"symbol"`
	Samples uint64 `json:"samples"`
}

func capture(args []string) (any, error) {
	f := flag.NewFlagSet("capture", flag.ContinueOnError)
	pid := f.Int("pid", 0, "target process id in the shared PID namespace")
	binary := f.String("binary", "", "the target's executable (symbols and GNU build ID)")
	seconds := f.Int("seconds", 5, "capture duration")
	if err := f.Parse(args); err != nil {
		return nil, err
	}
	if *pid <= 0 || *binary == "" || *seconds < 1 || *seconds > 60 {
		return nil, errors.New("--pid, --binary and --seconds (1..60) are required")
	}
	t, err := target(*pid, *binary)
	if err != nil {
		return nil, err
	}
	syms, err := symbols(*binary)
	if err != nil {
		return nil, err
	}
	cfg := nativeperf.DefaultConfig(1)
	targets := []nativeperf.Target{t}
	grant, err := nativeperf.SignStart(nativeperf.StartAuthorization{Installation: installation, UID: uint32(os.Geteuid()), Revision: 1,
		Expires: time.Now().Add(time.Minute).Unix(), Targets: targets, Config: cfg, Mode: nativeperf.ModeCPU}, fixtureKey())
	if err != nil {
		return nil, err
	}
	res := captureResult{Mode: "capture", HotSymbol: hotSymbol}
	ctx := context.Background()
	// The helper container may still be starting: wait for its socket (a missing socket is never a result).
	for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
		if st, e := os.Lstat(nativeperf.HelperSocket); e == nil && st.Mode()&os.ModeSocket != 0 {
			break
		}
	}
	session, err := nativeperf.OpenAuthorized(ctx, nativeperf.CaptureRequest{Authorization: grant, Targets: targets, Config: cfg, Mode: nativeperf.ModeCPU})
	if err != nil {
		res.Outcome = "refused"
		res.Error = err.Error()
		var capErr *nativeperf.CapabilityError
		if errors.As(err, &capErr) {
			res.ErrorStatus, res.ErrorReason = string(capErr.Status), string(capErr.Reason)
		}
		res.AuthorizationError = errors.Is(err, nativeperf.ErrAuthorization)
		res.ResourceError = errors.Is(err, nativeperf.ErrResources)
		return res, nil
	}
	start := time.Now()
	var ending atomic.Bool
	stop := time.AfterFunc(time.Duration(*seconds)*time.Second, func() {
		ending.Store(true)
		session.Stop()
		session.Close()
	})
	threads := map[uint32]bool{}
	named := map[string]uint64{}
	for {
		item, err := session.NextItem(ctx)
		if err != nil {
			if ending.Load() {
				res.StreamEnd = "client stopped the capture"
			} else if !errors.Is(err, nativeperf.ErrSourceComplete) {
				res.StreamEnd = err.Error()
				var capErr *nativeperf.CapabilityError
				if errors.As(err, &capErr) {
					res.ErrorStatus, res.ErrorReason = string(capErr.Status), string(capErr.Reason)
				}
			}
			break
		}
		if item.Proof != nil {
			res.Proofs++
			continue
		}
		ev := item.Event
		switch {
		case ev.CPUEvent != nil:
			res.Samples++
			threads[ev.Task.TID] = true
			if ev.Task.TGID == t.TGID && ev.Task.PIDNamespace == t.PIDNamespace {
				res.TargetSamples++
			}
			res.MethodUnit = string(ev.CPUEvent.Method) + "/" + string(ev.CPUEvent.Unit)
			user, hot, leaf := false, false, ""
			inUser := true
			consider := func(ip uint64, isLeaf bool) {
				if name, ok := lookup(syms, ip); ok {
					user = true
					if isLeaf {
						leaf = name
					}
					if name == hotSymbol {
						hot = true
					}
				}
			}
			consider(uint64(ev.CPUEvent.IP), true)
			for _, e := range ev.CPUEvent.Callchain {
				if e.Context != "" {
					inUser = e.Context == nativeperf.ContextUser
					continue
				}
				if inUser {
					consider(uint64(e.IP), false)
				}
			}
			if user {
				res.WithUserFrames++
			}
			if hot {
				res.HotSymbolSamples++
			}
			if leaf != "" {
				named[leaf]++
			}
		case ev.Mapping != nil:
			res.MappingUpdates++
			if ev.Mapping.BuildID == t.AllowedBuildIDs[0] {
				res.MappingBuildOK++
			}
		case ev.Loss != nil:
			res.LossEvents++
			res.LostRecords += uint64(ev.Loss.Count)
		}
	}
	stop.Stop()
	res.CaptureSeconds = time.Since(start).Seconds()
	session.Close()
	res.Threads = len(threads)
	for name, n := range named {
		res.TopSymbols = append(res.TopSymbols, top{name, n})
	}
	sort.Slice(res.TopSymbols, func(i, j int) bool { return res.TopSymbols[i].Samples > res.TopSymbols[j].Samples })
	if len(res.TopSymbols) > 5 {
		res.TopSymbols = res.TopSymbols[:5]
	}
	res.Outcome = "samples"
	if res.Samples == 0 {
		res.Outcome = "no_samples"
	}
	return res, nil
}
