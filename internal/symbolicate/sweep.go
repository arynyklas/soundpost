// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package symbolicate

import (
	"context"
	"io"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// sweepMinAge keeps the sweep away from a container another live process of this
// product has only just created and is about to start.
const sweepMinAge = 30 * time.Second

var sweepName = regexp.MustCompile(`^soundpost-symbolicate-[0-9a-f]{32}$`)

// SweepOCI removes worker containers left behind by a process that could not
// clean up after itself (a killed server or test binary). It only ever removes a
// container whose name is exactly `soundpost-symbolicate-<32 hex>`, whose image
// (as the runtime reports it) is exactly the configured pinned image ID, whose state is `created` or `exited`, and that
// is older than 30 seconds; each is removed by its exact ID with a plain
// `rm <id>` (never `--force`, never a prune, never a name glob). The two runtime
// invocations are:
//
//	<runtime> ps -a --no-trunc --filter ancestor=<pinned image> --filter name=soundpost-symbolicate- --format '{{.ID}}|{{.Names}}|{{.State}}|{{.CreatedAt}}|{{.Image}}'
//	<runtime> rm <exact container id>
//
// It returns the IDs it removed. Only the OCI mode has anything to sweep.
func SweepOCI(ctx context.Context, config Config) []string {
	if config.Mode != "oci" || !validImage(config.OCIImage) || config.OCIRuntime == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, ProcessTimeout)
	defer cancel()
	list := exec.CommandContext(ctx, config.OCIRuntime, "ps", "-a", "--no-trunc", "--filter", "ancestor="+config.OCIImage, "--filter", "name=soundpost-symbolicate-", "--format", "{{.ID}}|{{.Names}}|{{.State}}|{{.CreatedAt}}|{{.Image}}")
	var out limitBuffer
	out.max = 1 << 20
	list.Stdout = &out
	list.Stderr = io.Discard
	if list.Run() != nil {
		return nil
	}
	var removed []string
	for _, line := range strings.Split(string(out.data), "\n") {
		f := strings.SplitN(strings.TrimSpace(line), "|", 5)
		if len(f) != 5 || f[4] != config.OCIImage || f[0] == "" || !sweepName.MatchString(f[1]) || (f[2] != "created" && f[2] != "exited") {
			continue
		}
		created, ok := parseDockerTime(f[3])
		if !ok || time.Since(created) < sweepMinAge {
			continue
		}
		rm := exec.CommandContext(ctx, config.OCIRuntime, "rm", f[0])
		rm.Stdout, rm.Stderr = io.Discard, io.Discard
		if rm.Run() == nil {
			removed = append(removed, f[0])
		}
	}
	return removed
}

// parseDockerTime reads the `{{.CreatedAt}}` form, e.g.
// "2026-11-12 05:10:00 +0500 +05" (the trailing zone name is optional).
func parseDockerTime(s string) (time.Time, bool) {
	for _, layout := range []string{"2006-01-02 15:04:05 -0700 MST", "2006-01-02 15:04:05 -0700"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	if i := strings.LastIndex(s, " "); i > 0 {
		if t, err := time.Parse("2006-01-02 15:04:05 -0700", s[:i]); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}
