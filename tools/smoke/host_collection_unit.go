// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/arynyklas/soundpost/internal/agent"
	"github.com/arynyklas/soundpost/internal/model"
)

// The agent-unit step of the host-collection smoke runs the COMPILED agent as a
// systemd service built from the shipped deploy/systemd/soundpost-agent.service,
// and asserts what the node stored from it. An unprivileged run has no system
// manager to install into, so the unit runs in the user's service manager
// (`systemctl --user`, same unit file semantics, same sandboxing directives
// through an unprivileged user namespace). A user manager cannot do a few things a
// system one does, so exactly these lines of the shipped unit are replaced and
// every other line, including the whole hardening block, is used verbatim:
//
//	User=, Group=      removed (a user manager cannot switch account)
//	StateDirectory=    renamed to a per-run name (state lives in $XDG_STATE_HOME)
//	LoadCredential=    the source file is the smoke's credential file
//	ExecStart=         the smoke's binary and configuration
//	ProtectHome=yes    ProtectHome=tmpfs plus BindReadOnlyPaths= of the one directory
//	                   that holds the binary and configuration (they live under
//	                   $HOME; the system unit finds them in /usr/local/bin and /etc)
//
// The step fails if any of those lines is missing from the shipped unit, so a
// change of the unit is noticed here, and it reports every replaced line.

// hcUnitFacts are the process facts read from /proc/<pid>/status of the running
// service.
type hcUnitFacts struct {
	CapEff, CapBnd, NoNewPrivs, Seccomp string
}

func hcCommand(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return out.String(), err
}

// hcDeriveUserUnit applies the replacements above to the shipped unit and
// returns the new text and a description of every replaced line.
func hcDeriveUserUnit(shipped, stateName, credSource, execStart, bindDir string) (string, []string, error) {
	var out strings.Builder
	var notes []string
	seen := map[string]int{}
	for _, line := range strings.Split(shipped, "\n") {
		switch {
		case strings.HasPrefix(line, "User="), strings.HasPrefix(line, "Group="):
			seen["account"]++
			notes = append(notes, "removed "+strings.SplitN(line, "=", 2)[0]+"=")
			continue
		case strings.HasPrefix(line, "StateDirectory="):
			seen["state"]++
			notes = append(notes, "StateDirectory= renamed per run")
			line = "StateDirectory=" + stateName
		case strings.HasPrefix(line, "LoadCredential="):
			seen["credential"]++
			notes = append(notes, "LoadCredential= source file is the smoke's credential file")
			line = "LoadCredential=source.token:" + credSource
		case strings.HasPrefix(line, "ExecStart="):
			seen["exec"]++
			notes = append(notes, "ExecStart= binary and configuration of the smoke")
			line = "ExecStart=" + execStart
		case line == "ProtectHome=yes":
			seen["home"]++
			notes = append(notes, "ProtectHome=yes -> ProtectHome=tmpfs + BindReadOnlyPaths= of the smoke's directory")
			line = "ProtectHome=tmpfs\nBindReadOnlyPaths=" + bindDir
		}
		out.WriteString(line)
		out.WriteString("\n")
	}
	if seen["account"] != 2 || seen["state"] != 1 || seen["credential"] != 1 || seen["exec"] != 1 || seen["home"] != 1 {
		return "", nil, fmt.Errorf("the shipped unit no longer has the lines this step replaces: %v", seen)
	}
	return strings.TrimRight(out.String(), "\n") + "\n", notes, nil
}

func hcProcStatus(pid string) (hcUnitFacts, error) {
	raw, err := os.ReadFile("/proc/" + pid + "/status")
	if err != nil {
		return hcUnitFacts{}, err
	}
	var f hcUnitFacts
	for _, line := range strings.Split(string(raw), "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch k {
		case "CapEff":
			f.CapEff = v
		case "CapBnd":
			f.CapBnd = v
		case "NoNewPrivs":
			f.NoNewPrivs = v
		case "Seccomp":
			f.Seccomp = v
		}
	}
	return f, nil
}

func hcShow(unit string, props ...string) (map[string]string, error) {
	args := []string{"--user", "show", unit}
	for _, p := range props {
		args = append(args, "-p", p)
	}
	out, err := hcCommand("systemctl", args...)
	m := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			m[k] = v
		}
	}
	return m, err
}

// hcAgentUnit runs the step. It records a NotRun row, and returns nil, when the
// host has no systemd user manager at all.
func hcAgentUnit(unitFile, binary string, cfg agent.Config, node *hcNode, runID model.ID, work string, report *hcReport) error {
	const row = "agent_systemd_unit"
	if raw, err := os.ReadFile("/proc/1/comm"); err != nil || strings.TrimSpace(string(raw)) != "systemd" {
		report.NotRun[row] = "PID 1 is not systemd on this host"
		return nil
	}
	if out, err := hcCommand("systemctl", "--user", "is-system-running"); err != nil && !strings.Contains(out, "degraded") {
		report.NotRun[row] = "no systemd user manager is reachable for this account (systemctl --user: " + strings.TrimSpace(out) + ")"
		return nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	// everything the unit reads lives in one directory, bound read-only
	bind, err := os.MkdirTemp(home, "soundpost-unit-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(bind)
	if err := os.Chmod(bind, 0700); err != nil {
		return err
	}
	name := "soundpost-agent-" + hex.EncodeToString(runID[:4])
	unit := name + ".service"
	stateRoot := os.Getenv("XDG_STATE_HOME")
	if stateRoot == "" {
		stateRoot = filepath.Join(home, ".local", "state")
	}
	runtimeDir := os.Getenv("XDG_RUNTIME_DIR")
	if runtimeDir == "" {
		runtimeDir = "/run/user/" + strconv.Itoa(os.Getuid())
	}

	copyFile := func(from, to string, mode os.FileMode) error {
		raw, err := os.ReadFile(from)
		if err != nil {
			return err
		}
		return os.WriteFile(to, raw, mode)
	}
	if err := copyFile(binary, filepath.Join(bind, "soundpost-agent"), 0700); err != nil {
		return err
	}
	if err := copyFile(cfg.CAFile, filepath.Join(bind, "ca.pem"), 0600); err != nil {
		return err
	}
	credSource := filepath.Join(work, "unit-source.token")
	if err := os.WriteFile(credSource, []byte(node.cred+"\n"), 0600); err != nil {
		return err
	}
	defer os.Remove(credSource)

	// sources: the file and syslog sources of the in-process run, copied next
	// to the binary (the unit has a private /tmp)
	unitCfg := cfg
	unitCfg.CAFile = filepath.Join(bind, "ca.pem")
	unitCfg.CredentialFile = filepath.Join(runtimeDir, "credentials", unit, "source.token")
	unitCfg.StateDir = filepath.Join(stateRoot, name)
	unitCfg.Host = &agent.HostConfig{Interval: agent.Duration(time.Second), Allow: []string{"cpu", "memory", "load", "filesystem", "process_count"},
		Filesystems: []agent.FilesystemConfig{{Alias: "data", Path: bind}}}
	unitCfg.Logs = nil
	for _, l := range cfg.Logs {
		var from string
		switch {
		case l.File != nil:
			from = l.File.Path
		case l.Syslog != nil && l.Syslog.Path != "":
			from = l.Syslog.Path
		default:
			continue
		}
		if l.Name == "denied" {
			continue
		}
		to := filepath.Join(bind, l.Name+".log")
		if err := copyFile(from, to, 0600); err != nil {
			return err
		}
		if l.File != nil {
			spec := *l.File
			spec.Path = to
			l.File = &spec
		} else {
			spec := *l.Syslog
			spec.Path = to
			l.Syslog = &spec
		}
		unitCfg.Logs = append(unitCfg.Logs, l)
	}
	rawCfg, err := json.Marshal(unitCfg)
	if err != nil {
		return err
	}
	cfgFile := filepath.Join(bind, "agent.json")
	if err := os.WriteFile(cfgFile, rawCfg, 0600); err != nil {
		return err
	}

	shipped, err := os.ReadFile(unitFile)
	if err != nil {
		return err
	}
	derived, notes, err := hcDeriveUserUnit(string(shipped), name, credSource, filepath.Join(bind, "soundpost-agent")+" -config="+cfgFile, bind)
	if err != nil {
		return err
	}
	unitDir := os.Getenv("XDG_CONFIG_HOME")
	if unitDir == "" {
		unitDir = filepath.Join(home, ".config")
	}
	unitDir = filepath.Join(unitDir, "systemd", "user")
	if err := os.MkdirAll(unitDir, 0755); err != nil {
		return err
	}
	unitPath := filepath.Join(unitDir, unit)
	if err := os.WriteFile(unitPath, []byte(derived), 0644); err != nil {
		return err
	}
	cleanup := func() {
		hcCommand("systemctl", "--user", "stop", unit)
		hcCommand("systemctl", "--user", "reset-failed", unit)
		os.Remove(unitPath)
		hcCommand("systemctl", "--user", "daemon-reload")
		os.RemoveAll(filepath.Join(stateRoot, name))
	}
	defer cleanup()
	report.Rows[row+"_deviations"] = strings.Join(notes, "; ")

	if out, err := hcCommand("systemd-analyze", "--user", "verify", unitPath); err != nil {
		fmt.Fprintf(os.Stderr, "systemd-analyze verify: %v\n%s\n", err, out)
		return hcFail("hc_unit_verify", 1, 0)
	}
	report.Rows[row+"_verify"] = "systemd-analyze --user verify: no finding"
	if out, err := hcCommand("systemctl", "--user", "daemon-reload"); err != nil {
		return fmt.Errorf("daemon-reload: %v: %s", err, out)
	}

	before, err := node.scan(model.Metric)
	if err != nil {
		return err
	}
	baseline := len(hcSeries(before, "host_processes_total"))
	if out, err := hcCommand("systemctl", "--user", "start", unit); err != nil {
		st, _ := hcCommand("systemctl", "--user", "status", "--no-pager", "-l", unit)
		j, _ := hcCommand("journalctl", "--user", "--no-pager", "-u", unit, "-n", "30")
		fmt.Fprintf(os.Stderr, "start: %v: %s\n%s\n%s\n", err, out, st, j)
		return hcFail("hc_unit_start", 1, 0)
	}

	// the service delivers host samples through the credential systemd loaded
	deadline := time.Now().Add(40 * time.Second)
	arrived := 0
	for time.Now().Before(deadline) {
		rows, err := node.scan(model.Metric)
		if err != nil {
			return err
		}
		if arrived = len(hcSeries(rows, "host_processes_total")) - baseline; arrived >= 3 {
			break
		}
		if p, _ := hcShow(unit, "ActiveState"); p["ActiveState"] == "failed" {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	props, err := hcShow(unit, "ActiveState", "SubState", "MainPID", "NRestarts", "Result", "FragmentPath")
	if err != nil {
		return err
	}
	if props["ActiveState"] != "active" || props["SubState"] != "running" || props["NRestarts"] != "0" {
		st, _ := hcCommand("systemctl", "--user", "status", "--no-pager", "-l", unit)
		j, _ := hcCommand("journalctl", "--user", "--no-pager", "-u", unit, "-n", "30")
		fmt.Fprintf(os.Stderr, "unit state %v\n%s\n%s\n", props, st, j)
		return hcFail("hc_unit_running", 0, 1)
	}
	if arrived < 3 {
		return hcFail("hc_unit_delivered_samples", arrived, 3)
	}
	report.Observed["unit_host_sample_points_stored"] = float64(arrived)
	report.Rows[row+"_credential"] = "asserted: the service authenticated with the credential systemd loaded (LoadCredential=, $XDG_RUNTIME_DIR/credentials/<unit>/source.token) - the agent has no other credential, and the node stored its samples"

	// the sandbox that the unit asks for is on the running process
	facts, err := hcProcStatus(props["MainPID"])
	if err != nil {
		return err
	}
	if facts.CapEff != "0000000000000000" || facts.CapBnd != "0000000000000000" || facts.NoNewPrivs != "1" || facts.Seccomp != "2" {
		fmt.Fprintf(os.Stderr, "process facts %+v\n", facts)
		return hcFail("hc_unit_sandbox_facts", 0, 1)
	}
	report.Rows[row+"_sandbox"] = fmt.Sprintf("asserted on the running main process: CapEff=%s CapBnd=%s (CapabilityBoundingSet= empty), NoNewPrivs=%s, Seccomp=%s (filter) - from /proc/<pid>/status", facts.CapEff, facts.CapBnd, facts.NoNewPrivs, facts.Seccomp)
	if out, err := hcCommand("systemd-analyze", "--user", "security", "--no-pager", unit); err == nil {
		lines := strings.Split(strings.TrimSpace(out), "\n")
		report.Rows[row+"_exposure"] = strings.TrimSpace(lines[len(lines)-1])
	}

	// a stop is clean; nothing the service printed carries the credential or content
	if out, err := hcCommand("systemctl", "--user", "stop", unit); err != nil {
		return fmt.Errorf("stop: %v: %s", err, out)
	}
	props, _ = hcShow(unit, "ActiveState", "Result", "ExecMainStatus")
	if props["Result"] != "success" {
		fmt.Fprintf(os.Stderr, "after stop %v\n", props)
		return hcFail("hc_unit_stop_result", 1, 0)
	}
	j, _ := hcCommand("journalctl", "--user", "--no-pager", "-o", "cat", "-u", unit)
	for _, canary := range []string{"hunter2", "BODY-CANARY", "SYSLOG-CANARY", node.cred} {
		if strings.Contains(j, canary) {
			return hcFail("hc_unit_log_privacy", 1, 0)
		}
	}
	report.Rows[row] = fmt.Sprintf("asserted: soundpost-agent ran as a systemd service (%s, user manager) built from the shipped unit, ActiveState=active/running with NRestarts=0, stored %d host sample points, stopped with Result=success, and its journal carries no credential or unregistered content", name, arrived)
	return nil
}
