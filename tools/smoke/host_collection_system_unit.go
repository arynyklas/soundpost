// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/arynyklas/soundpost/internal/agent"
	"github.com/arynyklas/soundpost/internal/model"
)

// The system-unit step of the host-collection smoke (`--agent-system-unit`, root on a Linux host whose PID 1 is
// systemd) installs the shipped deploy/systemd/soundpost-agent.service BYTE FOR BYTE into the SYSTEM manager,
// at the paths that unit names (/usr/local/bin/soundpost-agent, /etc/soundpost/agent/agent.json, the credential
// /etc/soundpost/agent/source.token loaded by LoadCredential=) and starts it as its own `User=soundpost-agent`
// account. Unlike the user-manager step (host_collection_unit.go) no line of the unit is replaced: this is the
// shape an operator installs. It asserts what the node stored from it and what the running process is.
//
// It changes the host (an account, three paths, one unit) and removes all of it again, so it refuses to run when
// any of those paths already exists: a host that carries a real installation is never touched.

const (
	hcSysUnitName   = "soundpost-agent.service"
	hcSysUnitPath   = "/etc/systemd/system/" + hcSysUnitName
	hcSysBinary     = "/usr/local/bin/soundpost-agent"
	hcSysConfDir    = "/etc/soundpost/agent"
	hcSysAccount    = "soundpost-agent"
	hcSysStateDir   = "/var/lib/soundpost-agent"
	hcSysCredential = "/run/credentials/" + hcSysUnitName + "/source.token"
)

func hcSysShow(props ...string) (map[string]string, error) {
	args := []string{"show", hcSysUnitName}
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

// hcProcUIDs reads the real, effective, saved and filesystem uid of a process.
func hcProcUIDs(pid string) (string, error) {
	raw, err := os.ReadFile("/proc/" + pid + "/status")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if k, v, ok := strings.Cut(line, ":"); ok && k == "Uid" {
			return strings.Join(strings.Fields(v), " "), nil
		}
	}
	return "", errors.New("no Uid line in /proc/<pid>/status")
}

func hcAgentSystemUnit(unitFile, binary string, cfg agent.Config, node *hcNode, runID model.ID, work string, report *hcReport) (result error) {
	const row = "agent_systemd_system_unit"
	if os.Geteuid() != 0 {
		report.NotRun[row] = "not root: the system manager needs root to install a unit"
		return nil
	}
	if raw, err := os.ReadFile("/proc/1/comm"); err != nil || strings.TrimSpace(string(raw)) != "systemd" {
		report.NotRun[row] = "PID 1 is not systemd on this host"
		return nil
	}
	if out, err := hcCommand("systemctl", "is-system-running"); err != nil && !strings.Contains(out, "degraded") {
		report.NotRun[row] = "the system manager is not running (systemctl is-system-running: " + strings.TrimSpace(out) + ")"
		return nil
	}
	for _, p := range []string{hcSysUnitPath, hcSysBinary, hcSysConfDir, hcSysStateDir} {
		if _, err := os.Lstat(p); err == nil {
			return fmt.Errorf("%s already exists: this step installs and then removes its own copy and will not touch an existing installation", p)
		}
	}
	if _, err := user.Lookup(hcSysAccount); err == nil {
		return fmt.Errorf("the account %s already exists: this step creates and removes its own", hcSysAccount)
	}
	shipped, err := os.ReadFile(unitFile)
	if err != nil {
		return err
	}
	// the unit under test is the shipped one: it must still name exactly the paths installed here
	for _, want := range []string{"User=" + hcSysAccount, "Group=" + hcSysAccount, "StateDirectory=" + hcSysAccount,
		"LoadCredential=source.token:" + hcSysConfDir + "/source.token", "ExecStart=" + hcSysBinary + " -config=" + hcSysConfDir + "/agent.json"} {
		if !bytes.Contains(shipped, []byte("\n"+want+"\n")) {
			return fmt.Errorf("the shipped unit no longer has the line %q this step installs against", want)
		}
	}

	cleanup := func() {
		hcCommand("systemctl", "stop", hcSysUnitName)
		hcCommand("systemctl", "reset-failed", hcSysUnitName)
		os.Remove(hcSysUnitPath)
		os.Remove(hcSysBinary)
		os.RemoveAll(hcSysConfDir)
		os.Remove("/etc/soundpost") // only if empty
		hcCommand("systemctl", "daemon-reload")
		os.RemoveAll(hcSysStateDir)
		hcCommand("userdel", hcSysAccount)
	}
	if out, err := hcCommand("useradd", "--system", "--shell", "/usr/sbin/nologin", "--no-create-home", hcSysAccount); err != nil {
		return fmt.Errorf("useradd: %v: %s", err, out)
	}
	defer cleanup()
	account, err := user.Lookup(hcSysAccount)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(hcSysConfDir, 0o755); err != nil {
		return err
	}
	if raw, err := os.ReadFile(binary); err != nil {
		return err
	} else if err := os.WriteFile(hcSysBinary, raw, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(hcSysConfDir, "source.token"), []byte(node.cred+"\n"), 0o600); err != nil {
		return err
	}
	ca, err := os.ReadFile(cfg.CAFile)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(hcSysConfDir, "ca.pem"), ca, 0o644); err != nil {
		return err
	}
	sysCfg := cfg
	sysCfg.CAFile = filepath.Join(hcSysConfDir, "ca.pem")
	sysCfg.CredentialFile = hcSysCredential
	sysCfg.StateDir = hcSysStateDir
	sysCfg.Host = &agent.HostConfig{Interval: agent.Duration(time.Second), Allow: []string{"cpu", "memory", "load", "filesystem", "process_count"},
		Filesystems: []agent.FilesystemConfig{{Alias: "data", Path: "/"}}}
	sysCfg.Logs = nil
	rawCfg, err := json.Marshal(sysCfg)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(hcSysConfDir, "agent.json"), rawCfg, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(hcSysUnitPath, shipped, 0o644); err != nil {
		return err
	}
	if installed, err := os.ReadFile(hcSysUnitPath); err != nil || !bytes.Equal(installed, shipped) {
		return errors.New("the installed unit differs from the shipped unit")
	}

	if out, err := hcCommand("systemd-analyze", "verify", hcSysUnitPath); err != nil {
		fmt.Fprintf(os.Stderr, "systemd-analyze verify: %v\n%s\n", err, out)
		return hcFail("hc_system_unit_verify", 1, 0)
	}
	report.Rows[row+"_verify"] = "systemd-analyze verify (system manager): no finding"
	if out, err := hcCommand("systemctl", "daemon-reload"); err != nil {
		return fmt.Errorf("daemon-reload: %v: %s", err, out)
	}
	before, err := node.scan(model.Metric)
	if err != nil {
		return err
	}
	baseline := len(hcSeries(before, "host_processes_total"))
	if out, err := hcCommand("systemctl", "start", hcSysUnitName); err != nil {
		st, _ := hcCommand("systemctl", "status", "--no-pager", "-l", hcSysUnitName)
		j, _ := hcCommand("journalctl", "--no-pager", "-u", hcSysUnitName, "-n", "30")
		fmt.Fprintf(os.Stderr, "start: %v: %s\n%s\n%s\n", err, out, st, j)
		return hcFail("hc_system_unit_start", 1, 0)
	}
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
		if p, _ := hcSysShow("ActiveState"); p["ActiveState"] == "failed" {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	props, err := hcSysShow("ActiveState", "SubState", "MainPID", "NRestarts", "Result", "FragmentPath", "User", "Group")
	if err != nil {
		return err
	}
	if props["ActiveState"] != "active" || props["SubState"] != "running" || props["NRestarts"] != "0" || props["FragmentPath"] != hcSysUnitPath {
		st, _ := hcCommand("systemctl", "status", "--no-pager", "-l", hcSysUnitName)
		j, _ := hcCommand("journalctl", "--no-pager", "-u", hcSysUnitName, "-n", "30")
		fmt.Fprintf(os.Stderr, "unit state %v\n%s\n%s\n", props, st, j)
		return hcFail("hc_system_unit_running", 0, 1)
	}
	if arrived < 3 {
		return hcFail("hc_system_unit_delivered_samples", arrived, 3)
	}
	report.Observed["system_unit_host_sample_points_stored"] = float64(arrived)
	report.Rows[row+"_credential"] = "asserted: the service authenticated with the credential systemd loaded (LoadCredential=, " + hcSysCredential + ", the file is 0600 root) and the node stored its samples"

	uids, err := hcProcUIDs(props["MainPID"])
	if err != nil {
		return err
	}
	wantUID := account.Uid
	if props["User"] != hcSysAccount || props["Group"] != hcSysAccount || uids != strings.Join([]string{wantUID, wantUID, wantUID, wantUID}, " ") {
		fmt.Fprintf(os.Stderr, "account facts: show User=%q Group=%q /proc Uid=%q want uid %s\n", props["User"], props["Group"], uids, wantUID)
		return hcFail("hc_system_unit_account", 0, 1)
	}
	facts, err := hcProcStatus(props["MainPID"])
	if err != nil {
		return err
	}
	if facts.CapEff != "0000000000000000" || facts.CapBnd != "0000000000000000" || facts.NoNewPrivs != "1" || facts.Seccomp != "2" {
		fmt.Fprintf(os.Stderr, "process facts %+v\n", facts)
		return hcFail("hc_system_unit_sandbox_facts", 0, 1)
	}
	report.Rows[row+"_account"] = fmt.Sprintf("asserted: User=%s Group=%s (systemctl show), the main process runs as uid %s %s (/proc/<pid>/status), not root", props["User"], props["Group"], wantUID, hcSysAccount)
	report.Rows[row+"_sandbox"] = fmt.Sprintf("asserted on the running main process: CapEff=%s CapBnd=%s, NoNewPrivs=%s, Seccomp=%s (filter)", facts.CapEff, facts.CapBnd, facts.NoNewPrivs, facts.Seccomp)
	if out, err := hcCommand("systemd-analyze", "security", "--no-pager", hcSysUnitName); err == nil {
		lines := strings.Split(strings.TrimSpace(out), "\n")
		report.Rows[row+"_exposure"] = strings.TrimSpace(lines[len(lines)-1])
	}

	if out, err := hcCommand("systemctl", "stop", hcSysUnitName); err != nil {
		return fmt.Errorf("stop: %v: %s", err, out)
	}
	props, _ = hcSysShow("ActiveState", "Result", "ExecMainStatus")
	if props["Result"] != "success" {
		fmt.Fprintf(os.Stderr, "after stop %v\n", props)
		return hcFail("hc_system_unit_stop_result", 1, 0)
	}
	j, _ := hcCommand("journalctl", "--no-pager", "-o", "cat", "-u", hcSysUnitName)
	for _, canary := range []string{"hunter2", "BODY-CANARY", "SYSLOG-CANARY", node.cred} {
		if strings.Contains(j, canary) {
			return hcFail("hc_system_unit_log_privacy", 1, 0)
		}
	}
	report.Rows[row] = fmt.Sprintf("asserted: the shipped unit, installed byte for byte in the SYSTEM manager (%s), ran soundpost-agent as User=%s, ActiveState=active/running with NRestarts=0, stored %d host sample points, stopped with Result=success, and its journal carries no credential or canary; the account, unit, binary, configuration and state were removed again", hcSysUnitPath, hcSysAccount, int(report.Observed["system_unit_host_sample_points_stored"]))
	return nil
}
