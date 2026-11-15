// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/model"
)

// RunUpgradeRollback is the upgrade and rollback test of the PRODUCED binaries (07.08-W3):
//
//	--old-release DIR  release directory of the running (previous) build
//	--new-release DIR  release directory of the candidate build; its version must differ
//
// It installs the old binary on an empty data directory, bootstraps and ingests every signal,
// records the query and investigation answers, stops it gracefully and copies the directory (the
// pre-upgrade backup). Then it
//  1. upgrades: starts the new binary on the same directory; every original receipt, the query and
//     the investigation must be answered exactly as before;
//  2. rolls back the documented way (docs/operations/upgrade.md): the pre-upgrade copy is restored
//     and the old binary started; again every answer must equal the first one;
//  3. crosses schema versions: on a copy the persisted control-state format marker is set to
//     the future (2) and to the past (0); the new binary must refuse each with the typed reason
//     schema_newer / schema_old, stay unready and not acknowledge intake; with the marker restored
//     it must be ready again and answer as before;
//  4. records, without asserting a promise the product does not make, what the OLD binary does on a
//     directory the NEW binary has written (docs: not supported).
//
// To register (tools/smoke/main.go is frozen for lanes; the parent adds it): case "upgrade-rollback": return RunUpgradeRollback(os.Args[2:]).
// Until then it runs through TestUpgradeRollbackOfProducedBinaries (env SOUNDPOST_UPGRADE_*).
// Known red: the schema-crossing stage fails against the current product, which exits at start with reason=corrupt
// instead of answering schema_newer/schema_old (see the lane 4 wave 12 report, item for lane 1).
func RunUpgradeRollback(args []string) (result error) {
	stage := "upgrade_flags"
	defer func() { result = annotateSmokeFailure("upgrade_rollback", stage, model.ID{}, result) }()
	f := flag.NewFlagSet("upgrade-rollback", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	artifact := f.String("artifact-dir", "", "sanitized result directory")
	oldRelease := f.String("old-release", "", "release directory of the previous build")
	newRelease := f.String("new-release", "", "release directory of the candidate build")
	arch := f.String("arch", "amd64", "linux architecture directory inside each release")
	if err := f.Parse(args); err != nil {
		return err
	}
	if *artifact == "" || *oldRelease == "" || *newRelease == "" {
		return errors.New("--artifact-dir, --old-release and --new-release are required")
	}
	if err := os.MkdirAll(*artifact, 0o700); err != nil {
		return err
	}
	report := map[string]any{"version": 1}
	oldReport, newReport := map[string]any{}, map[string]any{}
	oldBin := filepath.Join(*oldRelease, "linux-"+*arch, "soundpost")
	newBin := filepath.Join(*newRelease, "linux-"+*arch, "soundpost")
	stage = "upgrade_identity"
	oldHostI, err := newBinaryHost(oldBin, *oldRelease, oldReport)
	if err != nil {
		return err
	}
	oldHost := oldHostI.(*binaryHost)
	defer oldHost.cleanup()
	newHostI, err := newBinaryHost(newBin, *newRelease, newReport)
	if err != nil {
		return err
	}
	newHost := newHostI.(*binaryHost)
	newHost.cleanup() // only its identity is used: it runs on the old host's directory
	newHost.dir, newHost.holdDir = oldHost.dir, oldHost.holdDir
	report["old"], report["new"] = oldReport, newReport
	if oldReport["binary_version"] == newReport["binary_version"] || oldReport["binary_sha256"] == newReport["binary_sha256"] {
		return &smokeFailure{Stage: stage, Code: "old_and_new_are_the_same_build"}
	}

	// ---- the old build serves and acknowledges data ----
	stage = "upgrade_old_install"
	run, err := oldHost.start()
	if err != nil {
		return err
	}
	defer func() { run.kill() }()
	cert, err := run.waitCertificate()
	if err != nil {
		return err
	}
	site := newInstallSite(run.url(), cert)
	if err = run.release(); err != nil {
		return err
	}
	if err = run.waitReady(60 * time.Second); err != nil {
		return err
	}
	token, err := run.bootstrapToken()
	if err != nil {
		return err
	}
	fx, err := bootstrapInstallation(site, token)
	if err != nil {
		return err
	}
	receipts, err := ingestEverySignal(site, fx)
	if err != nil {
		return err
	}
	queryBefore, err := queryInstalled(site, fx)
	if err != nil {
		return err
	}
	investigateBefore, err := investigateInstalled(site, fx)
	if err != nil {
		return err
	}
	if err = run.stop(); err != nil {
		return err
	}
	backup, err := os.MkdirTemp("", "soundpost-upgrade-backup-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(backup)
	if err = copyDataDir(oldHost.dir, backup); err != nil {
		return err
	}
	report["receipts"] = len(receipts)

	// same: a started binary on the directory must answer exactly what the old build answered.
	same := func(label string, h *binaryHost) (installRun, error) {
		stage = "upgrade_" + label + "_start"
		r, err := h.start()
		if err != nil {
			return nil, err
		}
		if _, err = r.waitCertificate(); err != nil {
			r.kill()
			return nil, err
		}
		site.base = r.url()
		if err = r.release(); err != nil {
			r.kill()
			return nil, err
		}
		stage = "upgrade_" + label + "_ready"
		if err = r.waitReady(60 * time.Second); err != nil {
			r.kill()
			return nil, err
		}
		stage = "upgrade_" + label + "_answers"
		if err = requireSameAnswers(site, fx, receipts, queryBefore, investigateBefore); err != nil {
			r.kill()
			return nil, err
		}
		return r, nil
	}

	// ---- 1. upgrade: the new binary on the old directory ----
	r, err := same("new_on_old_data", newHost)
	if err != nil {
		return err
	}
	report["upgrade_new_binary_answers_identically"] = true
	if err = r.stop(); err != nil {
		return err
	}
	report["upgrade_graceful_stop"] = true

	// ---- 4. recorded: the old binary on a directory the new binary wrote ----
	stage = "upgrade_old_on_new_data"
	if r, err = oldHost.start(); err != nil {
		return err
	}
	if _, err = r.waitCertificate(); err != nil {
		r.kill()
		return err
	}
	_ = r.release()
	deadline, last := time.Now().Add(30*time.Second), installReadiness{}
	for time.Now().Before(deadline) {
		if st, e := r.readyOnce(); e == nil {
			last = st
			if st.Ready || (st.Reason != "" && st.Reason != "starting" && st.Reason != "startup_hold") {
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	if last.Ready {
		site.base = r.url()
		if err = requireSameAnswers(site, fx, receipts, queryBefore, investigateBefore); err != nil {
			r.kill()
			return err
		}
		report["old_binary_on_new_data"] = "ready_and_answers_identically"
	} else {
		report["old_binary_on_new_data"] = "unready:" + last.Reason
	}
	r.kill()

	// ---- 2. rollback: the pre-upgrade copy and the old binary ----
	stage = "rollback_restore"
	if err = replaceDataDir(oldHost.dir, backup); err != nil {
		return err
	}
	if r, err = same("rollback_old_on_backup", oldHost); err != nil {
		return err
	}
	report["rollback_restored_backup_answers_identically"] = true
	if err = r.stop(); err != nil {
		return err
	}

	// ---- 3. schema versions: future and past markers on the new binary ----
	for _, c := range []struct {
		name   string
		marker uint8
		reason string
	}{{"future", 2, "schema_newer"}, {"past", 0, "schema_old"}} {
		stage = "schema_" + c.name
		original, err := setSchemaMarker(oldHost.dir, c.marker)
		if err != nil {
			return err
		}
		report["schema_marker_original"] = original
		run, err := newHost.start()
		if err != nil {
			return err
		}
		if _, err = run.waitCertificate(); err != nil {
			run.kill()
			return err
		}
		site.base = run.url()
		_ = run.release()
		var got installReadiness
		deadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(deadline) {
			if st, e := run.readyOnce(); e == nil {
				got = st
				if st.Ready || st.Reason == c.reason {
					break
				}
			}
			time.Sleep(100 * time.Millisecond)
		}
		if got.Ready || got.Reason != c.reason {
			run.kill()
			tail := oldHost.logs.String()
			if len(tail) > 600 {
				tail = tail[len(tail)-600:]
			}
			fmt.Fprintf(os.Stderr, "schema %s: ready answer %+v; server log tail:\n%s\n", c.name, got, tail)
			return &smokeFailure{Stage: stage, Code: "wrong_schema_decision_" + got.Reason}
		}
		status, raw, e := site.ingest(receipts[0].batch, fx.credential)
		if e == nil && status == 200 {
			run.kill()
			return &smokeFailure{Stage: stage, Code: "acknowledged_with_unsupported_schema"}
		}
		_ = raw
		report["schema_"+c.name+"_reason"] = got.Reason
		run.kill()
		if _, err = setSchemaMarker(oldHost.dir, original); err != nil {
			return err
		}
	}
	stage = "schema_restored"
	if r, err = same("schema_restored", newHost); err != nil {
		return err
	}
	report["schema_marker_restored_answers_identically"] = true
	if err = r.stop(); err != nil {
		return err
	}
	stage = "upgrade_artifact"
	encoded, _ := json.MarshalIndent(report, "", "  ")
	return os.WriteFile(filepath.Join(*artifact, "upgrade-rollback.json"), encoded, 0o600)
}

// requireSameAnswers replays every acknowledged batch, compares its receipt, the query result and the investigation.
func requireSameAnswers(site *installSite, fx *installFixture, receipts []installReceipt, query, investigate []byte) error {
	for i, rc := range receipts {
		status, raw, err := site.ingest(rc.batch, fx.credential)
		if err = requireSmokeResponse("replay_"+rc.name, status, 200, raw, err); err != nil {
			return err
		}
		var again model.Receipt
		if err = json.Unmarshal(raw, &again); err != nil {
			return err
		}
		want, _ := model.CanonicalJSON(rc.receipt)
		got, _ := model.CanonicalJSON(again)
		if !bytes.Equal(want, got) {
			return &smokeFailure{Stage: "same_answers", Code: "receipt_changed", Actual: i}
		}
	}
	q, err := queryInstalled(site, fx)
	if err != nil {
		return err
	}
	if !bytes.Equal(q, query) {
		return &smokeFailure{Stage: "same_answers", Code: "query_changed"}
	}
	inv, err := investigateInstalled(site, fx)
	if err != nil {
		return err
	}
	if !bytes.Equal(inv, investigate) {
		return &smokeFailure{Stage: "same_answers", Code: "investigation_changed"}
	}
	return nil
}

// setSchemaMarker rewrites the control state's persisted format marker of a stopped installation and returns the old value.
func setSchemaMarker(dir string, marker uint8) (uint8, error) {
	app, err := appcore.Open(dir)
	if err != nil {
		return 0, err
	}
	var original uint8
	err = app.Control.Update(context.Background(), func(st *model.ControlState) error {
		original = st.BearerHashKeyVersion
		st.BearerHashKeyVersion = marker
		return nil
	})
	if cerr := app.Close(); err == nil {
		err = cerr
	}
	return original, err
}

// copyDataDir copies a data directory keeping modes (files stay 0600, directories 0700).
func copyDataDir(src, dst string) error {
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		info, err := d.Info()
		if err != nil {
			return err
		}
		switch {
		case d.IsDir():
			return os.MkdirAll(target, info.Mode().Perm())
		case info.Mode().IsRegular():
			raw, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			return os.WriteFile(target, raw, info.Mode().Perm())
		}
		return fmt.Errorf("unexpected non-regular entry %s in the data directory", rel)
	})
}

// replaceDataDir makes dir's content equal to backup's.
func replaceDataDir(dir, backup string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if err = os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
			return err
		}
	}
	return copyDataDir(backup, dir)
}
