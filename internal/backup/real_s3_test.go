// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package backup_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/backup"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
)

// These tests run against a REAL S3-compatible service and are skipped unless one is named in the environment (the in-process
// fake of object_test.go is what every other run uses). The service is a black-box test dependency: the endpoint must be
// HTTPS, and a private CA is trusted through SSL_CERT_FILE. Two buckets with two different service credentials stand for
// the backup destination and the restore authority, exactly as the off-host configuration gate requires.
//
//	SOUNDPOST_REAL_S3_ENDPOINT            https://host:port
//	SOUNDPOST_REAL_S3_REGION              default us-east-1
//	SOUNDPOST_REAL_S3_DEST_BUCKET / _DEST_ACCESS_KEY / _DEST_SECRET_KEY
//	SOUNDPOST_REAL_S3_AUTHORITY_BUCKET / _AUTHORITY_ACCESS_KEY / _AUTHORITY_SECRET_KEY
//
// Every run writes below its own prefix; nothing is deleted.
func realS3Destination(t *testing.T, role string) *backup.S3Destination {
	t.Helper()
	endpoint := os.Getenv("SOUNDPOST_REAL_S3_ENDPOINT")
	if endpoint == "" {
		t.Skip("SOUNDPOST_REAL_S3_ENDPOINT is not set: no real S3-compatible service to run against")
	}
	region := os.Getenv("SOUNDPOST_REAL_S3_REGION")
	if region == "" {
		region = "us-east-1"
	}
	env := func(name string) string {
		v := os.Getenv("SOUNDPOST_REAL_S3_" + role + "_" + name)
		if v == "" {
			t.Fatalf("SOUNDPOST_REAL_S3_%s_%s is not set", role, name)
		}
		return v
	}
	d, err := backup.NewS3Destination(backup.S3Config{Endpoint: endpoint, Region: region, Bucket: env("BUCKET"), Prefix: realS3Prefix(t), AccessKey: env("ACCESS_KEY"), SecretKey: env("SECRET_KEY")})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// realS3Prefix is one prefix per test and run, so reruns never meet an earlier run's objects.
func realS3Prefix(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("gotest-%d", time.Now().UnixNano())
}

func readAll(t *testing.T, d backup.Destination, name string) []byte {
	t.Helper()
	r, err := d.Open(context.Background(), name)
	if err != nil {
		t.Fatalf("open %s: %v", name, err)
	}
	defer r.Close()
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return b
}

func digestHex(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

// rowsDigest is a SHA-256 over the sorted observed times of the rows a read returned.
func rowsDigest(rows map[int64]bool) string {
	times := make([]int64, 0, len(rows))
	for at := range rows {
		times = append(times, at)
	}
	sort.Slice(times, func(i, j int) bool { return times[i] < times[j] })
	h := sha256.New()
	for _, at := range times {
		fmt.Fprintf(h, "%d\n", at)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// The store must honour create-only writes (If-None-Match: *): the second create of a name is refused and the first bytes stay,
// racing creators of one name have exactly one winner, a large object reads back with its digest, and a list sees what was
// created. This is the property the restore authority's conditional HEAD advance rests on.
func TestRealS3DestinationHonoursConditionalCreate(t *testing.T) {
	d := realS3Destination(t, "AUTHORITY")
	ctx := context.Background()

	if err := backup.VerifyConditionalCreate(ctx, d); err != nil {
		t.Fatalf("VerifyConditionalCreate against the real service: %v", err)
	}

	first, second := []byte("first writer"), []byte("second writer that must never replace the first")
	if err := d.Create(ctx, "cc/one", bytes.NewReader(first), int64(len(first))); err != nil {
		t.Fatal(err)
	}
	if err := d.Create(ctx, "cc/one", bytes.NewReader(second), int64(len(second))); !errors.Is(err, backup.ErrExists) {
		t.Fatalf("second create of an existing name: %v, want ErrExists", err)
	}
	if got := readAll(t, d, "cc/one"); !bytes.Equal(got, first) {
		t.Fatalf("the object was replaced: %q", got)
	}
	if _, err := d.Open(ctx, "cc/absent"); !errors.Is(err, backup.ErrNotFound) {
		t.Fatalf("open of an absent object: %v, want ErrNotFound", err)
	}

	const writers = 16
	var wg sync.WaitGroup
	results := make([]error, writers)
	for i := range writers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			body := []byte(fmt.Sprintf("racing writer %02d", i))
			results[i] = d.Create(ctx, "cc/race", bytes.NewReader(body), int64(len(body)))
		}(i)
	}
	wg.Wait()
	winner := -1
	for i, err := range results {
		switch {
		case err == nil && winner < 0:
			winner = i
		case err == nil:
			t.Fatalf("two creators of one name both succeeded (%d and %d)", winner, i)
		case !errors.Is(err, backup.ErrExists):
			t.Fatalf("racing creator %d: %v, want ErrExists", i, err)
		}
	}
	if winner < 0 {
		t.Fatal("no racing creator won")
	}
	if got, want := readAll(t, d, "cc/race"), []byte(fmt.Sprintf("racing writer %02d", winner)); !bytes.Equal(got, want) {
		t.Fatalf("the stored object is not the winner's: %q", got)
	}

	big := make([]byte, 24<<20)
	for i := range big {
		big[i] = byte(i*131 + i>>9)
	}
	if err := d.Create(ctx, "cc/big", bytes.NewReader(big), int64(len(big))); err != nil {
		t.Fatal(err)
	}
	if got := readAll(t, d, "cc/big"); digestHex(got) != digestHex(big) {
		t.Fatalf("a %d byte object did not round-trip: %d bytes, digest %s want %s", len(big), len(got), digestHex(got), digestHex(big))
	}

	names, err := d.List(ctx, "cc/")
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(names)
	want := []string{"cc/big", "cc/one", "cc/race"}
	if fmt.Sprint(names) != fmt.Sprint(want) {
		t.Fatalf("list of cc/: %v, want %v", names, want)
	}
}

// A real backup into the real bucket and a real restore out of it, with the restore authority's journal in a second bucket under
// a second credential: the rows the restored installation serves are digest-equal to the rows the live one served at the backup,
// and a deletion that completed afterwards (checkpointed to the S3 journal by retention) is applied by restoring the OLDER backup.
func TestRealS3BackupRestoreRoundTripDigest(t *testing.T) {
	destS3 := realS3Destination(t, "DEST")
	authS3 := realS3Destination(t, "AUTHORITY")
	l := newLiveWith(t, false)
	ctx := l.ctx

	var installation model.ID
	if err := l.app.Control.View(ctx, func(st control.State) error { installation = st.Installation; return nil }); err != nil {
		t.Fatal(err)
	}
	keys, err := backup.GenerateAuthorityKeys("real-s3-authority")
	if err != nil {
		t.Fatal(err)
	}
	authority, err := backup.NewAuthority(authS3, keys, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = authority.Initialize(ctx, installation); err != nil {
		t.Fatal(err)
	}
	sw := &switchAuthority{inner: authority}
	if err = l.retention.UseAuthority(sw); err != nil {
		t.Fatal(err)
	}
	plane := backup.EngineDataPlane(l.app.Storage)
	svc, err := backup.New(backup.Config{Control: l.app.Control, Data: &hookPlane{DataPlane: plane}, Processed: backup.AppliedProcessed(plane), Authority: sw, Authorizer: l.app.Auth, Keys: l.keys, DataKEK: "data-kek", SecretKEK: "secret-kek", Attempts: backup.DirAttempts(t.TempDir()), Clock: time.Now})
	if err != nil {
		t.Fatal(err)
	}

	for _, at := range []int64{100, 200, 300, 400, 500} {
		l.append(at, "round_trip")
	}
	l.reconcile()
	liveBefore := l.liveRows()
	wantDigest := rowsDigest(liveBefore)
	scope, err := l.app.Auth.InstanceScope(ctx, l.owner, "real s3 backup")
	if err != nil {
		t.Fatal(err)
	}
	older, err := svc.Run(ctx, scope, destS3)
	if err != nil {
		t.Fatalf("backup into the real bucket: %v", err)
	}
	listed, err := destS3.List(ctx, "")
	if err != nil || len(listed) == 0 {
		t.Fatalf("the real bucket lists no backup object: %v %v", listed, err)
	}

	restore := func(t *testing.T, m backup.BackupManifest) (backup.RestoreReport, *restored, map[int64]bool) {
		t.Helper()
		rs, err := backup.NewRestorer(backup.RestoreConfig{Keys: l.keys, Source: destS3, Clock: time.Now})
		if err != nil {
			t.Fatal(err)
		}
		root := l.newRoot()
		report, err := rs.Restore(ctx, m, backup.DestinationRoot(root), sw)
		if err != nil {
			t.Fatalf("restore out of the real bucket: %v", err)
		}
		app, err := appcore.Open(root)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { app.Close() })
		if err = app.Retention.UseAuthority(sw); err != nil {
			t.Fatal(err)
		}
		r := &restored{l: l, root: root, app: app, svc: app.Retention}
		if _, err = rs.Activate(ctx, backup.DestinationRoot(root), activation{Engine: app.Storage, svc: app.Retention, reconcile: app.ArtifactLifecycle.ReconcileRetired}, sw); err != nil {
			t.Fatalf("activation against the real authority: %v", err)
		}
		rows, err := l.rows(app, r.reader())
		if err != nil {
			t.Fatal(err)
		}
		return report, r, rows
	}

	t.Run("round trip without a later deletion is digest-equal", func(t *testing.T) {
		report, _, rows := restore(t, older)
		if report.Tombstones != 0 {
			t.Fatalf("no deletion was made yet but restore applied %d tombstones", report.Tombstones)
		}
		if got := rowsDigest(rows); got != wantDigest {
			t.Fatalf("restored rows digest %s != live rows digest %s (restored %v, live %v)", got, wantDigest, rows, liveBefore)
		}
	})

	t.Run("a deletion checkpointed to the S3 journal is applied to the older backup", func(t *testing.T) {
		if receipt := l.deleteRange(250, 450); receipt.Phase != model.DeletePhaseComplete {
			t.Fatalf("the deletion did not complete: %+v", receipt)
		}
		head, err := authority.Current(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if head.Head.Sequence < 1 || len(head.Tombstones) != 1 {
			t.Fatalf("the real S3 journal does not hold the completed deletion: sequence %d, %d tombstones", head.Head.Sequence, len(head.Tombstones))
		}
		report, _, rows := restore(t, older)
		if report.Tombstones != 1 || report.AuthoritySequence < 1 {
			t.Fatalf("restore did not read the journal head from the real bucket: %+v", report)
		}
		if rows[300] || rows[400] || !rows[100] || !rows[200] || !rows[500] {
			t.Fatalf("restored rows after the deletion of [250,450): %v", rows)
		}
		if got, want := rowsDigest(rows), rowsDigest(l.liveRows()); got != want {
			t.Fatalf("restored rows digest %s != live rows digest after the deletion %s", got, want)
		}
	})
}
