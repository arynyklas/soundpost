// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/backup"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/smokecluster"
)

// `soundpost backup create --mode distributed` joins its cluster as the voter of the data directory it
// is given (the other two voters running), backs the installation up from that voter and records the
// source topology; `restore` builds a single-voter root of it and `activate --cluster-seed-out` writes
// the seed of the new cluster, naming the old cluster's node identities as retired.
func TestBackupCLIBacksUpAVoterAndSeedsARestoredCluster(t *testing.T) {
	work := t.TempDir()
	live, dest, authority, keys := filepath.Join(work, "live"), filepath.Join(work, "dest"), filepath.Join(work, "authority"), filepath.Join(work, "keys")
	keysPath, restricted, root := filepath.Join(work, "authority-keys.json"), filepath.Join(work, "authority-restricted.json"), filepath.Join(work, "restored")
	seedInstallation(t, live)
	t.Setenv("SOUNDPOST_ADMIN_PASSWORD", cliAdminPassword)
	run := func(args ...string) {
		t.Helper()
		if err := runBackup(args); err != nil {
			t.Fatalf("soundpost backup %s: %v (prints as %q)", args[0], err, backupFailureLine(err))
		}
	}
	run("keygen", "--key-dir", keys, "--id", "data-kek")
	run("keygen", "--key-dir", keys, "--id", "secret-kek")
	run("authority-keygen", "--out", keysPath, "--restricted-out", restricted, "--id", "authority-1")
	run("authority-init", "--data-dir", live, "--authority-keys", keysPath, "--authority-dir", authority)

	// The installation the three voters continue.
	seed := filepath.Join(work, "cluster.seed")
	app, err := appcore.Open(live)
	if err != nil {
		t.Fatal(err)
	}
	if err = app.WriteClusterSeed(seed); err != nil {
		t.Fatal(err)
	}
	if err = app.Close(); err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll(filepath.Join(work, "cluster"), 0o700); err != nil {
		t.Fatal(err)
	}
	cluster, err := smokecluster.New(filepath.Join(work, "cluster"), seed)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cluster.Close)
	if err = cluster.Open(smokecluster.Voters...); err != nil {
		t.Fatal(err)
	}

	// Voter 3 is stopped; the CLI runs as that voter.
	if err = cluster.Stop(3); err != nil {
		t.Fatal(err)
	}
	cluster.Partition(3, false)
	ca, certificate, key := cluster.Identity(3)
	config := filepath.Join(work, "node-3.json")
	raw, err := json.Marshal(appcore.NodeConfig{NodeID: 3, PeerListen: cluster.ListenAddress(3), PeerSourceIP: smokecluster.PeerSourceIP(3), Certificate: certificate, PrivateKey: key, CA: ca, Seed: seed, Members: cluster.Members(), InitialLeader: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(config, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	node := cluster.NodeDir(3)
	create := []string{"create", "--data-dir", node, "--admin-email", cliAdminEmail, "--key-dir", keys, "--data-kek", "data-kek", "--secret-kek", "secret-kek", "--authority-keys", keysPath, "--authority-dir", authority, "--dest-dir", dest}

	// Without joining the cluster the directory is refused, typed; a directory that is no cluster node
	// is refused as one.
	if err = runBackup(append(append([]string{}, create...), "--mode", "single")); !strings.Contains(backupFailureLine(err), "unsupported_mode") || !strings.Contains(backupFailureLine(err), "--mode distributed") {
		t.Fatalf("a single-mode backup of a voter's directory: %q", backupFailureLine(err))
	}
	other := append([]string{}, create...)
	other[2] = live
	if err = runBackup(append(other, "--mode", "distributed", "--node-id", "3", "--cluster-config", config)); !strings.Contains(backupFailureLine(err), "unsupported_mode") {
		t.Fatalf("--mode distributed on a single installation's directory: %q", backupFailureLine(err))
	}
	run(append(append([]string{}, create...), "--mode", "distributed", "--node-id", "3", "--cluster-config", config)...)

	source, err := backup.NewLocalDestination(dest)
	if err != nil {
		t.Fatal(err)
	}
	names, err := source.List(context.Background(), "backups/")
	if err != nil {
		t.Fatal(err)
	}
	var id string
	for _, name := range names {
		if strings.HasSuffix(name, "/manifest.json") {
			id = strings.TrimSuffix(strings.TrimPrefix(name, "backups/"), "/manifest.json")
		}
	}
	if id == "" {
		t.Fatalf("no backup was created: %v", names)
	}
	backupID, err := model.ParseID(id)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := backup.LoadManifest(context.Background(), source, backupID, backup.KeyDir(keys))
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Topology == nil || manifest.Topology.Voters != 3 || manifest.Topology.SourceNode != 3 || !slices.Equal(manifest.Topology.Retired(), []string{"node-1", "node-2", "node-3"}) {
		t.Fatalf("the backup of voter 3 records %+v", manifest.Topology)
	}

	// Nothing has expired: the command runs against the destination and deletes nothing.
	run("expire", "--key-dir", keys, "--dest-dir", dest)

	run("restore", "--backup-id", id, "--root", root, "--key-dir", keys, "--authority-keys", restricted, "--dest-dir", dest, "--authority-dir", authority)
	restoredSeed := filepath.Join(work, "restored.seed")
	run("activate", "--root", root, "--authority-keys", restricted, "--authority-dir", authority, "--cluster-seed-out", restoredSeed)
	var seeded appcore.ClusterSeed
	if err = json.Unmarshal(mustReadFile(t, restoredSeed), &seeded); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(seeded.Retired, []string{"node-1", "node-2", "node-3"}) {
		t.Fatalf("the restored cluster's seed retires %v", seeded.Retired)
	}
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
