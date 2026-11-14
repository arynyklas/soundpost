// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package config

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/replica"
	"gopkg.in/yaml.v3"
)

// validDistributed is a generic, reserved-name three-node installation with no customer data.
func validDistributed() InstallConfig {
	node := func(id uint64, name string) Node {
		return Node{
			ID: id, Identity: "node-" + name, FailureDomain: "domain-" + name,
			PeerAddress: Endpoint(fmt.Sprintf("https://soundpost-%s.example.invalid:9444", name)), PeerListen: "0.0.0.0:9444",
			Disk:        Disk{ID: "disk-" + name, Volume: "vol-" + name, Path: "/var/lib/soundpost", CapacityBytes: 1 << 40},
			Certificate: "/etc/soundpost/pki/" + name + ".pem", PrivateKey: NewSecretRef("file:/etc/soundpost/pki/" + name + ".key"),
		}
	}
	return InstallConfig{
		Mode: ModeDistributed, ReplicationFactor: 3,
		Cluster:   Cluster{Placement: PlacementSimulated, CA: "/etc/soundpost/pki/ca.pem", Seed: NewSecretRef("file:/etc/soundpost/cluster.seed"), InitialLeader: 1, Revision: 1},
		Nodes:     []Node{node(1, "a"), node(2, "b"), node(3, "c")},
		Listen:    Listen{Address: "0.0.0.0:8443", PublicOrigins: []string{"https://soundpost.example.invalid"}},
		Sources:   []SourcePolicy{{ID: "web", Class: "browser", Origins: []string{"https://app.example.invalid"}}, {ID: "backend", Class: "private"}},
		Quotas:    Quotas{MaxBytesPerSource: 1 << 30, MaxSeriesPerSource: 1000},
		Retention: Retention{Days: map[string]uint32{"metric": 30, "log": 14}},
		Backup:    Backup{Mode: BackupNone},
	}
}

func validOffhost() InstallConfig {
	c := validDistributed()
	c.Backup = Backup{
		Mode:        BackupOffhost,
		Destination: Store{Kind: "s3", Endpoint: "https://objects.example.invalid", Bucket: "backups", Prefix: "soundpost", AccessKey: NewSecretRef("env:SOUNDPOST_DEST_S3_ACCESS_KEY"), SecretKey: NewSecretRef("env:SOUNDPOST_DEST_S3_SECRET_KEY")},
		Authority: Authority{
			Store:          Store{Kind: "s3", Endpoint: "https://authority.example.invalid", Bucket: "authority", Prefix: "soundpost", AccessKey: NewSecretRef("env:SOUNDPOST_AUTHORITY_S3_ACCESS_KEY"), SecretKey: NewSecretRef("env:SOUNDPOST_AUTHORITY_S3_SECRET_KEY")},
			Keys:           NewSecretRef("file:/etc/soundpost/authority.keys"),
			RestrictedKeys: NewSecretRef("file:/etc/soundpost/authority.restricted.keys"),
			SigningNode:    "node-a",
			Capabilities:   Capabilities{ConditionalCreate: true, FreshHead: true, RestrictedRestore: true},
		},
		DataKEKID: "data-kek-1", SecretKEKID: "secret-kek-1", RetentionDays: 30,
	}
	return c
}

func TestValidBaselinesAreAccepted(t *testing.T) {
	for name, c := range map[string]InstallConfig{"distributed": validDistributed(), "offhost": validOffhost()} {
		if err := Validate(c); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	single := validDistributed()
	single.Mode, single.ReplicationFactor, single.Nodes = ModeSingle, 1, single.Nodes[:1]
	single.Cluster = Cluster{}
	if err := Validate(single); err != nil {
		t.Fatalf("single: %v", err)
	}
}

func TestDistributedRejectsSharedIdentityOrMissingVoter(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*InstallConfig)
		rule   string
	}{
		{"shared member identity", func(c *InstallConfig) { c.Nodes[1].Identity = c.Nodes[0].Identity }, "nodes[1].identity"},
		{"shared raft id", func(c *InstallConfig) { c.Nodes[2].ID = c.Nodes[0].ID }, "nodes[2].id"},
		{"zero raft id", func(c *InstallConfig) { c.Nodes[2].ID = 0 }, "nodes[2].id"},
		{"shared volume", func(c *InstallConfig) { c.Nodes[1].Disk.Volume = c.Nodes[0].Disk.Volume }, "nodes[1].disk.volume"},
		{"shared disk device", func(c *InstallConfig) { c.Nodes[2].Disk.ID = c.Nodes[1].Disk.ID }, "nodes[2].disk.id"},
		{"shared failure domain", func(c *InstallConfig) { c.Nodes[1].FailureDomain = c.Nodes[0].FailureDomain }, "nodes[1].failure_domain"},
		{"empty failure domain", func(c *InstallConfig) { c.Nodes[1].FailureDomain = "" }, "nodes[1].failure_domain"},
		{"shared peer address", func(c *InstallConfig) { c.Nodes[1].PeerAddress = c.Nodes[0].PeerAddress }, "nodes[1].peer_address"},
		{"plain http peer", func(c *InstallConfig) { c.Nodes[1].PeerAddress = "http://soundpost-b.example.invalid:9444" }, "nodes[1].peer_address"},
		{"data directories nested", func(c *InstallConfig) { c.Nodes[0].Disk.Path, c.Nodes[1].Disk.Path = "/data", "/data/b" }, "nodes[1].disk.path"},
		{"two nodes is a missing voter", func(c *InstallConfig) { c.Nodes = c.Nodes[:2] }, "nodes"},
		{"four nodes", func(c *InstallConfig) {
			c.Nodes = append(c.Nodes, Node{ID: 4, Identity: "node-d", FailureDomain: "domain-d", PeerAddress: "https://soundpost-d.example.invalid:9444", PeerListen: "0.0.0.0:9444", Disk: Disk{ID: "disk-d", Volume: "vol-d", Path: "/var/lib/soundpost", CapacityBytes: 1}, Certificate: "/etc/soundpost/pki/d.pem", PrivateKey: NewSecretRef("file:/etc/soundpost/pki/d.key")})
		}, "nodes"},
		{"a learner is not a voter", func(c *InstallConfig) { c.Nodes[2].Learner = true }, "nodes[2].learner"},
		{"replication factor two", func(c *InstallConfig) { c.ReplicationFactor = 2 }, "replication_factor"},
		{"replication factor five", func(c *InstallConfig) { c.ReplicationFactor = 5 }, "replication_factor"},
		{"initial leader is not a member", func(c *InstallConfig) { c.Cluster.InitialLeader = 9 }, "cluster.initial_leader"},
		{"shared certificate", func(c *InstallConfig) { c.Nodes[1].Certificate = c.Nodes[0].Certificate }, "nodes[1].certificate"},
		{"shared private key", func(c *InstallConfig) { c.Nodes[1].PrivateKey = c.Nodes[0].PrivateKey }, "nodes[1].private_key"},
		{"no cluster CA", func(c *InstallConfig) { c.Cluster.CA = "" }, "cluster.ca"},
		{"relative CA path", func(c *InstallConfig) { c.Cluster.CA = "ca.pem" }, "cluster.ca"},
		{"no node certificate", func(c *InstallConfig) { c.Nodes[2].Certificate = "" }, "nodes[2].certificate"},
		{"no node key", func(c *InstallConfig) { c.Nodes[2].PrivateKey = SecretRef{} }, "nodes[2].private_key"},
		{"inline key material instead of a file reference", func(c *InstallConfig) { c.Nodes[2].PrivateKey = NewSecretRef("-----BEGIN PRIVATE KEY-----MIIB") }, "nodes[2].private_key"},
		{"env reference where a key file is needed", func(c *InstallConfig) { c.Nodes[2].PrivateKey = NewSecretRef("env:NODE_KEY") }, "nodes[2].private_key"},
		{"relative key file reference", func(c *InstallConfig) { c.Nodes[2].PrivateKey = NewSecretRef("file:keys/c.key") }, "nodes[2].private_key"},
		{"key file reference that climbs out", func(c *InstallConfig) { c.Nodes[2].PrivateKey = NewSecretRef("file:/etc/soundpost/../c.key") }, "nodes[2].private_key"},
		{"seed is not a file reference", func(c *InstallConfig) { c.Cluster.Seed = NewSecretRef("env:SEED") }, "cluster.seed"},
		{"seed missing", func(c *InstallConfig) { c.Cluster.Seed = SecretRef{} }, "cluster.seed"},
		{"placement unattested", func(c *InstallConfig) { c.Cluster.Placement = "" }, "cluster.placement"},
		{"identity not usable in a certificate URI", func(c *InstallConfig) { c.Nodes[0].Identity = "Node A/../x" }, "nodes[0].identity"},
		{"peer listen is not host:port", func(c *InstallConfig) { c.Nodes[0].PeerListen = "9444" }, "nodes[0].peer_listen"},
		{"no disk capacity", func(c *InstallConfig) { c.Nodes[0].Disk.CapacityBytes = 0 }, "nodes[0].disk.capacity_bytes"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := validDistributed()
			tc.mutate(&c)
			err := Validate(c)
			var v *ValidationError
			if !errors.As(err, &v) {
				t.Fatalf("an invalid placement was accepted or mis-typed: %v", err)
			}
			if v.Field != tc.rule {
				t.Fatalf("rejected for %q, want %q (%v)", v.Field, tc.rule, err)
			}
		})
	}
}

// What the engine would accept must be exactly what the generated node files describe.
func TestGeneratedNodeFilesAreTheRealClusterConfig(t *testing.T) {
	c := validDistributed()
	files, err := NodeConfigs(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 3 {
		t.Fatalf("got %d node files", len(files))
	}
	want := map[uint64]string{1: "node-a", 2: "node-b", 3: "node-c"}
	for id, raw := range files {
		var node appcore.NodeConfig
		if err := json.Unmarshal(raw, &node); err != nil {
			t.Fatalf("node %d is not an appcore.NodeConfig: %v", id, err)
		}
		if node.NodeID != id || node.InitialLeader != 1 || node.PeerListen != "0.0.0.0:9444" || node.CA != "/etc/soundpost/pki/ca.pem" || node.Seed != "/etc/soundpost/cluster.seed" {
			t.Fatalf("node %d wrong header: %+v", id, node)
		}
		if err := replica.ValidateMembers(node.Members); err != nil || len(node.Members.Nodes) != 3 {
			t.Fatalf("node %d members rejected by the engine's own validator: %v", id, err)
		}
		own := ""
		for _, m := range node.Members.Nodes {
			if m.ID == id {
				own = m.NodeIdentity
			}
			if m.Learner {
				t.Fatalf("initial member %d is a learner", m.ID)
			}
		}
		if own != want[id] || !strings.HasSuffix(node.Certificate, strings.TrimPrefix(want[id], "node-")+".pem") || !strings.HasSuffix(node.PrivateKey, strings.TrimPrefix(want[id], "node-")+".key") {
			t.Fatalf("node %d identity or key pair mixed up: %q %q %q", id, own, node.Certificate, node.PrivateKey)
		}
		// strict: the real loader refuses unknown fields
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		var strict appcore.NodeConfig
		if err := dec.Decode(&strict); err != nil {
			t.Fatalf("node %d has fields the engine does not know: %v", id, err)
		}
	}
	// Generation refuses what validation refuses.
	c.Nodes[1].Disk.Volume = c.Nodes[0].Disk.Volume
	if _, err := NodeConfigs(c); err == nil {
		t.Fatal("node files were generated for a shared volume")
	}
}

func TestParseIsStrictYAML(t *testing.T) {
	good, err := yaml.Marshal(struct {
		Mode string `yaml:"mode"`
	}{"single"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Parse(good); err != nil {
		t.Fatalf("a document with only known fields must parse: %v", err)
	}
	for name, doc := range map[string]string{
		"unknown field":  "mode: single\nunexpected: 1\n",
		"two documents":  "mode: single\n---\nmode: single\n",
		"not a mapping":  "- a\n- b\n",
		"typo in nested": "mode: distributed\ncluster:\n  placment: simulated\n",
	} {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}

func TestSourcesQuotasRetentionAndGrantsAreChecked(t *testing.T) {
	cases := map[string]func(*InstallConfig){
		"browser source without origins":     func(c *InstallConfig) { c.Sources[0].Origins = nil },
		"wildcard browser origin":            func(c *InstallConfig) { c.Sources[0].Origins = []string{"https://*.example.invalid"} },
		"browser origin with path":           func(c *InstallConfig) { c.Sources[0].Origins = []string{"https://app.example.invalid/x"} },
		"plain http public origin":           func(c *InstallConfig) { c.Listen.PublicOrigins = []string{"http://soundpost.example.invalid"} },
		"private source with browser origin": func(c *InstallConfig) { c.Sources[1].Origins = []string{"https://app.example.invalid"} },
		"duplicate source":                   func(c *InstallConfig) { c.Sources[1].ID = c.Sources[0].ID },
		"zero byte quota":                    func(c *InstallConfig) { c.Quotas.MaxBytesPerSource = 0 },
		"zero series quota":                  func(c *InstallConfig) { c.Quotas.MaxSeriesPerSource = 0 },
		"retention of zero days":             func(c *InstallConfig) { c.Retention.Days["log"] = 0 },
		"retention of unknown signal":        func(c *InstallConfig) { c.Retention.Days["telemetry"] = 5 },
		"grant to an undeclared source": func(c *InstallConfig) {
			c.CollectorGrants = []CollectorGrant{{Collector: "host", Source: "ghost", Kinds: []string{"metric"}}}
		},
		"grant of an unknown signal": func(c *InstallConfig) {
			c.CollectorGrants = []CollectorGrant{{Collector: "host", Source: "backend", Kinds: []string{"x"}}}
		},
		"public listen address without a port": func(c *InstallConfig) { c.Listen.Address = "0.0.0.0" },
	}
	for name, mutate := range cases {
		c := validDistributed()
		mutate(&c)
		if Validate(c) == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
	c := validDistributed()
	c.CollectorGrants = []CollectorGrant{{Collector: "host", Source: "backend", Kinds: []string{"metric", "log"}}}
	if err := Validate(c); err != nil {
		t.Fatalf("an optional collector grant for a declared source: %v", err)
	}
}

// ---- off-host backup ----

type fakeProbe struct {
	createErr, headErr error
	head               AuthorityHead
	creates, reads     int
}

func (p *fakeProbe) VerifyConditionalCreate(context.Context) error { p.creates++; return p.createErr }
func (p *fakeProbe) CurrentHead(context.Context) (AuthorityHead, error) {
	p.reads++
	return p.head, p.headErr
}

func TestOffhostBackupRequiresAuthorityCASAndFreshHead(t *testing.T) {
	now := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	fresh := func() AuthorityHead {
		return AuthorityHead{Authority: "0123456789abcdef", Sequence: 4, Generation: 4, Digest: "d4", ReadAt: now}
	}
	check := func(probe *fakeProbe, c InstallConfig) (BackupStatus, error) {
		checker := &BackupChecker{Probe: probe, Now: func() time.Time { return now }, MaxHeadAge: time.Minute}
		return checker.Check(context.Background(), c)
	}

	t.Run("complete declaration with a proven store is deletion safe", func(t *testing.T) {
		probe := &fakeProbe{head: fresh()}
		status, err := check(probe, validOffhost())
		if err != nil || status.Label != LabelDeletionSafeDisasterBackup || probe.creates != 1 || probe.reads != 1 {
			t.Fatalf("%+v %v creates=%d reads=%d", status, err, probe.creates, probe.reads)
		}
	})

	notReady := map[string]struct {
		probe  func() *fakeProbe
		mutate func(*InstallConfig)
		reason Reason
	}{
		"conditional create refused (last-writer-wins store)": {probe: func() *fakeProbe {
			return &fakeProbe{head: fresh(), createErr: errors.New("probe: second create overwrote")}
		}, reason: ReasonConditionalCreateFailed},
		"head unreadable or unverifiable":               {probe: func() *fakeProbe { return &fakeProbe{headErr: errors.New("chain broken")} }, reason: ReasonHeadUnavailable},
		"head read earlier than the freshness window":   {probe: func() *fakeProbe { h := fresh(); h.ReadAt = now.Add(-2 * time.Minute); return &fakeProbe{head: h} }, reason: ReasonHeadStale},
		"head stamped in the future":                    {probe: func() *fakeProbe { h := fresh(); h.ReadAt = now.Add(time.Hour); return &fakeProbe{head: h} }, reason: ReasonHeadStale},
		"head without an authority identity":            {probe: func() *fakeProbe { h := fresh(); h.Authority = ""; return &fakeProbe{head: h} }, reason: ReasonHeadUnavailable},
		"head of a foreign authority":                   {probe: func() *fakeProbe { return &fakeProbe{head: fresh()} }, mutate: func(c *InstallConfig) { c.Backup.Authority.ID = "ffffffffffffffff" }, reason: ReasonForeignAuthority},
		"invalid configuration never reaches the store": {probe: func() *fakeProbe { return &fakeProbe{head: fresh()} }, mutate: func(c *InstallConfig) { c.Backup.Authority.Capabilities.ConditionalCreate = false }, reason: ReasonInvalidConfig},
	}
	for name, tc := range notReady {
		t.Run(name, func(t *testing.T) {
			c := validOffhost()
			if tc.mutate != nil {
				tc.mutate(&c)
			}
			probe := tc.probe()
			status, err := check(probe, c)
			var nr *NotReadyError
			if !errors.As(err, &nr) || !errors.Is(err, ErrNotReady) || nr.Reason != tc.reason {
				t.Fatalf("got %v, want not-ready %q", err, tc.reason)
			}
			if status.Label == LabelDeletionSafeDisasterBackup {
				t.Fatal("a failed authority check still labelled the backup deletion safe")
			}
			if tc.reason == ReasonInvalidConfig && (probe.creates != 0 || probe.reads != 0) {
				t.Fatal("the store was contacted for an invalid configuration")
			}
		})
	}

	t.Run("an authority that goes backwards is rolled back", func(t *testing.T) {
		probe := &fakeProbe{head: fresh()}
		checker := &BackupChecker{Probe: probe, Now: func() time.Time { return now }, MaxHeadAge: time.Minute}
		if _, err := checker.Check(context.Background(), validOffhost()); err != nil {
			t.Fatal(err)
		}
		probe.head.Sequence = 3
		_, err := checker.Check(context.Background(), validOffhost())
		var nr *NotReadyError
		if !errors.As(err, &nr) || nr.Reason != ReasonAuthorityRolledBack {
			t.Fatalf("a head below the highest one already seen was accepted: %v", err)
		}
		probe.head.Sequence = 4
		if _, err = checker.Check(context.Background(), validOffhost()); err != nil {
			t.Fatalf("recovery to the seen head must be possible: %v", err)
		}
	})

	t.Run("no probe means not ready", func(t *testing.T) {
		checker := &BackupChecker{Now: func() time.Time { return now }, MaxHeadAge: time.Minute}
		if _, err := checker.Check(context.Background(), validOffhost()); !errors.Is(err, ErrNotReady) {
			t.Fatalf("%v", err)
		}
	})

	t.Run("local recovery copy is never labelled deletion safe", func(t *testing.T) {
		c := validDistributed()
		c.Backup = Backup{Mode: BackupLocal, Local: LocalBackup{Dir: "/var/backups/soundpost"}, RetentionDays: 7}
		if err := Validate(c); err != nil {
			t.Fatal(err)
		}
		probe := &fakeProbe{head: fresh()}
		status, err := check(probe, c)
		if err != nil || status.Label != LabelLocalRecoveryCopy || probe.creates+probe.reads != 0 {
			t.Fatalf("%+v %v", status, err)
		}
		// Even with a complete authority declaration, a local mode stays a local copy.
		c2 := validOffhost()
		c2.Backup.Mode = BackupLocal
		c2.Backup.Local = LocalBackup{Dir: "/var/backups/soundpost"}
		if status, _ := check(probe, c2); status.Label == LabelDeletionSafeDisasterBackup {
			t.Fatal("local mode carrying an authority block was labelled deletion safe")
		}
		none := validDistributed()
		if status, err := check(probe, none); err != nil || status.Label != LabelNone {
			t.Fatalf("%+v %v", status, err)
		}
	})
}

func TestOffhostBackupDeclarationIsRejectedWhenIncomplete(t *testing.T) {
	cases := map[string]struct {
		mutate func(*InstallConfig)
		field  string
	}{
		"no authority store":                {func(c *InstallConfig) { c.Backup.Authority.Store = Store{} }, "backup.authority.store.kind"},
		"conditional create not declared":   {func(c *InstallConfig) { c.Backup.Authority.Capabilities.ConditionalCreate = false }, "backup.authority.capabilities.conditional_create"},
		"fresh head not declared":           {func(c *InstallConfig) { c.Backup.Authority.Capabilities.FreshHead = false }, "backup.authority.capabilities.fresh_head"},
		"restricted restore not declared":   {func(c *InstallConfig) { c.Backup.Authority.Capabilities.RestrictedRestore = false }, "backup.authority.capabilities.restricted_restore"},
		"authority keys missing":            {func(c *InstallConfig) { c.Backup.Authority.Keys = SecretRef{} }, "backup.authority.keys"},
		"restricted keys missing":           {func(c *InstallConfig) { c.Backup.Authority.RestrictedKeys = SecretRef{} }, "backup.authority.restricted_keys"},
		"restricted keys are the full keys": {func(c *InstallConfig) { c.Backup.Authority.RestrictedKeys = c.Backup.Authority.Keys }, "backup.authority.restricted_keys"},
		"signing node is not a member":      {func(c *InstallConfig) { c.Backup.Authority.SigningNode = "node-z" }, "backup.authority.signing_node"},
		"authority is the backup bucket":    {func(c *InstallConfig) { c.Backup.Authority.Store = c.Backup.Destination }, "backup.authority.store"},
		"authority shares its credentials":  {func(c *InstallConfig) { c.Backup.Authority.Store.SecretKey = c.Backup.Destination.SecretKey }, "backup.authority.store.secret_key"},
		"destination without credentials":   {func(c *InstallConfig) { c.Backup.Destination.SecretKey = SecretRef{} }, "backup.destination.secret_key"},
		"plain http destination":            {func(c *InstallConfig) { c.Backup.Destination.Endpoint = "http://objects.example.invalid" }, "backup.destination.endpoint"},
		"credentials inside the endpoint":   {func(c *InstallConfig) { c.Backup.Destination.Endpoint = "https://user:pw@objects.example.invalid" }, "backup.destination.endpoint"},
		"data and secret KEK are the same":  {func(c *InstallConfig) { c.Backup.SecretKEKID = c.Backup.DataKEKID }, "backup.secret_kek_id"},
		"backup older than 30 days":         {func(c *InstallConfig) { c.Backup.RetentionDays = 31 }, "backup.retention_days"},
		"authority directory on a node disk": {func(c *InstallConfig) {
			c.Backup.Authority.Store = Store{Kind: "dir", Path: "/var/lib/soundpost/authority", DeviceID: "disk-a"}
		}, "backup.authority.store.device_id"},
		"authority directory inside the data path": {func(c *InstallConfig) {
			c.Backup.Authority.Store = Store{Kind: "dir", Path: "/var/lib/soundpost/authority", DeviceID: "other-device"}
		}, "backup.authority.store.path"},
		"local mode without a directory": {func(c *InstallConfig) { c.Backup = Backup{Mode: BackupLocal} }, "backup.local.dir"},
		"unknown mode":                   {func(c *InstallConfig) { c.Backup.Mode = "cloud" }, "backup.mode"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			c := validOffhost()
			tc.mutate(&c)
			var v *ValidationError
			if err := Validate(c); !errors.As(err, &v) || v.Field != tc.field {
				t.Fatalf("got %v, want a rejection of %s", err, tc.field)
			}
		})
	}
	// A directory on a different device is a legitimate off-host store.
	c := validOffhost()
	c.Backup.Authority.Store = Store{Kind: "dir", Path: "/mnt/authority", DeviceID: "authority-device"}
	if err := Validate(c); err != nil {
		t.Fatalf("separate-device authority directory: %v", err)
	}
}

// ---- safe logs ----

const canary = "CANARY-7f3a91-do-not-log"

func TestLogsRedactSecretReferencesAndCredentials(t *testing.T) {
	c := validOffhost()
	c.Cluster.Seed = NewSecretRef("file:/run/" + canary + "/seed")
	c.Nodes[0].PrivateKey = NewSecretRef("file:/run/" + canary + "/a.key")
	c.Backup.Destination.AccessKey = NewSecretRef("env:" + strings.ToUpper(strings.ReplaceAll(canary, "-", "_")))
	c.Backup.Authority.Keys = NewSecretRef("file:/run/" + canary + "/authority.keys")
	c.Backup.Destination.Endpoint = Endpoint("https://akia:" + canary + "@objects.example.invalid/path?token=" + canary)

	var out bytes.Buffer
	text := slog.New(slog.NewTextHandler(&out, nil))
	jsonLog := slog.New(slog.NewJSONHandler(&out, nil))
	text.Info("config", "config", c, "seed", c.Cluster.Seed, "dest", c.Backup.Destination, "node", c.Nodes[0], "authority", c.Backup.Authority)
	jsonLog.Info("config", "config", c, "seed", c.Cluster.Seed, "dest", c.Backup.Destination, "node", c.Nodes[0], "authority", c.Backup.Authority)
	rendered := []string{out.String(), c.Cluster.Seed.String(), c.Cluster.Seed.GoString(), c.Nodes[0].PrivateKey.String(), c.Backup.Destination.Endpoint.String(), c.Backup.Destination.Endpoint.GoString(), c.Summary()}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
		rendered = append(rendered, fmt.Sprintf(verb, c), fmt.Sprintf(verb, c.Nodes[0]), fmt.Sprintf(verb, c.Backup), fmt.Sprintf(verb, c.Cluster.Seed), fmt.Sprintf(verb, c.Backup.Destination.Endpoint))
	}
	asJSON, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	asYAML, err := c.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	rendered = append(rendered, string(asJSON), string(asYAML))
	validation := Validate(c)
	if validation == nil {
		t.Fatal("userinfo inside an endpoint must be rejected")
	}
	rendered = append(rendered, validation.Error())
	for i, text := range rendered {
		if strings.Contains(text, canary) || strings.Contains(strings.ToUpper(text), "CANARY_7F3A91") || strings.Contains(text, "akia") {
			t.Fatalf("rendering %d leaks a secret reference or credential: %.200s", i, text)
		}
	}
	if !strings.Contains(string(asYAML), "[redacted]") {
		t.Fatal("redaction marker missing from the YAML view")
	}
	// The value is still there for the code that resolves it.
	if got, ok := c.Cluster.Seed.FilePath(); !ok || !strings.Contains(got, canary) {
		t.Fatal("Reveal/FilePath lost the reference")
	}

	// Validation errors name the field and rule, never the value of a bad reference.
	bad := validOffhost()
	bad.Backup.Destination.AccessKey = NewSecretRef("AKIA" + canary)
	err = Validate(bad)
	var v *ValidationError
	if !errors.As(err, &v) || v.Field != "backup.destination.access_key" || strings.Contains(err.Error(), canary) {
		t.Fatalf("a raw credential in a reference slot: %v", err)
	}
}

func TestSecretReferencesAreRoundTrippedFromYAMLButNotBack(t *testing.T) {
	c, err := Parse([]byte("mode: single\nbackup:\n  mode: offhost\n  destination:\n    secret_key: env:SOUNDPOST_DEST_S3_SECRET_KEY\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Backup.Destination.SecretKey.Reveal() != "env:SOUNDPOST_DEST_S3_SECRET_KEY" {
		t.Fatal("reference not read")
	}
	out, _ := c.Marshal()
	if strings.Contains(string(out), "SOUNDPOST_DEST_S3_SECRET_KEY") {
		t.Fatalf("reference written back: %s", out)
	}
}
