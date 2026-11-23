// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
)

// RunK8sInstall installs the Helm chart (deploy/helm/soundpost) on a real Kubernetes cluster and drives the
// three-member cluster over its public HTTPS API through `kubectl port-forward` (the public listener's own
// certificate names only localhost, so a port-forward is also the route a certificate that matches).
//
// Nothing about the cluster is built in: the kubeconfig, the kubectl and helm commands, the namespace, the image
// (a digest-pinned reference) and the storage class are flags. The cluster needs three schedulable nodes (the chart's
// required anti-affinity places one member per node) and the image loaded or pullable on each of them.
//
// Phases: render the chart and check what the chart promises (three StatefulSets, a PodDisruptionBudget, no host
// namespaces, no privilege); make a private CA, leaves with the members' pod DNS names and the cluster seed (a
// one-time single installation made by --binary, stopped and exported); create the Secrets, `helm install`, wait for
// three ready members on three different nodes with bound PersistentVolumeClaims; ingest and read through different
// members; force-delete the leader's pod while its node is cordoned (the member stays down) and require the other
// two to keep acknowledging; bring it back and require it to rejoin and converge; drain another member's node
// likewise; check no pod log carries a credential; remove everything it created.
//
// Registered as: case "k8s-install": return RunK8sInstall(os.Args[2:]).
func RunK8sInstall(args []string) (result error) {
	stage := "k8s_flags"
	defer func() { result = annotateSmokeFailure("k8s_install", stage, model.ID{}, result) }()
	f := flag.NewFlagSet("k8s-install", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	artifact := f.String("artifact-dir", "", "sanitized result directory")
	kubeconfig := f.String("kubeconfig", "", "kubeconfig file (empty: the kubectl/helm commands' own default)")
	kubectl := f.String("kubectl", "kubectl", "kubectl command (words are split on spaces, e.g. \"sudo k3s kubectl\")")
	helm := f.String("helm", "helm", "helm command (words are split on spaces)")
	chart := f.String("chart", "deploy/helm/soundpost", "chart directory")
	namespace := f.String("namespace", "soundpost-smoke", "namespace to create (and, unless --keep, to delete)")
	repository := f.String("image-repository", "", "server image repository as the nodes know it")
	digest := f.String("image-digest", "", "server image digest (sha256:...)")
	binary := f.String("binary", "", "static soundpost binary of the same release (makes the one-time installation the seed is exported from; runs on this host)")
	release := f.String("release", "", "release directory the binary must belong to")
	storageClass := f.String("storage-class", "", "storage class of the member volumes (empty: the cluster default)")
	storageSize := f.String("storage-size", "1Gi", "size of each member's volume")
	keep := f.Bool("keep", false, "leave the namespace, release and volumes in place")
	if err := f.Parse(args); err != nil {
		return err
	}
	if *artifact == "" || *repository == "" || *binary == "" || !regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(*digest) {
		return errors.New("--artifact-dir, --image-repository, --image-digest (sha256:<64 hex>) and --binary are required")
	}
	if err := os.MkdirAll(*artifact, 0o700); err != nil {
		return err
	}
	k := &k8s{kubectl: strings.Fields(*kubectl), helm: strings.Fields(*helm), kubeconfig: *kubeconfig, namespace: *namespace}
	if len(k.kubectl) == 0 || len(k.helm) == 0 {
		return errors.New("--kubectl and --helm must not be empty")
	}
	report := map[string]any{"version": 1, "caveat": "three nodes of one Kubernetes cluster: node loss is a pod kill and a drain, not a power cut of a physical host; the placement is attested by the operator"}
	started := time.Now()
	work, err := os.MkdirTemp("", "soundpost-k8s-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)

	stage = "k8s_preflight"
	nodes, err := k.readyNodes()
	if err != nil {
		return err
	}
	if len(nodes) < 3 {
		return &smokeFailure{Stage: stage, Code: "fewer_than_three_ready_schedulable_nodes", Actual: len(nodes), Expected: 3}
	}
	report["nodes"] = nodes
	if out, e := k.run(time.Minute, nil, "get", "namespace", *namespace); e == nil {
		_ = out
		return &smokeFailure{Stage: stage, Code: "namespace_already_exists"}
	}

	stage = "k8s_values_and_render"
	valuesPath := filepath.Join(work, "values.yaml")
	if err = os.WriteFile(valuesPath, []byte(k8sValues(*repository, *digest, *storageClass, *storageSize)), 0o600); err != nil {
		return err
	}
	rendered, err := k.helmRun(2*time.Minute, "template", "soundpost", *chart, "-n", *namespace, "-f", valuesPath)
	if err != nil {
		return err
	}
	chartFacts, err := checkRenderedChart(rendered)
	if err != nil {
		return err
	}
	report["chart"] = chartFacts

	stage = "k8s_pki_bootstrap_seed"
	boot := &processCluster{binary: mustAbs(*binary), seed: filepath.Join(work, "cluster.seed")}
	if boot.boot, err = newBinaryHost(*binary, *release, report); err != nil {
		return err
	}
	defer boot.boot.cleanup()
	pki := filepath.Join(work, "pki")
	if err = os.MkdirAll(pki, 0o700); err != nil {
		return err
	}
	sans := map[uint64][]string{}
	for _, n := range distNodes {
		pod := "soundpost-" + n.name + "-0.soundpost-peer." + *namespace
		sans[n.id] = []string{pod + ".svc", pod + ".svc.cluster.local", "soundpost." + *namespace + ".svc", "localhost"}
	}
	caFile, certs, keys, material, _, err := distPKI(pki, sans, []net.IP{net.ParseIP("127.0.0.1")})
	if err != nil {
		return err
	}
	fx, seed, err := boot.bootstrap(report)
	if err != nil {
		return err
	}

	stage = "k8s_secrets"
	cleanedUp := false
	cleanup := func() {
		if cleanedUp || *keep {
			return
		}
		cleanedUp = true
		_, _ = k.helmRun(2*time.Minute, "uninstall", "soundpost", "-n", *namespace)
		_, _ = k.run(3*time.Minute, nil, "delete", "namespace", *namespace, "--wait=true")
		for _, n := range nodes {
			_, _ = k.run(time.Minute, nil, "uncordon", n)
		}
	}
	defer cleanup()
	if _, err = k.run(time.Minute, nil, "create", "namespace", *namespace); err != nil {
		return err
	}
	secrets := []k8sSecret{}
	for _, n := range distNodes {
		crt, e1 := os.ReadFile(certs[n.id])
		key, e2 := os.ReadFile(keys[n.id])
		if err = errors.Join(e1, e2); err != nil {
			return err
		}
		secrets = append(secrets, k8sSecret{"soundpost-" + n.name + "-pki", map[string][]byte{"tls.crt": crt, "tls.key": key}})
	}
	ca, err := os.ReadFile(caFile)
	if err != nil {
		return err
	}
	secrets = append(secrets, k8sSecret{"soundpost-cluster-ca", map[string][]byte{"ca.crt": ca}}, k8sSecret{"soundpost-cluster-seed", map[string][]byte{"cluster.seed": seed}})
	if err = k.applySecrets(secrets); err != nil {
		return err
	}

	stage = "k8s_helm_install"
	if _, err = k.helmRun(5*time.Minute, "install", "soundpost", *chart, "-n", *namespace, "-f", valuesPath); err != nil {
		return err
	}
	stage = "k8s_members_ready"
	var pods map[uint64]k8sPod
	for _, n := range distNodes {
		if _, err = k.waitPod("soundpost-"+n.name+"-0", "", 6*time.Minute); err != nil {
			return err
		}
	}
	if pods, err = k.members(); err != nil {
		return err
	}
	seen := map[string]bool{}
	placement := map[string]string{}
	for _, n := range distNodes {
		p := pods[n.id]
		if seen[p.node] {
			return &smokeFailure{Stage: stage, Code: "two_members_on_one_node"}
		}
		seen[p.node] = true
		placement[n.name] = p.node
	}
	report["member_nodes"] = placement
	claims, err := k.volumeClaims()
	if err != nil {
		return err
	}
	report["persistent_volume_claims"] = claims

	stage = "k8s_sites"
	forwards := &forwardSet{k: k, byID: map[uint64]*portForward{}, sites: map[uint64]*installSite{}}
	defer forwards.closeAll()
	siteOf := func(id uint64) (*installSite, error) { return forwards.site(id, pods[id].name) }
	sites := map[uint64]*installSite{}
	for _, n := range distNodes {
		if sites[n.id], err = siteOf(n.id); err != nil {
			return err
		}
	}
	stage = "k8s_ready_all"
	for _, n := range distNodes {
		if err = waitNodeReady(sites[n.id], 3*time.Minute); err != nil {
			return err
		}
	}
	stage = "k8s_initial_leadership"
	initial, err := leadership(sites, []uint64{1, 2, 3}, 90*time.Second)
	if err != nil {
		return err
	}
	lead, followers := initial.leader, otherMembers(initial.leader)
	report["initial_leadership"] = map[string]any{"leader": initial.leader, "term": initial.term}
	sessions := map[uint64]auth.Session{}
	login := func(id uint64) error {
		s, e := loginReader(sites[id], fx)
		sessions[id] = s
		return e
	}
	nfx := func(id uint64) *installFixture {
		c := *fx
		c.reader = sessions[id]
		return &c
	}
	stage = "k8s_ingest_and_agree"
	ledger := &distLedger{}
	if err = ledger.write(sites[lead], fx, "leader"); err != nil {
		return err
	}
	if err = ledger.write(sites[followers[0]], fx, "follower"); err != nil {
		return err
	}
	for _, id := range []uint64{1, 2, 3} {
		if err = login(id); err != nil {
			return err
		}
	}
	if _, err = agreedAnswers(stage, sites, []uint64{1, 2, 3}, nfx, ledger, 90*time.Second, "members_answer_differently"); err != nil {
		return err
	}
	report["write_through_leader_and_follower_visible_everywhere"] = true

	// loss runs one loss of member id: lose(), the other two must keep acknowledging, restore(), the member must
	// rejoin, answer every acknowledged value and converge with the others.
	loss := func(name string, id uint64, lose, restore func() error) (map[string]any, error) {
		out := map[string]any{"member": distNodes[id-1].name, "node": pods[id].node}
		via := otherMembers(id)[0]
		if err := lose(); err != nil {
			return nil, err
		}
		lostAt := time.Now()
		forwards.drop(id)
		if err := ledger.write(sites[via], fx, name+"_during"); err != nil {
			return nil, err
		}
		out["first_ack_after_loss_s"] = time.Since(lostAt).Round(100 * time.Millisecond).Seconds()
		for i := range 5 {
			if err := ledger.write(sites[via], fx, fmt.Sprintf("%s_during_%d", name, i)); err != nil {
				return nil, err
			}
		}
		out["acknowledged_batches_while_down"] = 6
		// the member is really gone while those writes were acknowledged
		if p, e := k.pod(pods[id].name); e == nil && p.ready {
			return nil, &smokeFailure{Stage: "k8s_" + name, Code: "lost_member_still_ready"}
		}
		if err := restore(); err != nil {
			return nil, err
		}
		fresh, err := k.waitPod(pods[id].name, pods[id].uid, 6*time.Minute)
		if err != nil {
			return nil, err
		}
		pods[id] = fresh
		out["pod_uid_changed"] = true
		out["rejoined_after_s"] = time.Since(lostAt).Round(time.Second).Seconds()
		if sites[id], err = siteOf(id); err != nil {
			return nil, err
		}
		if err = waitNodeReady(sites[id], 3*time.Minute); err != nil {
			return nil, err
		}
		if err = login(id); err != nil {
			return nil, err
		}
		for _, other := range []uint64{1, 2, 3} {
			if _, err = eventuallyQuery(sites[other], nfx(other), ledger, 120*time.Second); err != nil {
				return nil, err
			}
		}
		cursors, err := converged(sites, 120*time.Second)
		if err != nil {
			return nil, err
		}
		out["applied_cursors_equal"] = cursors
		return out, nil
	}

	stage = "k8s_force_delete_leader_pod"
	killed := pods[lead]
	killResult, err := loss("pod_kill", lead,
		func() error {
			// cordon first: the replacement then cannot start on the node (the volume is node-bound and the
			// anti-affinity leaves no other node), so the member stays down while the others are judged
			if _, e := k.run(time.Minute, nil, "cordon", killed.node); e != nil {
				return e
			}
			_, e := k.run(time.Minute, nil, "delete", "pod", killed.name, "--grace-period=0", "--force")
			return e
		},
		func() error { _, e := k.run(time.Minute, nil, "uncordon", killed.node); return e })
	if err != nil {
		return err
	}
	report["force_delete_leader_pod"] = killResult

	stage = "k8s_drain_member_node"
	target := otherMembers(lead)[1]
	drained := pods[target]
	drainResult, err := loss("drain", target,
		func() error {
			_, e := k.run(5*time.Minute, nil, "drain", drained.node, "--ignore-daemonsets", "--delete-emptydir-data", "--force", "--timeout=240s")
			return e
		},
		func() error { _, e := k.run(time.Minute, nil, "uncordon", drained.node); return e })
	if err != nil {
		return err
	}
	report["drain_member_node"] = drainResult

	stage = "k8s_final_agreement"
	answers, err := agreedAnswers(stage, sites, []uint64{1, 2, 3}, nfx, ledger, 120*time.Second, "members_answer_differently_after_losses")
	if err != nil {
		return err
	}
	report["acknowledged_batches"] = len(ledger.accepted)
	report["all_members_agree_on_latest_acknowledged_value"] = len(answers) == 3

	stage = "k8s_pod_logs_free_of_credentials"
	secretsToFind := append([]string{fx.credential, fx.password, "install smoke reader password 2026", fx.session.Token, fx.session.CSRF, fx.reader.Token, fx.reader.CSRF}, material...)
	for _, n := range distNodes {
		logs, e := k.run(time.Minute, nil, "logs", pods[n.id].name, "--tail=-1")
		if e != nil {
			return e
		}
		for _, s := range secretsToFind {
			if s != "" && strings.Contains(logs, s) {
				return &smokeFailure{Stage: stage, Code: "credential_or_key_in_pod_log"}
			}
		}
	}
	report["pod_logs_free_of_credentials_and_private_keys"] = true

	stage = "k8s_cleanup"
	forwards.closeAll()
	cleanup()
	if !*keep {
		if out, e := k.run(time.Minute, nil, "get", "namespace", *namespace); e == nil {
			_ = out
			return &smokeFailure{Stage: stage, Code: "namespace_not_removed"}
		}
		report["namespace_removed"] = true
	}
	report["wall_clock_s"] = time.Since(started).Round(time.Second).Seconds()
	report["not_run"] = []string{
		"three independent physical hosts, disks, power or network paths (one Kubernetes cluster, an operator-attested placement)",
		"the native acquisition helper (DaemonSet, hostPID): see docs/support/native-linux.md",
	}
	stage = "k8s_artifact"
	encoded, _ := json.MarshalIndent(report, "", "  ")
	return os.WriteFile(filepath.Join(*artifact, "k8s-install.json"), encoded, 0o600)
}

func mustAbs(p string) string {
	a, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	return a
}

// k8sValues is the chart values file of the smoke: the image, three small volumes. The member names, ids and
// identities are the chart's own defaults.
func k8sValues(repository, digest, storageClass, size string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "image:\n  repository: %q\n  digest: %q\nmembers:\n", repository, digest)
	for _, n := range distNodes {
		fmt.Fprintf(&b, "  - {name: %s, id: %d, identity: %s, failureDomain: domain-%s, pkiSecret: soundpost-%s-pki, storage: {size: %s, storageClassName: %q}}\n", n.name, n.id, n.identity, n.name, n.name, size, storageClass)
	}
	return b.String()
}

// checkRenderedChart checks what the chart promises on the rendered manifests: three single-replica StatefulSets with
// literal node ids and a required anti-affinity, no host namespace, no privilege, one PodDisruptionBudget.
func checkRenderedChart(rendered string) (map[string]any, error) {
	docs := strings.Split(rendered, "\n---")
	count := map[string]int{}
	for _, d := range docs {
		if m := regexp.MustCompile(`(?m)^kind: (\w+)$`).FindStringSubmatch(d); m != nil {
			count[m[1]]++
		}
	}
	fail := func(code string) error { return &smokeFailure{Stage: "k8s_render", Code: code} }
	if count["StatefulSet"] != 3 || count["PodDisruptionBudget"] != 1 || count["Service"] != 2 {
		return nil, fail("unexpected_object_counts")
	}
	for _, bad := range []string{"hostPID: true", "hostNetwork: true", "hostIPC: true", "privileged: true"} {
		if strings.Contains(rendered, bad) {
			return nil, fail("rendered_" + strings.ReplaceAll(strings.Split(bad, ":")[0], " ", "_"))
		}
	}
	if strings.Count(rendered, "requiredDuringSchedulingIgnoredDuringExecution") != 3 || strings.Count(rendered, "replicas: 1") != 3 {
		return nil, fail("members_not_single_replica_with_required_anti_affinity")
	}
	for id := 1; id <= 3; id++ {
		if !strings.Contains(rendered, fmt.Sprintf("--node-id=%d", id)) {
			return nil, fail("missing_literal_node_id")
		}
	}
	if strings.Contains(rendered, "-----BEGIN") {
		return nil, fail("key_material_rendered")
	}
	kinds := make([]string, 0, len(count))
	for kind := range count {
		kinds = append(kinds, kind)
	}
	sort.Strings(kinds)
	facts := map[string]any{"kinds": count}
	_ = kinds
	return facts, nil
}

// ---- kubectl / helm ----

type k8s struct {
	kubectl, helm []string
	kubeconfig    string
	namespace     string
}

func (k *k8s) exec(timeout time.Duration, stdin []byte, argv []string, kubeconfigFlag string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	full := append([]string{}, argv[1:]...)
	if k.kubeconfig != "" {
		full = append(full, kubeconfigFlag+"="+k.kubeconfig)
	}
	cmd := exec.CommandContext(ctx, argv[0], full...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		word := ""
		if len(full) > 0 {
			word = full[0]
		}
		return out.String(), fmt.Errorf("%s %s: %w: %s", argv[0], word, err, clip(strings.TrimSpace(errb.String()), 400))
	}
	return out.String(), nil
}

// run is kubectl in the smoke's namespace.
func (k *k8s) run(timeout time.Duration, stdin []byte, args ...string) (string, error) {
	argv := append(append([]string{}, k.kubectl...), args...)
	if len(args) > 0 && !(args[0] == "get" && len(args) > 1 && (args[1] == "nodes" || args[1] == "namespace")) && args[0] != "create" && args[0] != "cordon" && args[0] != "uncordon" && args[0] != "drain" && !(args[0] == "delete" && len(args) > 1 && args[1] == "namespace") {
		argv = append(argv, "-n", k.namespace)
	}
	return k.exec(timeout, stdin, argv, "--kubeconfig")
}

func (k *k8s) helmRun(timeout time.Duration, args ...string) (string, error) {
	argv := append(append([]string{}, k.helm...), args...)
	return k.exec(timeout, nil, argv, "--kubeconfig")
}

func (k *k8s) readyNodes() ([]string, error) {
	out, err := k.run(time.Minute, nil, "get", "nodes", "-o", "json")
	if err != nil {
		return nil, err
	}
	var list struct {
		Items []struct {
			Metadata struct{ Name string }
			Spec     struct{ Unschedulable bool }
			Status   struct {
				Conditions []struct{ Type, Status string }
			}
		}
	}
	if err = json.Unmarshal([]byte(out), &list); err != nil {
		return nil, err
	}
	var names []string
	for _, n := range list.Items {
		ready := false
		for _, c := range n.Status.Conditions {
			ready = ready || (c.Type == "Ready" && c.Status == "True")
		}
		if ready && !n.Spec.Unschedulable {
			names = append(names, n.Metadata.Name)
		}
	}
	sort.Strings(names)
	return names, nil
}

type k8sSecret struct {
	name string
	data map[string][]byte
}

func (k *k8s) applySecrets(secrets []k8sSecret) error {
	items := []any{}
	for _, s := range secrets {
		data := map[string]string{}
		for key, v := range s.data {
			data[key] = base64.StdEncoding.EncodeToString(v)
		}
		items = append(items, map[string]any{"apiVersion": "v1", "kind": "Secret", "type": "Opaque", "metadata": map[string]any{"name": s.name, "namespace": k.namespace}, "data": data})
	}
	body, _ := json.Marshal(map[string]any{"apiVersion": "v1", "kind": "List", "items": items})
	_, err := k.run(time.Minute, body, "apply", "-f", "-")
	return err
}

type k8sPod struct {
	name, uid, node string
	ready, deleting bool
}

func (k *k8s) pod(name string) (k8sPod, error) {
	out, err := k.run(time.Minute, nil, "get", "pod", name, "-o", "json")
	if err != nil {
		return k8sPod{}, err
	}
	return parsePod([]byte(out))
}

func parsePod(raw []byte) (k8sPod, error) {
	var p struct {
		Metadata struct {
			Name, UID         string
			DeletionTimestamp *string `json:"deletionTimestamp"`
		}
		Spec   struct{ NodeName string }
		Status struct {
			Phase      string
			Conditions []struct{ Type, Status string }
		}
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return k8sPod{}, err
	}
	out := k8sPod{name: p.Metadata.Name, uid: p.Metadata.UID, node: p.Spec.NodeName, deleting: p.Metadata.DeletionTimestamp != nil}
	for _, c := range p.Status.Conditions {
		out.ready = out.ready || (c.Type == "Ready" && c.Status == "True")
	}
	out.ready = out.ready && p.Status.Phase == "Running" && !out.deleting
	return out, nil
}

// waitPod waits for the pod to exist, be Ready and (when oldUID is set) be a different pod than oldUID.
func (k *k8s) waitPod(name, oldUID string, limit time.Duration) (k8sPod, error) {
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		if p, err := k.pod(name); err == nil && p.ready && p.uid != oldUID {
			return p, nil
		}
		time.Sleep(2 * time.Second)
	}
	return k8sPod{}, &smokeFailure{Stage: "k8s_wait_pod", Code: "pod_not_ready_in_time"}
}

func (k *k8s) members() (map[uint64]k8sPod, error) {
	out := map[uint64]k8sPod{}
	for _, n := range distNodes {
		p, err := k.pod("soundpost-" + n.name + "-0")
		if err != nil {
			return nil, err
		}
		out[n.id] = p
	}
	return out, nil
}

func (k *k8s) volumeClaims() (map[string]any, error) {
	out, err := k.run(time.Minute, nil, "get", "pvc", "-o", "json")
	if err != nil {
		return nil, err
	}
	var list struct {
		Items []struct {
			Metadata struct{ Name string }
			Spec     struct {
				StorageClassName string `json:"storageClassName"`
			}
			Status struct{ Phase string }
		}
	}
	if err = json.Unmarshal([]byte(out), &list); err != nil {
		return nil, err
	}
	claims := map[string]any{}
	for _, c := range list.Items {
		if c.Status.Phase != "Bound" {
			return nil, &smokeFailure{Stage: "k8s_volumes", Code: "claim_not_bound"}
		}
		claims[c.Metadata.Name] = map[string]string{"storage_class": c.Spec.StorageClassName, "phase": c.Status.Phase}
	}
	if len(claims) != 3 {
		return nil, &smokeFailure{Stage: "k8s_volumes", Code: "expected_three_claims", Actual: len(claims), Expected: 3}
	}
	return claims, nil
}

// ---- port-forward sites ----

type portForward struct {
	cmd  *exec.Cmd
	addr string
	once sync.Once
}

func (p *portForward) close() {
	p.once.Do(func() {
		if p.cmd != nil && p.cmd.Process != nil {
			// SIGTERM: a forward started through `sudo` is only ended by the signal sudo relays; SIGKILL would orphan it
			_ = p.cmd.Process.Signal(syscall.SIGTERM)
			_ = p.cmd.Wait()
		}
	})
}

var forwardedLine = regexp.MustCompile(`Forwarding from 127\.0\.0\.1:(\d+) ->`)

// startForward runs `kubectl port-forward pod/NAME :8443` (a free local port) and returns once it reports the port.
func (k *k8s) startForward(pod string) (*portForward, error) {
	argv := append(append([]string{}, k.kubectl...), "-n", k.namespace, "port-forward", "--address", "127.0.0.1", "pod/"+pod, ":8443")
	if k.kubeconfig != "" {
		argv = append(argv, "--kubeconfig="+k.kubeconfig)
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stderr = io.Discard
	cmd.WaitDelay = 3 * time.Second // a forward started through sudo leaves a grandchild holding the pipe
	if err = cmd.Start(); err != nil {
		return nil, err
	}
	pf := &portForward{cmd: cmd}
	found := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			if m := forwardedLine.FindStringSubmatch(sc.Text()); m != nil {
				found <- "127.0.0.1:" + m[1]
				break
			}
		}
		_, _ = io.Copy(io.Discard, stdout)
	}()
	select {
	case pf.addr = <-found:
		return pf, nil
	case <-time.After(30 * time.Second):
		pf.close()
		return nil, &smokeFailure{Stage: "k8s_port_forward", Code: "no_local_port"}
	}
}

type forwardSet struct {
	k     *k8s
	mu    sync.Mutex
	byID  map[uint64]*portForward
	sites map[uint64]*installSite
}

func (s *forwardSet) drop(id uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if pf := s.byID[id]; pf != nil {
		pf.close()
	}
	delete(s.byID, id)
}

func (s *forwardSet) closeAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, pf := range s.byID {
		pf.close()
		delete(s.byID, id)
	}
}

// site forwards the member's public port and returns a client that trusts exactly the certificate the member
// presents through the forward: the kubeconfig-authenticated channel is the "authenticated channel" the server's
// startup message asks for (the certificate is generated by the member and names only localhost).
func (s *forwardSet) site(id uint64, pod string) (*installSite, error) {
	s.drop(id)
	pf, err := s.k.startForward(pod)
	if err != nil {
		return nil, err
	}
	cert, err := presentedCertificate(pf.addr, 60*time.Second)
	if err != nil {
		pf.close()
		return nil, err
	}
	s.mu.Lock()
	s.byID[id] = pf
	s.mu.Unlock()
	return newInstallSite("https://"+pf.addr, cert), nil
}

func presentedCertificate(addr string, limit time.Duration) (*x509.Certificate, error) {
	deadline := time.Now().Add(limit)
	var last error
	for time.Now().Before(deadline) {
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}) //nolint:gosec // pin of the certificate the authenticated forward presents
		if err == nil {
			peers := conn.ConnectionState().PeerCertificates
			conn.Close()
			if len(peers) > 0 {
				return peers[0], nil
			}
		}
		last = err
		time.Sleep(time.Second)
	}
	return nil, &smokeFailure{Stage: "k8s_member_certificate", Code: "timeout_" + safeToken(fmt.Sprint(last != nil))}
}
