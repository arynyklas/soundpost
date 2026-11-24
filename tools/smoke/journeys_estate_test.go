// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Criterion 07.04#12 (literal): examples/reference/compose.yaml covers the WHOLE reference estate. The node, the SDK-bearing
// applications (Python API and jobs, Bun gateway, the Vite web build), PostgreSQL and the dependency are all services of the
// file; per-source credentials are provisioned at run time by a service that waits for the node and writes them to a volume only the
// applications mount, never into the file; every image is content-pinned or is the id of an image built from this tree.
// This replaces TestReferenceComposeStartsOnlyBackingServices, which pinned the service set to {postgres, dependency} and the docs to
// "backing services only": D78 read 07.04#12 that way (the node and the applications as host processes of the smoke), the release
// implements the criterion's literal wording instead (verify9-c: D78's reading is "NOT_SUPPORTED"; verify10-e: whole-estate compose
// "SUPPORTED"), so the same two pins now hold for the whole set (the service set below, "whole reference estate" in the docs) and the
// old wording must not come back (TestReferenceComposeDocumentsTheWholeEstate).
// The structure is checked on the parsed file, not on its text.
type composeFile struct {
	Services map[string]struct {
		Image       string         `yaml:"image"`
		PullPolicy  string         `yaml:"pull_policy"`
		User        string         `yaml:"user"`
		ReadOnly    bool           `yaml:"read_only"`
		Privileged  bool           `yaml:"privileged"`
		NetworkMode string         `yaml:"network_mode"`
		Pid         string         `yaml:"pid"`
		Cgroup      string         `yaml:"cgroup"`
		CapAdd      []string       `yaml:"cap_add"`
		CapDrop     []string       `yaml:"cap_drop"`
		SecurityOpt []string       `yaml:"security_opt"`
		Profiles    []string       `yaml:"profiles"`
		Ports       []string       `yaml:"ports"`
		Volumes     []string       `yaml:"volumes"`
		Command     []string       `yaml:"command"`
		DependsOn   map[string]any `yaml:"depends_on"`
	} `yaml:"services"`
}

func readReferenceCompose(t *testing.T) (composeFile, string) {
	t.Helper()
	raw, err := os.ReadFile("../../examples/reference/compose.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var c composeFile
	if err = yaml.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	return c, string(raw)
}

func TestReferenceComposeCoversTheWholeEstate(t *testing.T) {
	c, _ := readReferenceCompose(t)
	var got []string
	for name := range c.Services {
		got = append(got, name)
	}
	slices.Sort(got)
	want := []string{"api", "dependency", "gateway", "handover", "init", "jobs", "node", "postgres", "provision", "webbuild"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("compose services %v, want the whole estate %v", got, want)
	}
	// The roles: which image family runs what.
	for name, family := range map[string]string{"node": "REFERENCE_NODE_IMAGE", "provision": "REFERENCE_TOOLS_IMAGE", "api": "REFERENCE_ESTATE_IMAGE", "gateway": "REFERENCE_ESTATE_IMAGE",
		"jobs": "REFERENCE_ESTATE_IMAGE", "webbuild": "REFERENCE_ESTATE_IMAGE", "postgres": "REFERENCE_PG_IMAGE", "dependency": "REFERENCE_PYTHON_IMAGE", "init": "REFERENCE_PYTHON_IMAGE"} {
		if !strings.Contains(c.Services[name].Image, "${"+family) {
			t.Errorf("service %s image %q does not come from %s", name, c.Services[name].Image, family)
		}
	}
	has := func(service string, deps map[string]string) {
		for dep, cond := range deps {
			d, ok := c.Services[service].DependsOn[dep].(map[string]any)
			if !ok || d["condition"] != cond {
				t.Errorf("service %s must wait for %s (%s), depends_on is %v", service, dep, cond, c.Services[service].DependsOn)
			}
		}
	}
	has("node", map[string]string{"init": "service_completed_successfully"})
	has("provision", map[string]string{"node": "service_healthy"})
	for _, app := range []string{"webbuild", "api", "jobs"} {
		has(app, map[string]string{"provision": "service_completed_successfully"})
	}
	has("api", map[string]string{"postgres": "service_healthy", "dependency": "service_healthy"})
	has("gateway", map[string]string{"webbuild": "service_completed_successfully", "api": "service_healthy"})
	if !slices.Equal(c.Services["jobs"].Profiles, []string{"jobs"}) || !slices.Equal(c.Services["handover"].Profiles, []string{"handover"}) {
		t.Error("jobs and handover are on-demand services (profiles), not part of `up`")
	}
}

// The estate's containers hold no more privilege than the estate needs, and the one exception is the node's, named and limited:
// uid 0 without any capability (its native symbolication sandbox must move its worker into a delegated cgroup, which a nonroot
// container user cannot), in the host cgroup namespace. Nothing is privileged, nothing shares the host's pid or network namespace,
// every published port is loopback, no service reaches the Docker socket.
func TestReferenceComposeContainersAreLimited(t *testing.T) {
	c, text := readReferenceCompose(t)
	if strings.Contains(text, "docker.sock") {
		t.Error("compose.yaml mounts the Docker socket")
	}
	for name, s := range c.Services {
		if s.Privileged || s.NetworkMode != "" || s.Pid != "" {
			t.Errorf("%s is privileged or shares a host namespace: privileged=%v network_mode=%q pid=%q", name, s.Privileged, s.NetworkMode, s.Pid)
		}
		if s.PullPolicy != "never" {
			t.Errorf("%s pull_policy %q: a run never reaches a registry", name, s.PullPolicy)
		}
		if name != "postgres" && !slices.Contains(s.CapDrop, "ALL") {
			t.Errorf("%s does not drop all capabilities", name)
		}
		if !slices.Contains(s.SecurityOpt, "no-new-privileges:true") {
			t.Errorf("%s does not set no-new-privileges", name)
		}
		for _, p := range s.Ports {
			if !strings.HasPrefix(p, "127.0.0.1:") {
				t.Errorf("%s publishes %q beyond loopback", name, p)
			}
		}
	}
	node := c.Services["node"]
	if node.User != "0:0" || node.Cgroup != "host" || !node.ReadOnly || len(node.CapAdd) != 0 {
		t.Errorf("node: user %q cgroup %q read_only %v cap_add %v: want uid 0 with no capability, read-only root, host cgroup namespace", node.User, node.Cgroup, node.ReadOnly, node.CapAdd)
	}
	for _, app := range []string{"api", "gateway", "jobs", "webbuild"} {
		s := c.Services[app]
		if s.User != "65534:65534" || !s.ReadOnly || len(s.CapAdd) != 0 {
			t.Errorf("%s: user %q read_only %v cap_add %v: the applications run as nobody, read-only, with no capability", app, s.User, s.ReadOnly, s.CapAdd)
		}
	}
	// Credentials are provisioned at run time: the applications read their source configuration from the cfg volume, and nothing in
	// the file is a credential.
	for app, cfg := range map[string]string{"api": "/cfg/api.json", "gateway": "/cfg/gateway.json", "jobs": "/cfg/jobs.json"} {
		if !slices.Contains(c.Services[app].Command, cfg) {
			t.Errorf("%s does not read its provisioned configuration %s: %v", app, cfg, c.Services[app].Command)
		}
		if !slices.Contains(c.Services[app].Volumes, "cfg:/cfg:ro") {
			t.Errorf("%s does not mount the provisioned configuration volume read-only", app)
		}
	}
	for _, svc := range []string{"node", "postgres", "dependency", "init", "handover"} {
		for _, v := range c.Services[svc].Volumes {
			if strings.Contains(v, "cfg:") {
				t.Errorf("%s mounts the credential volume: %s", svc, v)
			}
		}
	}
	for _, m := range regexp.MustCompile(`[0-9a-f]{40,}`).FindAllString(text, -1) {
		if m != testDigest64 && m != testDigestB {
			t.Errorf("compose.yaml carries a long hex string that is no pinned third-party digest: %s", m)
		}
	}
}

// The documents say what the file is: the whole estate, with credentials provisioned at run time and the node's one deviation.
func TestReferenceComposeDocumentsTheWholeEstate(t *testing.T) {
	for _, f := range []string{"../../examples/reference/README.md", "../../docs/acceptance/reference-journeys.md"} {
		doc, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		text := strings.Join(strings.Fields(string(doc)), " ")
		for _, must := range []string{"whole reference estate", "provision", "uid 0"} {
			if !strings.Contains(text, must) {
				t.Errorf("%s does not state %q", f, must)
			}
		}
		if strings.Contains(text, "backing services only") {
			t.Errorf("%s still says the compose file is the backing services only", f)
		}
	}
}

// The estate's compose environment: a whole-estate run names the three images it built (ids, never tags), the ports the node and the
// gateway are published on and the delegated cgroup; a run that starts only the backing services gives compose inert values for them, so
// that the file interpolates, and none of them can start anything.
func TestReferenceComposeEstateEnvironment(t *testing.T) {
	c := testCompose()
	c.NodeImage, c.ToolsImage, c.EstateImage = "sha256:"+testDigest64, "sha256:"+testDigestB, "sha256:"+strings.Repeat("ab", 32)
	c.NodePort, c.GatewayPort, c.CgroupRoot, c.NodeData, c.HandoverUID, c.HandoverGID, c.JobRunID = "40003", "40004", "/sys/fs/cgroup/x.service", "/work/node-data", 1000, 1001, "run-id"
	env, err := c.env()
	if err != nil {
		t.Fatal(err)
	}
	m := envMap(env)
	for k, want := range map[string]string{"REFERENCE_NODE_IMAGE": c.NodeImage, "REFERENCE_TOOLS_IMAGE": c.ToolsImage, "REFERENCE_ESTATE_IMAGE": c.EstateImage,
		"REFERENCE_NODE_PORT": "40003", "REFERENCE_GATEWAY_PORT": "40004", "REFERENCE_CGROUP_ROOT": "/sys/fs/cgroup/x.service", "REFERENCE_NODE_DATA": "/work/node-data",
		"REFERENCE_HANDOVER_UID": "1000", "REFERENCE_HANDOVER_GID": "1001", "REFERENCE_JOB_RUN_ID": "run-id"} {
		if m[k] != want {
			t.Errorf("%s = %q, want %q", k, m[k], want)
		}
	}
	for name, mutate := range map[string]func(*referenceCompose){
		"node image tag":        func(c *referenceCompose) { c.NodeImage = "soundpost:1.0.0" },
		"estate image short id": func(c *referenceCompose) { c.EstateImage = "c9fe697315a6" },
		"tools image latest":    func(c *referenceCompose) { c.ToolsImage = "smoke:latest" },
		"no node port":          func(c *referenceCompose) { c.NodePort = "" },
		"no gateway port":       func(c *referenceCompose) { c.GatewayPort = "" },
		"no cgroup root":        func(c *referenceCompose) { c.CgroupRoot = "" },
		"node image only":       func(c *referenceCompose) { c.ToolsImage = "" },
	} {
		c2 := c
		mutate(&c2)
		if _, err := c2.env(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Backing services only (an attached cluster): inert values, never a real image.
	backing, err := testCompose().env()
	if err != nil {
		t.Fatal(err)
	}
	m = envMap(backing)
	for _, k := range []string{"REFERENCE_NODE_IMAGE", "REFERENCE_TOOLS_IMAGE", "REFERENCE_ESTATE_IMAGE"} {
		if m[k] != inertImage {
			t.Errorf("%s = %q, want the inert image", k, m[k])
		}
	}
	if err := pinnedImageRef(inertImage); err != nil {
		t.Errorf("the inert image is not a well-formed id: %v", err)
	}
}

// The provision service takes everything it needs from its command line and refuses an incomplete one; the browser reaches the node at its
// published address and every other application at the node's service name.
func TestProvisionServiceFlags(t *testing.T) {
	s := provisionService{enabled: true, nodeURL: "https://node:8443", tlsDir: "/tls", nodeData: "/node-data", cfgDir: "/cfg", gatewayOrigin: "127.0.0.1:40004", browserIngest: "127.0.0.1:40003", serverIngest: "node:8443"}
	if err := s.validate(); err != nil {
		t.Fatal(err)
	}
	for app, want := range map[string]string{"web": "127.0.0.1:40003", "gateway": "node:8443", "api": "node:8443", "jobs": "node:8443", "webbuild": "node:8443"} {
		if got := s.ingestAddress(app); got != want {
			t.Errorf("ingest address of %s = %q, want %q", app, got, want)
		}
	}
	for name, mutate := range map[string]func(*provisionService){
		"no node url":       func(s *provisionService) { s.nodeURL = "" },
		"plain http":        func(s *provisionService) { s.nodeURL = "http://node:8443" },
		"no tls dir":        func(s *provisionService) { s.tlsDir = "" },
		"no node data":      func(s *provisionService) { s.nodeData = "" },
		"no cfg dir":        func(s *provisionService) { s.cfgDir = "" },
		"no gateway":        func(s *provisionService) { s.gatewayOrigin = "" },
		"no browser ingest": func(s *provisionService) { s.browserIngest = "" },
		"no server ingest":  func(s *provisionService) { s.serverIngest = "" },
	} {
		s2 := s
		mutate(&s2)
		if err := s2.validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The one TLS leaf of a run names loopback and every compose service that is called over TLS, so that the browser, the host's reads and the
// containers all verify the same certificate.
func TestJourneyLeafNamesTheComposeServices(t *testing.T) {
	pki, err := newJourneyPKI(filepath.Join(t.TempDir(), "pki"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(pki.Cert)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(raw)
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"localhost", "node", "api", "gateway", "dependency"} {
		if err := leaf.VerifyHostname(name); err != nil {
			t.Errorf("leaf does not name %s: %v", name, err)
		}
	}
	if err := leaf.VerifyHostname("127.0.0.1"); err != nil {
		t.Errorf("leaf does not name 127.0.0.1: %v", err)
	}
	if err := leaf.VerifyHostname("postgres"); err == nil {
		t.Error("leaf names postgres, which is not served over TLS")
	}
}

// Identities are deterministic and the web build's two sources share the build the expectations name.
func TestJourneyAppIdentitiesAreDeterministic(t *testing.T) {
	var j journeyRun
	e := j.setExpectations()
	seen := map[string]bool{}
	for _, a := range journeyAppSpecs {
		c := journeyAppIdentity(a.name, e.WebBuild)
		again := journeyAppIdentity(a.name, e.WebBuild)
		if c.Source != again.Source || c.Build != again.Build || c.Service != again.Service {
			t.Errorf("%s: identity is not deterministic", a.name)
		}
		if seen[c.Source.String()] {
			t.Errorf("%s: source id repeats", a.name)
		}
		seen[c.Source.String()] = true
		if c.Browser != a.browser {
			t.Errorf("%s: browser flag %v, spec %v", a.name, c.Browser, a.browser)
		}
		if (a.name == "web" || a.name == "webbuild") != (c.Build == e.WebBuild) {
			t.Errorf("%s: build %s, the web build is %s", a.name, c.Build, e.WebBuild)
		}
	}
	if e.WebSource != journeyAppIdentity("web", e.WebBuild).Source {
		t.Error("the expected web source is not the web app's source")
	}
}

// Inside the provision service a configuration (it carries a source's credential) is readable by the applications' uid alone.
func TestWritePrivateConfigOutsideTheServiceIsPrivateToTheUser(t *testing.T) {
	var j journeyRun
	path := filepath.Join(t.TempDir(), "api.json")
	if err := j.writePrivateConfig(path, []byte("{}")); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v err %v", fi.Mode().Perm(), err)
	}
}
