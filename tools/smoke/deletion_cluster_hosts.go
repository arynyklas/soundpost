// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// The cross-host mode of the deletion-cluster smoke (`deletion-cluster --hosts ...`): the three
// voters run on three DIFFERENT machines, each as an enabled systemd unit on its own host, driven
// from a fourth place over ssh. Nothing about a host is built in: every host, user and address is a
// flag. The scenario itself is in deletion_cluster_hosts_run.go.

const (
	dcRemoteBin    = "/usr/local/bin/soundpost-dc"
	dcRemoteSmoke  = "/usr/local/bin/soundpost-dc-smoke"
	dcRemoteEtc    = "/etc/soundpost-dc"
	dcRemoteVar    = "/var/lib/soundpost-dc"
	dcRemoteUnit   = "soundpost-dc"
	dcRemoteKeys   = dcRemoteEtc + "/authority.keys"
	dcRemoteEnv    = dcRemoteEtc + "/authority.env"
	dcRemoteS3CA   = dcRemoteEtc + "/s3ca.pem"
	dcRemoteBackup = dcRemoteVar + "/backups"
	dcRemoteKeyDir = dcRemoteEtc + "/backup-keys"
	dcPublicPort   = "8443"
	dcPeerPort     = "9444"
)

// dcHostSpec is one voter's machine: how to reach it with ssh and the address its listeners use.
type dcHostSpec struct {
	ID   uint64
	SSH  string // the ssh destination (user@host or an ssh config alias)
	Addr string // the IP address the voter listens on and its peers dial
}

var dcSSHTarget = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._@:-]*$`)

// dcParseHosts parses --hosts "1=ssh=addr,2=ssh=addr,3=ssh=addr": exactly the voters 1, 2 and 3, each
// on its own machine (distinct ssh destinations and distinct addresses). A host list that names one
// machine twice is not a cross-host run.
func dcParseHosts(s string) (map[uint64]dcHostSpec, error) {
	out := map[uint64]dcHostSpec{}
	seenSSH, seenAddr := map[string]bool{}, map[string]bool{}
	for _, part := range strings.Split(s, ",") {
		fields := strings.Split(strings.TrimSpace(part), "=")
		if len(fields) != 3 {
			return nil, errors.New("--hosts wants id=ssh=address,... for voters 1, 2 and 3")
		}
		id, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil || id < 1 || id > 3 {
			return nil, errors.New("--hosts: voter ids are 1, 2 and 3")
		}
		if _, dup := out[id]; dup {
			return nil, errors.New("--hosts: a voter is named twice")
		}
		ssh, addr := fields[1], fields[2]
		if !dcSSHTarget.MatchString(ssh) {
			return nil, errors.New("--hosts: an ssh destination has characters ssh would read as an option or a shell would expand")
		}
		if ip := net.ParseIP(addr); ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
			return nil, errors.New("--hosts: an address must be a routable IP address of the voter's machine")
		}
		if seenSSH[ssh] || seenAddr[addr] {
			return nil, errors.New("--hosts: two voters on one machine is not a cross-host run (every voter needs its own ssh destination and address)")
		}
		seenSSH[ssh], seenAddr[addr] = true, true
		out[id] = dcHostSpec{ID: id, SSH: ssh, Addr: addr}
	}
	if len(out) != 3 {
		return nil, errors.New("--hosts wants exactly the three voters 1, 2 and 3")
	}
	return out, nil
}

// dcHostFacts is what one machine says about itself.
type dcHostFacts struct {
	Hostname  string `json:"hostname"`
	MachineID string `json:"machine_id"`
	BootID    string `json:"boot_id"`
	Kernel    string `json:"kernel"`
}

// dcDistinctDomains is the failure-domain judgement of the voters' machines: three machines that
// differ in hostname, machine id and boot id (one machine reached through three names would not).
// It never claims independent power, storage or a hypervisor: that is an attestation of the operator.
func dcDistinctDomains(facts map[uint64]dcHostFacts) (bool, string) {
	if len(facts) != 3 {
		return false, fmt.Sprintf("%d machines reported, want 3", len(facts))
	}
	for _, field := range []struct {
		name string
		get  func(dcHostFacts) string
	}{{"hostname", func(f dcHostFacts) string { return f.Hostname }}, {"machine_id", func(f dcHostFacts) string { return f.MachineID }}, {"boot_id", func(f dcHostFacts) string { return f.BootID }}} {
		seen := map[string]bool{}
		for _, f := range facts {
			v := field.get(f)
			if v == "" {
				return false, "a machine reported no " + field.name
			}
			if seen[v] {
				return false, "two voters share one " + field.name
			}
			seen[v] = true
		}
	}
	return true, "three machines with three hostnames, machine ids and boot ids"
}

// dcLookup resolves a host name to its addresses (net.LookupHost in a run, a table in the unit tests).
type dcLookup func(host string) ([]string, error)

// dcNameIsMachine says whether a host name (or address) is the machine at machineAddr. A name is judged
// by what it resolves to, so an alias of the machine is the machine; a name that does not resolve is an
// error, never an answer: the placement would be unproven.
func dcNameIsMachine(name, machineAddr string, lookup dcLookup) (bool, error) {
	machine := net.ParseIP(machineAddr)
	if machine == nil {
		return false, &smokeFailure{Smoke: dcSmoke, Stage: "authority_placement", Code: "machine_address_unreadable"}
	}
	addrs := []string{name}
	if net.ParseIP(name) == nil {
		var err error
		if addrs, err = lookup(name); err != nil || len(addrs) == 0 {
			return false, &smokeFailure{Smoke: dcSmoke, Stage: "authority_placement", Code: "authority_host_does_not_resolve"}
		}
	}
	for _, a := range addrs {
		if ip := net.ParseIP(a); ip != nil && ip.Equal(machine) {
			return true, nil
		}
	}
	return false, nil
}

// dcMountServer is the machine a network mount comes from, read from the SOURCE column of findmnt:
// `host:/export` (nfs), `user@host:/dir` (sshfs), `//host/share` (cifs). Empty when it cannot be read.
func dcMountServer(fstype, source string) string {
	switch fstype {
	case "nfs", "nfs4", "fuse.sshfs":
		host := source
		if strings.HasPrefix(source, "[") { // an IPv6 address
			if end := strings.Index(source, "]"); end > 0 {
				return source[1:end]
			}
			return ""
		}
		i := strings.Index(host, ":")
		if i <= 0 {
			return ""
		}
		host = host[:i]
		if at := strings.LastIndex(host, "@"); at >= 0 {
			host = host[at+1:]
		}
		return host
	case "cifs", "smb3":
		host := strings.TrimPrefix(source, "//")
		if host == source {
			return ""
		}
		if i := strings.Index(host, "/"); i > 0 {
			host = host[:i]
		}
		return host
	}
	return ""
}

// dcMountOnMachineDisk judges one directory as the machine sees it (findmnt FSTYPE and SOURCE): it is
// on the machine's own disk unless it is a network mount whose server is another machine. What cannot be
// shown to come from another machine counts as the machine's own disk.
func dcMountOnMachineDisk(fstype, source, machineAddr string, lookup dcLookup) (bool, string) {
	switch fstype {
	case "nfs", "nfs4", "fuse.sshfs", "cifs", "smb3":
	default:
		return true, "a " + fstype + " filesystem, not a network mount of another machine"
	}
	server := dcMountServer(fstype, source)
	if server == "" {
		return true, "the " + fstype + " mount does not say which machine serves it"
	}
	on, err := dcNameIsMachine(server, machineAddr, lookup)
	switch {
	case err != nil:
		return true, "the server of the " + fstype + " mount does not resolve"
	case on:
		return true, "the " + fstype + " mount is served by the machine itself"
	}
	return false, "a " + fstype + " mount served by another machine"
}

// dcAuthorityPlacement judges where the authority journal lives against the machine that is cut: an S3
// endpoint by the addresses its name resolves to, a directory by the mount the cut machine itself reports
// for it. ok is false when the journal is on the cut machine's disk or cannot be shown not to be; err when
// a machine could not be asked or a name not resolved. The evidence names the voters that share the
// journal's machine (allowed: only the cut machine's loss is the scenario).
func dcAuthorityPlacement(rem *dcRemote, o *dcHostsOptions, lookup dcLookup) (ok bool, detail string, evidence map[string]string, err error) {
	evidence = map[string]string{}
	if o.spot.S3 != nil {
		u, perr := url.Parse(o.spot.S3.Endpoint)
		if perr != nil || u.Hostname() == "" {
			return false, "", nil, &smokeFailure{Smoke: dcSmoke, Stage: "authority_placement", Code: "endpoint_unreadable"}
		}
		evidence["kind"] = "s3"
		var sharing []string
		cutShares := false
		for _, id := range dcNodes {
			on, e := dcNameIsMachine(u.Hostname(), o.hosts[id].Addr, lookup)
			if e != nil {
				return false, "", nil, e
			}
			if on {
				sharing = append(sharing, dcKey(id))
				cutShares = cutShares || id == o.cut
			}
		}
		evidence["voters_on_the_authority_machine"] = "none"
		if len(sharing) > 0 {
			evidence["voters_on_the_authority_machine"] = strings.Join(sharing, ",")
		}
		if cutShares {
			return false, "the journal's endpoint resolves to the machine that is powered off", evidence, nil
		}
		return true, "the journal's endpoint resolves to no address of the machine that is powered off", evidence, nil
	}
	dir := o.spot.Dir
	evidence["kind"] = "directory"
	for _, id := range dcNodes {
		out, e := rem.run(id, "findmnt -n -T "+dcQuote(dir)+" -o FSTYPE,SOURCE", nil, time.Minute)
		if e != nil {
			return false, "", nil, e
		}
		fields := strings.Fields(string(out))
		if len(fields) < 2 {
			return false, "", nil, &smokeFailure{Smoke: dcSmoke, Stage: "authority_placement", Code: "findmnt_unreadable_voter_" + dcKey(id)}
		}
		onDisk, why := dcMountOnMachineDisk(fields[0], fields[1], o.hosts[id].Addr, lookup)
		evidence["voter_"+dcKey(id)+"_sees_the_directory_as"] = fields[0] + " " + fields[1]
		if id == o.cut {
			if onDisk {
				return false, "the authority directory is on the cut machine's own disk: " + why, evidence, nil
			}
			detail = "the cut machine sees the authority directory as " + why
		}
	}
	return true, detail, evidence, nil
}

// dcQuote makes one word of a /bin/sh command line.
func dcQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// dcRemote runs commands on the voters' machines over ssh. exec is the one place a process is
// started, so the unit tests replace it.
type dcRemote struct {
	hosts map[uint64]dcHostSpec
	exec  func(spec dcHostSpec, command string, stdin io.Reader, limit time.Duration) ([]byte, error)
}

func newDCRemote(hosts map[uint64]dcHostSpec) *dcRemote {
	return &dcRemote{hosts: hosts, exec: dcSSHExec}
}

// dcSSHExec runs one command line on a host. The failure carries only the exit status, never the
// command's output: the command may have read a key.
func dcSSHExec(spec dcHostSpec, command string, stdin io.Reader, limit time.Duration) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=4", spec.SSH, command)
	cmd.WaitDelay = 5 * time.Second
	cmd.Stdin = stdin
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	if err := cmd.Run(); err != nil {
		return nil, &smokeFailure{Smoke: dcSmoke, Stage: "ssh", Code: "command_failed", Actual: exitCode(err)}
	}
	return out.Bytes(), nil
}

func exitCode(err error) int {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return -1
}

func (c *dcRemote) run(id uint64, command string, stdin io.Reader, limit time.Duration) ([]byte, error) {
	spec, ok := c.hosts[id]
	if !ok {
		return nil, errors.New("unknown voter")
	}
	return c.exec(spec, command, stdin, limit)
}

// facts asks a machine who it is.
func (c *dcRemote) facts(id uint64) (dcHostFacts, error) {
	out, err := c.run(id, `printf '%s\n' "$(hostname)" "$(cat /etc/machine-id)" "$(cat /proc/sys/kernel/random/boot_id)" "$(uname -r)"`, nil, time.Minute)
	if err != nil {
		return dcHostFacts{}, err
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) != 4 {
		return dcHostFacts{}, &smokeFailure{Smoke: dcSmoke, Stage: "host_facts", Code: "unexpected_answer"}
	}
	return dcHostFacts{Hostname: strings.TrimSpace(lines[0]), MachineID: strings.TrimSpace(lines[1]), BootID: strings.TrimSpace(lines[2]), Kernel: strings.TrimSpace(lines[3])}, nil
}

// push writes a file on a host through stdin (a secret never travels in a command line), syncs it and
// its directory, and reads its digest back from the disk of that host: a power cut loses what was
// not synced, and a voter must find its binary and keys whole after one.
func (c *dcRemote) push(id uint64, remote string, mode string, content []byte) error {
	dir := path.Dir(remote)
	script := "set -e; umask 077; install -d -m 0700 " + dcQuote(dir) + "; cat > " + dcQuote(remote+".new") + "; chmod " + mode + " " + dcQuote(remote+".new") + "; sync " + dcQuote(remote+".new") + "; mv -f " + dcQuote(remote+".new") + " " + dcQuote(remote) + "; sync " + dcQuote(dir)
	if _, err := c.run(id, script, bytes.NewReader(content), 10*time.Minute); err != nil {
		return err
	}
	out, err := c.run(id, "sha256sum "+dcQuote(remote), nil, time.Minute)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(content)
	if !strings.HasPrefix(string(out), hex.EncodeToString(sum[:])+" ") {
		return &smokeFailure{Smoke: dcSmoke, Stage: "push", Code: "digest_differs_on_the_host"}
	}
	return nil
}

func (c *dcRemote) pushFile(id uint64, remote, mode, local string) error {
	raw, err := os.ReadFile(local)
	if err != nil {
		return err
	}
	return c.push(id, remote, mode, raw)
}

// systemctl runs one verb on the voter's unit (stop waits for the process to exit).
func (c *dcRemote) systemctl(id uint64, verb string) error {
	_, err := c.run(id, "systemctl "+verb+" "+dcRemoteUnit, nil, 3*time.Minute)
	return err
}

// wipe removes every trace of a run of this smoke from a host: the unit (stopped, disabled, its file),
// the binaries, the keys and credentials, the node data and the backups. It starts every run and, with
// --cleanup, ends a run that passed.
func (c *dcRemote) wipe(id uint64) error {
	unit := "/etc/systemd/system/" + dcRemoteUnit + ".service"
	_, err := c.run(id, "systemctl stop "+dcRemoteUnit+" 2>/dev/null || true; systemctl disable "+dcRemoteUnit+" 2>/dev/null || true; rm -rf "+dcQuote(dcRemoteVar)+" "+dcQuote(dcRemoteEtc)+"; rm -f "+dcQuote(unit)+" "+dcQuote(dcRemoteBin)+" "+dcQuote(dcRemoteSmoke)+"; systemctl daemon-reload", nil, 3*time.Minute)
	return err
}

// syncAll flushes a host's page cache to disk and drops it (a power cut then reads back what is really there).
func (c *dcRemote) syncAll(id uint64) error {
	_, err := c.run(id, "sync; echo 3 > /proc/sys/vm/drop_caches", nil, 2*time.Minute)
	return err
}

// scan runs the whole-file scan of the smoke on the voter's own host (the canary is read from stdin, not
// from the command line, so it is not in a process list).
func (c *dcRemote) scan(id uint64, dir, needle string) (dcScan, error) {
	out, err := c.run(id, dcQuote(dcRemoteSmoke)+" deletion-cluster-scan --dir "+dcQuote(dir), strings.NewReader(needle+"\n"), 10*time.Minute)
	if err != nil {
		return dcScan{}, err
	}
	var s dcScan
	if err = json.Unmarshal(out, &s); err != nil {
		return dcScan{}, &smokeFailure{Smoke: dcSmoke, Stage: "remote_scan", Code: "unexpected_answer"}
	}
	return s, nil
}

// certificate reads the public listener certificate the voter generated in its data directory.
func (c *dcRemote) certificate(id uint64, dataDir string) (*x509.Certificate, error) {
	out, err := c.run(id, "cat "+dcQuote(dataDir+"/server.crt"), nil, time.Minute)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(out)
	if block == nil {
		return nil, &smokeFailure{Smoke: dcSmoke, Stage: "member_certificate", Code: "not_pem"}
	}
	return x509.ParseCertificate(block.Bytes)
}

// copyDown copies a directory of a host (a backup destination) into a local directory.
func (c *dcRemote) copyDown(id uint64, remoteDir, localDir string) error {
	raw, err := c.run(id, "tar -C "+dcQuote(remoteDir)+" -cf - .", nil, 15*time.Minute)
	if err != nil {
		return err
	}
	return dcUntar(raw, localDir)
}

// dcUntar extracts a tar stream into dir: regular files and directories only, never outside dir.
func dcUntar(raw []byte, dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tr := tar.NewReader(bytes.NewReader(raw))
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		clean := path.Clean(h.Name)
		if clean == "." {
			continue
		}
		if path.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, "../") {
			return &smokeFailure{Smoke: dcSmoke, Stage: "copy_down", Code: "path_escapes_the_directory"}
		}
		target := filepath.Join(dir, filepath.FromSlash(clean))
		switch h.Typeflag {
		case tar.TypeDir:
			if err = os.MkdirAll(target, 0o700); err != nil {
				return err
			}
		case tar.TypeReg:
			if err = os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
				return err
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
			if err != nil {
				return err
			}
			_, err = io.Copy(f, tr)
			if cerr := f.Close(); err == nil {
				err = cerr
			}
			if err != nil {
				return err
			}
		default:
			return &smokeFailure{Smoke: dcSmoke, Stage: "copy_down", Code: "unexpected_entry_type"}
		}
	}
}

// dcUnit is the systemd unit of one voter. It is ENABLED, so a voter whose machine lost power serves
// again when the machine is powered on, with nobody starting it; the authority credentials are in the
// unit's EnvironmentFile (a root-only file), never in the command line.
func dcUnit(spec dcHostSpec, a *dcAuthority) string {
	id := strconv.FormatUint(spec.ID, 10)
	cmdline := dcRemoteBin + " serve --mode=distributed --node-id " + id + " --cluster-config " + dcRemoteEtc + "/node-" + id + ".json --data-dir " + dcRemoteVar + "/node-" + id + " --listen " + spec.Addr + ":" + dcPublicPort
	env := ""
	if a != nil {
		cmdline += " --authority-keys " + dcRemoteKeys
		remote := *a
		remote.Keys = dcRemoteKeys
		flags := remote.flags()
		if a.S3 != nil {
			env = "EnvironmentFile=" + dcRemoteEnv + "\n"
		}
		cmdline += " " + strings.Join(flags, " ")
	}
	return "[Unit]\nDescription=Soundpost deletion-cluster smoke voter " + id + "\nAfter=network-online.target\nWants=network-online.target\nStartLimitIntervalSec=0\n\n[Service]\nType=simple\n" + env +
		"ExecStart=" + cmdline + "\nRestart=on-failure\nRestartSec=3\nTimeoutStopSec=60\nLimitNOFILE=65536\n\n[Install]\nWantedBy=multi-user.target\n"
}

// dcAuthorityEnv is the content of a voter's authority.env: the S3 credentials and the CA bundle path,
// taken from the environment of this process. Empty when the journal is a directory.
func dcAuthorityEnv(a *dcAuthority) []byte {
	if a == nil || a.S3 == nil {
		return nil
	}
	return []byte("SOUNDPOST_AUTHORITY_S3_ACCESS_KEY=" + os.Getenv("SOUNDPOST_AUTHORITY_S3_ACCESS_KEY") + "\nSOUNDPOST_AUTHORITY_S3_SECRET_KEY=" + os.Getenv("SOUNDPOST_AUTHORITY_S3_SECRET_KEY") + "\nSSL_CERT_FILE=" + dcRemoteS3CA + "\n")
}

// RunDeletionClusterScan is the helper the smoke runs ON each voter's host: it scans one directory
// for the name read from stdin (the same nested decoder as the local scan; a directory that is not
// there holds nothing) and prints the result as JSON.
func RunDeletionClusterScan(args []string) error {
	var dir string
	for i := 0; i < len(args); i++ {
		if args[i] == "--dir" && i+1 < len(args) {
			dir = args[i+1]
			i++
		}
	}
	if dir == "" {
		return errors.New("deletion-cluster-scan wants --dir")
	}
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, 4096))
	if err != nil {
		return err
	}
	needle := strings.TrimSpace(string(raw))
	if needle == "" {
		return errors.New("deletion-cluster-scan wants the name on stdin")
	}
	s, err := dcScanIfPresent(dir, needle)
	if err != nil {
		return err
	}
	out, err := json.Marshal(s)
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(append(out, '\n'))
	return err
}

// ---- the ACK journal of the load that runs through the deletion and the power cut ----

// dcAckLine is one line of the journal. The hash chains every line to the one before, so a reader
// refuses a journal that lost, changed, reordered or swapped a line: the claims made against it are
// made against an untampered record. A batch's `issue` line is synced BEFORE its first send and its
// `ack` line BEFORE the writer counts the acknowledgement.
type dcAckLine struct {
	N     uint64 `json:"n"`
	Kind  string `json:"kind"` // issue | ack | reject
	Seq   uint64 `json:"seq"`  // the value of the sample (its sequence number)
	At    int64  `json:"at"`   // the observed time of the sample (ns)
	Node  uint64 `json:"node,omitempty"`
	Prev  string `json:"prev"`
	Chain string `json:"chain"`
}

func dcAckChain(l dcAckLine) string {
	l.Chain = ""
	raw, _ := json.Marshal(l)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// dcAckJournal appends lines to the journal file with one fsync per line.
type dcAckJournal struct {
	f    *os.File
	n    uint64
	prev string
}

func dcCreateAckJournal(file string) (*dcAckJournal, error) {
	f, err := os.OpenFile(file, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	return &dcAckJournal{f: f, prev: strings.Repeat("0", 64)}, nil
}

// add appends and syncs one line.
func (j *dcAckJournal) add(kind string, seq uint64, at int64, node uint64) error {
	j.n++
	l := dcAckLine{N: j.n, Kind: kind, Seq: seq, At: at, Node: node, Prev: j.prev}
	l.Chain = dcAckChain(l)
	raw, err := json.Marshal(l)
	if err != nil {
		return err
	}
	if _, err = j.f.Write(append(raw, '\n')); err != nil {
		return err
	}
	if err = j.f.Sync(); err != nil {
		return err
	}
	j.prev = l.Chain
	return nil
}

func (j *dcAckJournal) close() error { return j.f.Close() }

// dcAckState is what an intact journal says: every sample issued (value -> observed time), the
// acknowledged ones and the refused ones.
type dcAckState struct {
	Issued   map[uint64]int64
	Acked    map[uint64]uint64 // value -> the voter that acknowledged it
	Rejected map[uint64]bool
	Lines    uint64
}

// dcReadAckJournal reads a journal and refuses it unless its chain is whole: a first line that does not
// start the chain, a line that does not follow its predecessor, a changed line, a numbering gap, an
// ack or reject for a sample that was never issued, or a sample issued twice.
func dcReadAckJournal(raw []byte) (dcAckState, error) {
	st := dcAckState{Issued: map[uint64]int64{}, Acked: map[uint64]uint64{}, Rejected: map[uint64]bool{}}
	prev := strings.Repeat("0", 64)
	for i, line := range bytes.Split(bytes.TrimRight(raw, "\n"), []byte("\n")) {
		if len(line) == 0 {
			return st, errors.New("journal has an empty line")
		}
		var l dcAckLine
		if err := json.Unmarshal(line, &l); err != nil {
			return st, errors.New("journal line does not decode (torn or changed)")
		}
		switch {
		case l.N != uint64(i+1):
			return st, errors.New("journal numbering has a gap or a swap")
		case l.Prev != prev:
			return st, errors.New("journal line does not follow its predecessor (a line was dropped or swapped)")
		case dcAckChain(l) != l.Chain:
			return st, errors.New("journal line was changed")
		}
		prev = l.Chain
		switch l.Kind {
		case "issue":
			if _, dup := st.Issued[l.Seq]; dup {
				return st, errors.New("a sample was issued twice")
			}
			st.Issued[l.Seq] = l.At
		case "ack":
			if _, ok := st.Issued[l.Seq]; !ok {
				return st, errors.New("an acknowledgement for a sample that was never issued")
			}
			st.Acked[l.Seq] = l.Node
		case "reject":
			if _, ok := st.Issued[l.Seq]; !ok {
				return st, errors.New("a refusal for a sample that was never issued")
			}
			st.Rejected[l.Seq] = true
		default:
			return st, errors.New("journal line of an unknown kind")
		}
		st.Lines = l.N
	}
	if st.Lines == 0 {
		return st, errors.New("journal is empty")
	}
	return st, nil
}

// dcRetained is one sample a voter retains: its value (the sequence number) and its observed time.
type dcRetained struct {
	Seq uint64
	At  int64
}

// dcJudgeRetained judges the samples one voter retains against the journal; it does no I/O. Every
// acknowledged sample must be there with exactly its observed time; no sample may be retained that
// was never issued, with a changed time, or twice; a sample issued and never acknowledged may be
// retained or absent (it is counted, not judged). It returns the violations (empty is a pass).
func dcJudgeRetained(st dcAckState, retained []dcRetained) []string {
	var bad []string
	seen := map[uint64]int{}
	for _, r := range retained {
		seen[r.Seq]++
		at, issued := st.Issued[r.Seq]
		switch {
		case !issued:
			bad = append(bad, fmt.Sprintf("unknown_sample_%d", r.Seq))
		case at != r.At:
			bad = append(bad, fmt.Sprintf("changed_time_sample_%d", r.Seq))
		}
	}
	for seq, n := range seen {
		if n > 1 {
			bad = append(bad, fmt.Sprintf("duplicate_sample_%d", seq))
		}
	}
	for seq := range st.Acked {
		if seen[seq] == 0 {
			bad = append(bad, fmt.Sprintf("acknowledged_sample_missing_%d", seq))
		}
	}
	sort.Strings(bad)
	return bad
}

// dcDigest is the SHA-256 over the sorted (value, time) lines a voter retains.
func dcDigest(retained []dcRetained) string {
	rows := append([]dcRetained(nil), retained...)
	sort.Slice(rows, func(i, j int) bool { return rows[i].Seq < rows[j].Seq })
	h := sha256.New()
	for _, r := range rows {
		fmt.Fprintf(h, "%d %d\n", r.Seq, r.At)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// ---- where the power cut landed ----

// dcPoint is one sample of the deletion's state through a live voter's lifecycle poll.
type dcPoint struct {
	AtMS     int64    `json:"at_ms"`
	Phase    string   `json:"phase"`
	Physical string   `json:"physical"`
	Residual []string `json:"residual_stores,omitempty"`
}

func (p dcPoint) clean() bool {
	return p.Phase == "complete" && p.Physical == "done" && len(p.Residual) == 0
}

// dcOutage is a run of failed readiness probes of one voter.
type dcOutage struct {
	StartMS int64 `json:"start_ms"`
	EndMS   int64 `json:"end_ms"` // the first ready probe after the run; 0 while it lasts
}

func (o dcOutage) lasted() time.Duration { return time.Duration(o.EndMS-o.StartMS) * time.Millisecond }

// dcOutages folds a voter's probe samples (time, ready) into its outages: runs of at least minRun
// consecutive failures (a single failed probe is noise, not a power cut).
func dcOutages(times []int64, ready []bool, minRun int) []dcOutage {
	var out []dcOutage
	for i := 0; i < len(ready); {
		if ready[i] {
			i++
			continue
		}
		j := i
		for j < len(ready) && !ready[j] {
			j++
		}
		if j-i >= minRun {
			o := dcOutage{StartMS: times[i]}
			if j < len(ready) {
				o.EndMS = times[j]
			}
			out = append(out, o)
		}
		i = j
	}
	return out
}

// dcLongest returns the longest finished outage.
func dcLongest(outages []dcOutage) (dcOutage, bool) {
	best, found := dcOutage{}, false
	for _, o := range outages {
		if o.EndMS != 0 && (!found || o.lasted() > best.lasted()) {
			best, found = o, true
		}
	}
	return best, found
}

// dcCutMidDeletion judges whether the power cut landed DURING the deletion: the deletion had begun
// before the cut voter's first failed probe, and the last state seen through a live voter at or
// before that instant was not yet the clean receipt. A cut after the receipt read clean is a run of
// something else (a crash after the erasure), and is reported as such, not as this evidence.
func dcCutMidDeletion(beganMS int64, timeline []dcPoint, outage dcOutage) (bool, string) {
	if beganMS <= 0 || outage.StartMS < beganMS {
		return false, "the cut voter's outage began before the deletion did"
	}
	var last *dcPoint
	for i := range timeline {
		if timeline[i].AtMS <= outage.StartMS {
			last = &timeline[i]
		}
	}
	if last == nil {
		return false, "no state of the deletion was observed before the cut"
	}
	if last.clean() {
		return false, "the receipt already read clean through a live voter when the power was cut"
	}
	return true, fmt.Sprintf("at the cut the deletion was phase %s, physical %s, residual %v", safeToken(last.Phase), safeToken(last.Physical), last.Residual)
}
