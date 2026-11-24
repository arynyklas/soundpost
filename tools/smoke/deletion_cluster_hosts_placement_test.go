// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"errors"
	"strings"
	"testing"
)

func dcFakeLookup(table map[string][]string) dcLookup {
	return func(host string) ([]string, error) {
		if addrs, ok := table[host]; ok {
			return addrs, nil
		}
		return nil, errors.New("no such host")
	}
}

// The authority journal must not live on the machine that is cut. A name is judged by what it resolves
// to (an alias of the cut machine is the cut machine), never by its spelling.
func TestDeletionClusterHostsAuthorityEndpointIsJudgedByAddressNotByName(t *testing.T) {
	lookup := dcFakeLookup(map[string][]string{
		"s3.example.invalid":    {"192.0.2.50"},
		"alias-of-a.invalid":    {"192.0.2.1"},
		"two-faced.example.org": {"192.0.2.50", "192.0.2.1"},
	})
	for _, c := range []struct {
		name string
		host string
		want bool
	}{
		{"the cut machine's own address", "192.0.2.1", true},
		{"another machine's address", "192.0.2.50", false},
		{"an alias of the cut machine", "alias-of-a.invalid", true},
		{"a name of another machine", "s3.example.invalid", false},
		{"a name with one address of the cut machine", "two-faced.example.org", true},
	} {
		got, err := dcNameIsMachine(c.host, "192.0.2.1", lookup)
		if err != nil || got != c.want {
			t.Errorf("%s: on the machine %v (want %v), error %v", c.name, got, c.want, err)
		}
	}
	if _, err := dcNameIsMachine("nowhere.invalid", "192.0.2.1", lookup); err == nil {
		t.Error("a name that does not resolve was judged: the placement is unproven, not fine")
	}
}

// A directory journal is off the cut machine's disk only when that machine sees it through a network
// filesystem whose server is another machine.
func TestDeletionClusterHostsAuthorityDirectoryMustNotBeTheCutMachinesDisk(t *testing.T) {
	lookup := dcFakeLookup(map[string][]string{"journal-host.invalid": {"192.0.2.60"}, "vm-a.invalid": {"192.0.2.1"}})
	for _, c := range []struct {
		name, fstype, source string
		onDisk               bool
	}{
		{"local ext4", "ext4", "/dev/sda1", true},
		{"local xfs", "xfs", "/dev/vdb", true},
		{"tmpfs", "tmpfs", "tmpfs", true},
		{"overlay", "overlay", "overlay", true},
		{"a bind of a local directory", "fuse", "/srv/x", true},
		{"sshfs of another machine", "fuse.sshfs", "sp@192.0.2.60:/srv/journal", false},
		{"sshfs by name of another machine", "fuse.sshfs", "sp@journal-host.invalid:/srv/journal", false},
		{"nfs4 of another machine", "nfs4", "192.0.2.60:/export/journal", false},
		{"cifs of another machine", "cifs", "//journal-host.invalid/journal", false},
		{"nfs served by the cut machine itself", "nfs4", "192.0.2.1:/export/journal", true},
		{"sshfs served by the cut machine under another name", "fuse.sshfs", "root@vm-a.invalid:/srv/journal", true},
		{"a network source that does not say its server", "nfs", "garbage", true},
		{"a network source that does not resolve", "nfs4", "unknown.invalid:/x", true},
	} {
		onDisk, why := dcMountOnMachineDisk(c.fstype, c.source, "192.0.2.1", lookup)
		if onDisk != c.onDisk {
			t.Errorf("%s: on the machine's disk %v (want %v): %s", c.name, onDisk, c.onDisk, why)
		}
		if why == "" {
			t.Errorf("%s: no reason given", c.name)
		}
	}
}

// The check the run makes before it starts the voters: S3 (by address) and a directory (by the mount
// the cut machine itself reports).
func TestDeletionClusterHostsAuthorityPlacementIsCheckedForS3AndForADirectory(t *testing.T) {
	hosts, _ := dcParseHosts("1=root@vm-a=192.0.2.1,2=root@vm-b=192.0.2.2,3=root@vm-c=192.0.2.3")
	lookup := dcFakeLookup(map[string][]string{"s3.example.invalid": {"192.0.2.50"}, "alias-of-a.invalid": {"192.0.2.1"}, "alias-of-b.invalid": {"192.0.2.2"}})

	s3 := func(host string) *dcHostsOptions {
		return &dcHostsOptions{hosts: hosts, cut: 1, spot: &dcAuthority{S3: &dcS3{Endpoint: "https://" + host + ":9000", Bucket: "b"}}}
	}
	if ok, why, _, err := dcAuthorityPlacement(&dcRemote{hosts: hosts}, s3("s3.example.invalid"), lookup); err != nil || !ok {
		t.Fatalf("a bucket of a fourth machine refused: %v %s", err, why)
	}
	if ok, _, _, err := dcAuthorityPlacement(&dcRemote{hosts: hosts}, s3("alias-of-a.invalid"), lookup); err != nil || ok {
		t.Fatalf("a bucket reached through an alias of the cut machine accepted (error %v)", err)
	}
	ok, _, ev, err := dcAuthorityPlacement(&dcRemote{hosts: hosts}, s3("alias-of-b.invalid"), lookup)
	if err != nil || !ok {
		t.Fatalf("a bucket on another voter's machine refused (only the cut machine is the criterion): %v", err)
	}
	if !strings.Contains(ev["voters_on_the_authority_machine"], "2") {
		t.Fatalf("the voter that shares the journal's machine is not recorded: %v", ev)
	}

	dir := func(findmnt string) (*dcHostsOptions, *dcRemote, *dcFakeShell) {
		sh := &dcFakeShell{answer: map[string]string{"findmnt": findmnt}}
		return &dcHostsOptions{hosts: hosts, cut: 1, spot: &dcAuthority{Dir: "/mnt/journal"}}, &dcRemote{hosts: hosts, exec: sh.exec}, sh
	}
	o, rem, sh := dir("fuse.sshfs sp@192.0.2.60:/srv/journal\n")
	if ok, why, _, err := dcAuthorityPlacement(rem, o, lookup); err != nil || !ok {
		t.Fatalf("a directory mounted from another machine refused: %v %s", err, why)
	}
	asked := 0
	for _, c := range sh.commands {
		if strings.Contains(c, "findmnt") && strings.Contains(c, "/mnt/journal") {
			asked++
		}
	}
	if asked < 1 {
		t.Fatalf("the cut machine was not asked what its authority directory is: %v", sh.commands)
	}
	o, rem, _ = dir("ext4 /dev/sda1\n")
	if ok, _, _, err := dcAuthorityPlacement(rem, o, lookup); err != nil || ok {
		t.Fatalf("a directory on the cut machine's own disk accepted (error %v)", err)
	}
	o, rem, _ = dir("nfs4 192.0.2.1:/export\n")
	if ok, _, _, err := dcAuthorityPlacement(rem, o, lookup); err != nil || ok {
		t.Fatalf("a directory exported by the cut machine itself accepted (error %v)", err)
	}
	o, rem, _ = dir("")
	if ok, _, _, err := dcAuthorityPlacement(rem, o, lookup); err == nil && ok {
		t.Fatal("an unanswered findmnt was read as off-disk")
	}
}

// What a run puts on a host, the same wipe that starts a run takes away: the unit (stopped, disabled,
// its file), the binaries, the keys, the node data and the backups.
func TestDeletionClusterHostsWipeTakesEverythingTheRunPutOnAHost(t *testing.T) {
	hosts, _ := dcParseHosts("1=root@vm-a=192.0.2.1,2=root@vm-b=192.0.2.2,3=root@vm-c=192.0.2.3")
	sh := &dcFakeShell{}
	if err := (&dcRemote{hosts: hosts, exec: sh.exec}).wipe(2); err != nil {
		t.Fatal(err)
	}
	all := strings.Join(sh.commands, "\n")
	for _, want := range []string{"systemctl stop " + dcRemoteUnit, "systemctl disable " + dcRemoteUnit, "/etc/systemd/system/" + dcRemoteUnit + ".service", dcRemoteBin, dcRemoteSmoke, dcRemoteVar, dcRemoteEtc, "daemon-reload"} {
		if !strings.Contains(all, want) {
			t.Errorf("the wipe leaves %q on the host: %s", want, all)
		}
	}
}
