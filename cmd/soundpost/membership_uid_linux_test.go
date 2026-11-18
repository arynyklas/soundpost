// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"

	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
)

// The child of TestMembershipSocketRefusesAProcessOfAnotherUid: it runs `membership status` against
// the directory named by the environment and reports whether the node answered.
func TestMembershipUidChildHelper(t *testing.T) {
	dir := os.Getenv("SOUNDPOST_MEMBERSHIP_UID_CHILD")
	if dir == "" {
		t.Skip("helper of TestMembershipSocketRefusesAProcessOfAnotherUid")
	}
	var out bytes.Buffer
	if err := runMembership([]string{"status", "--data-dir", dir}, &out); err != nil || !strings.Contains(out.String(), "voter:") {
		os.Stdout.WriteString("REFUSED\n")
		os.Exit(3)
	}
	os.Stdout.WriteString("ANSWERED\n")
	os.Exit(0)
}

// With a real second uid: the socket is served by root and made reachable by file mode for
// everyone, so only the SO_PEERCRED check stands between uid 65534 and the membership state. A
// child of uid 65534 gets no answer; a child of the server's own uid does.
func TestMembershipSocketRefusesAProcessOfAnotherUid(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to start a child process under another uid (run the test binary as root)")
	}
	dir, err := os.MkdirTemp("", "w2uid")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	if err = os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	group := &socketGroup{status: replica.Status{Group: model.NewID(), ID: 1, Leader: 1, Revision: 1, Members: threeVoters()}}
	closer, err := serveMembershipGroups(dir, []appcore.MembershipGroup{group}, nil, peerIsOwner)
	if err != nil {
		t.Fatal(err)
	}
	defer closer.Close()
	// The modes would keep the other uid out first; open them so the peer check is what is tested.
	if err = os.Chmod(dir+"/"+membershipSocket, 0o666); err != nil {
		t.Fatal(err)
	}
	run := func(cred *syscall.Credential) (string, error) {
		cmd := exec.Command(os.Args[0], "-test.run=^TestMembershipUidChildHelper$")
		cmd.Env = append(os.Environ(), "SOUNDPOST_MEMBERSHIP_UID_CHILD="+dir)
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: cred}
		out, err := cmd.Output()
		return string(out), err
	}
	if out, err := run(nil); err != nil || !strings.Contains(out, "ANSWERED") {
		t.Fatalf("a child of the server's own uid: %v %q", err, out)
	}
	out, err := run(&syscall.Credential{Uid: 65534, Gid: 65534})
	if err == nil || strings.Contains(out, "ANSWERED") || !strings.Contains(out, "REFUSED") {
		t.Fatalf("a child of uid 65534 was not refused: %v %q", err, out)
	}
}
