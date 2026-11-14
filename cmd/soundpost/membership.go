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
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
)

// membershipSocket is the operator channel of a RUNNING distributed node: a Unix socket inside the
// node's private data directory (mode 0700, the socket 0600), so only the service account can use
// it. There is no network listener and no credential: membership changes are not a tenant
// operation. `soundpost membership` is its client.
const membershipSocket = "membership.sock"

// errMembershipIncomplete is the exit-1 outcome of a membership step that left groups undone. The
// per-group result is already on stdout.
var errMembershipIncomplete = errors.New("membership step incomplete")

var errMembershipUsage = errors.New("usage: soundpost membership status|add-learner|replace --data-dir DIR (add-learner: --id --address --identity --failure-domain; replace: --remove --promote)")

// maxSocketPath is the longest path a Unix socket address takes on Linux.
const maxSocketPath = 104

// serveMembership starts the operator socket of a distributed node. It returns nil, nil for a
// single-host installation. A data directory whose path is too long for a socket address gets no
// socket (the error says so; serve continues, the node is otherwise unaffected).
func serveMembership(dir string, core *appcore.App) (io.Closer, error) {
	groups, err := core.MembershipGroups()
	if errors.Is(err, appcore.ErrNoMembership) {
		return nil, nil
	}
	return serveMembershipGroups(dir, groups, peerIsOwner)
}

// gatedListener drops every connection the allow function refuses before a byte is read from it.
type gatedListener struct {
	net.Listener
	allow func(net.Conn) bool
}

func (l *gatedListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil || l.allow(c) {
			return c, err
		}
		_ = c.Close()
	}
}

func serveMembershipGroups(dir string, groups []appcore.MembershipGroup, allow func(net.Conn) bool) (io.Closer, error) {
	path := filepath.Join(dir, membershipSocket)
	if len(path) > maxSocketPath {
		return nil, errors.New("the data directory path is too long for the membership socket")
	}
	_ = os.Remove(path)
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err = os.Chmod(path, 0o600); err != nil {
		listener.Close()
		return nil, err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, r *http.Request) {
		writeMembershipJSON(w, appcore.ReportMembership(groups))
	})
	mux.HandleFunc("POST /step", func(w http.ResponseWriter, r *http.Request) {
		var change appcore.MembershipChange
		body := http.MaxBytesReader(w, r.Body, 4096)
		decoder := json.NewDecoder(body)
		decoder.DisallowUnknownFields()
		if decoder.Decode(&change) != nil {
			http.Error(w, "invalid", http.StatusBadRequest)
			return
		}
		writeMembershipJSON(w, appcore.StepMembership(r.Context(), groups, change))
	})
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = server.Serve(&gatedListener{Listener: listener, allow: allow}) }()
	return closerFunc(func() error { err := server.Close(); _ = os.Remove(path); return err }), nil
}

type closerFunc func() error

func (f closerFunc) Close() error { return f() }

func writeMembershipJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// runMembership is `soundpost membership <status|add-learner|replace> --data-dir DIR ...`.
//
//	status                                    the configuration of every group on this node
//	add-learner --id N --address URL --identity NAME --failure-domain NAME
//	                                          install a fresh member as a learner in every group
//	replace --remove N --promote M            promote learner M and remove voter N, per group
//
// A step acts on the groups this node leads and reports every group. Run it on every surviving
// node until it exits 0: that is when all groups are in the requested configuration. A group led
// by another node reports its leader; a learner that has not caught up reports
// learner_not_caught_up (retry).
func runMembership(args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: soundpost membership status|add-learner|replace --data-dir DIR")
	}
	op := args[0]
	f := flag.NewFlagSet("membership", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	dir := f.String("data-dir", "", "private data directory of the running node")
	id := f.Uint64("id", 0, "raft id of the new learner")
	address := f.String("address", "", "peer https URL of the new learner")
	identity := f.String("identity", "", "node identity of the new learner")
	domain := f.String("failure-domain", "", "failure domain attestation of the new learner")
	remove := f.Uint64("remove", 0, "raft id of the voter to remove")
	promote := f.Uint64("promote", 0, "raft id of the learner to promote")
	if err := f.Parse(args[1:]); err != nil || *dir == "" {
		return errMembershipUsage
	}
	client := &http.Client{Timeout: 30 * time.Minute, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", filepath.Join(*dir, membershipSocket))
	}}}
	switch op {
	case "status":
		var status []appcore.MembershipStatus
		if err := membershipCall(client, http.MethodGet, "/status", nil, &status); err != nil {
			return err
		}
		return printMembershipStatus(out, status)
	case "add-learner", "replace":
		change := appcore.MembershipChange{Op: appcore.MembershipAddLearner}
		if op == "add-learner" {
			change.Member = replica.Member{ID: *id, Address: *address, NodeIdentity: *identity, FailureDomain: *domain, Learner: true}
		} else {
			change = appcore.MembershipChange{Op: appcore.MembershipReplace, Remove: *remove, Promote: *promote}
		}
		raw, _ := json.Marshal(change)
		var outcomes []appcore.MembershipOutcome
		if err := membershipCall(client, http.MethodPost, "/step", raw, &outcomes); err != nil {
			return err
		}
		return printMembershipOutcomes(out, outcomes)
	}
	return errMembershipUsage
}

func membershipCall(client *http.Client, method, path string, body []byte, into any) error {
	request, err := http.NewRequest(method, "http://membership"+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return model.Fail(model.Invalid)
	}
	return json.NewDecoder(io.LimitReader(response.Body, 8<<20)).Decode(into)
}

func printMembershipStatus(out io.Writer, status []appcore.MembershipStatus) error {
	for _, g := range status {
		fmt.Fprintf(out, "group %s leader=%d term=%d applied=%d failed=%t revision=%d members=", g.Group, g.Leader, g.Term, g.Applied, g.Failed, g.Members.Revision)
		for i, m := range g.Members.Nodes {
			if i > 0 {
				fmt.Fprint(out, ",")
			}
			role := "voter"
			if m.Learner {
				role = "learner"
			}
			fmt.Fprintf(out, "%d:%s:%s", m.ID, role, m.NodeIdentity)
		}
		fmt.Fprintln(out)
	}
	return nil
}

// printMembershipOutcomes prints one line per group that is not yet in the requested
// configuration, then a summary, and returns errMembershipIncomplete unless every group is.
func printMembershipOutcomes(out io.Writer, outcomes []appcore.MembershipOutcome) error {
	counts := map[string]int{}
	for _, o := range outcomes {
		counts[o.Result]++
		if o.Result == appcore.OutcomeApplied || o.Result == appcore.OutcomeAlready {
			continue
		}
		if o.Result == appcore.OutcomeNotLeader {
			fmt.Fprintf(out, "group %s: %s (led by node %d; run this step there)\n", o.Group, o.Result, o.Leader)
		} else {
			fmt.Fprintf(out, "group %s: %s\n", o.Group, o.Result)
		}
	}
	fmt.Fprintf(out, "groups=%d applied=%d already=%d not_leader=%d learner_not_caught_up=%d unavailable=%d rejected=%d\n", len(outcomes),
		counts[appcore.OutcomeApplied], counts[appcore.OutcomeAlready], counts[appcore.OutcomeNotLeader], counts[appcore.OutcomeNotCaughtUp], counts[appcore.OutcomeUnavailable], counts[appcore.OutcomeRejected])
	if !appcore.MembershipDone(outcomes) {
		return errMembershipIncomplete
	}
	return nil
}
