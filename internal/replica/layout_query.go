// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

// ErrMemberNotRunning is what QueryLayout reports (also an ErrUnavailable) when no connection could be
// made to the member's peer address: no process listens there yet, or the address cannot be reached.
// It is not the answer of a binary that does not implement the question (the previous release
// answers the route with a refusal, which is plain ErrUnavailable): a member that is not running has
// no binary to be incompatible, so a learner that is about to be started can be added before it runs.
var ErrMemberNotRunning = errors.Join(ErrUnavailable, errors.New("nothing listens at the member's peer address"))

// layoutPath is the member-to-member question "does your RUNNING binary read the sharded artifact
// ledger index and the per-replay pins without the per-project values?" (D70). Nothing stored can
// answer it: a voter put back on the previous release keeps whatever its last run advertised. The
// previous release does not implement this route (a GET on a path outside raftPath's POST routes is
// answered forbidden), so a member that cannot answer is one that does not support the layout, which
// is what `soundpost upgrade contract-indexes` refuses on.
const layoutPath = "/internal/raft/v1/layout"

type layoutAnswer struct {
	Node      model.Uint64 `json:"node"`
	Supported model.Uint64 `json:"supported"`
}

// SetLayoutSupport installs what this member answers to QueryLayout: the highest index layout the
// running binary reads, and false to behave like a binary that does not implement the question
// (tests).
func (t *MTLS) SetLayoutSupport(answer func() (uint64, bool)) {
	if answer == nil {
		t.layoutSupport.Store(nil)
		return
	}
	t.layoutSupport.Store(&answer)
}

// QueryLayout asks target, over the authenticated peer connection, for the highest index layout its
// running binary reads. A member that does not answer 200 with its own node id (the previous release,
// a member whose connection fails after it was made) is reported as ErrUnavailable; a member nothing
// could be connected to is ErrMemberNotRunning.
func (t *MTLS) QueryLayout(ctx context.Context, target Member) (uint64, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	client, err := t.peerClient(target)
	if err != nil {
		return 0, err
	}
	request, err := http.NewRequestWithContext(ctx, "GET", strings.TrimSuffix(target.Address, "/")+layoutPath, nil)
	if err != nil {
		return 0, err
	}
	response, err := client.Do(request)
	if err != nil {
		var op *net.OpError
		if errors.As(err, &op) && op.Op == "dial" {
			return 0, ErrMemberNotRunning
		}
		return 0, ErrUnavailable
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 1<<16))
	if err != nil || response.StatusCode != http.StatusOK {
		return 0, ErrUnavailable
	}
	var answer layoutAnswer
	if model.StrictJSON(raw, &answer) != nil || uint64(answer.Node) != target.ID {
		return 0, ErrUnavailable
	}
	return uint64(answer.Supported), nil
}

func (t *MTLS) serveLayout(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" || r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	identity := certificateIdentity(r.TLS.PeerCertificates[0])
	// The groups are copied out before any of them is asked: a group holds its own lock while it sends
	// (MTLS.Send takes t.mu), so t.mu must never be held across a group's lock (a writer waiting on t.mu
	// then blocks every reader, and the two halves deadlock).
	t.mu.RLock()
	groups := make([]*Group, 0, len(t.groups))
	for _, g := range t.groups {
		groups = append(groups, g)
	}
	t.mu.RUnlock()
	allowed := false
	for _, g := range groups {
		for _, member := range g.transportMembers().Nodes {
			if member.NodeIdentity == identity {
				allowed = true
			}
		}
		if allowed {
			break
		}
	}
	answer := t.layoutSupport.Load()
	if !allowed || answer == nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	supported, ok := (*answer)()
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(layoutAnswer{Node: model.Uint64(t.id), Supported: model.Uint64(supported)})
}
