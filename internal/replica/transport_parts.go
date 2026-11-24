// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
	raft "go.etcd.io/raft/v3"
	pb "go.etcd.io/raft/v3/raftpb"
	"google.golang.org/protobuf/proto"
)

// A message larger than one request (D86, condition 3).
//
// A snapshot a lagging voter or a new member is given carries the whole state of the machine, and the
// control state alone can be larger than a request may be (maxReady). Such a message is sent in parts: a
// run of requests to snapshotPartPath, each carrying one slice of the message's protobuf encoding and the
// transfer's identity, its place in the run and its total size, one after the other on the delivery lane.
// The receiving transport joins the run and steps the message exactly as if it had arrived whole; a run
// that is interrupted or out of order is dropped and the sender reports the delivery as failed, and raft
// offers the snapshot again. A message that fits one request is sent as before to raftPath, so a peer of
// the previous release is never sent a part: a part addressed to it fails as an invalid route.
//
// The route is not under raftPath's group form (it carries the group after "part/"), so the previous release
// answers it with a bad request and never reads a slice as a message.

const snapshotPartPath = raftPath + "part/"

// maxTransferBytes bounds a message in parts: the limit of one protobuf encoding.
const maxTransferBytes = 1 << 31

// partRequestTimeout bounds one part.
const partRequestTimeout = 15 * time.Second

// transferIdle is how long a transfer that is waiting for its next part is kept.
const transferIdle = 4 * partRequestTimeout

// partBytes is how many bytes of a message one request carries.
func partBytes() int { return max(1, maxReady()/16) }

type transferKey struct {
	group  model.ID
	sender uint64
}

// transfer is a message being received in parts.
type transfer struct {
	id    string
	total int // the number of parts
	next  int // the part expected next
	size  int // the length of the whole message
	buf   []byte
	timer *time.Timer // drops the transfer when its sender goes quiet
}

// partURL builds the request URL of a part.
func partURL(target Member, group model.ID, id string, seq, total, size int) string {
	q := url.Values{"id": {id}, "seq": {strconv.Itoa(seq)}, "total": {strconv.Itoa(total)}, "size": {strconv.Itoa(size)}}
	return strings.TrimSuffix(target.Address, "/") + snapshotPartPath + group.String() + "?" + q.Encode()
}

// sendParts delivers the encoding raw of a message as a run of part requests.
func (t *MTLS) sendParts(client *http.Client, target Member, group model.ID, raw []byte) error {
	if len(raw) > maxTransferBytes {
		return ErrInvalid
	}
	step := partBytes()
	total := (len(raw) + step - 1) / step
	id := randomSuffix()
	for seq := range total {
		part := raw[seq*step : min((seq+1)*step, len(raw))]
		if err := func() error {
			ctx, cancel := context.WithTimeout(context.Background(), partRequestTimeout)
			defer cancel()
			request, err := http.NewRequestWithContext(ctx, "POST", partURL(target, group, id, seq, total, len(raw)), bytes.NewReader(part))
			if err != nil {
				return err
			}
			request.Header.Set("Content-Type", "application/octet-stream")
			response, err := client.Do(request)
			if err != nil {
				return err
			}
			defer response.Body.Close()
			if response.StatusCode != http.StatusNoContent {
				return ErrUnavailable
			}
			return nil
		}(); err != nil {
			return err
		}
	}
	return nil
}

// authenticatePeer answers the group and the member id of the verified peer of a request under prefix; it
// has answered the request itself when ok is false.
func (t *MTLS) authenticatePeer(w http.ResponseWriter, r *http.Request, prefix string) (g *Group, sender uint64, ok bool) {
	if r.Method != "POST" || !strings.HasPrefix(r.URL.Path, prefix) || r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
		http.Error(w, "forbidden", http.StatusForbidden)
		return nil, 0, false
	}
	identity := certificateIdentity(r.TLS.PeerCertificates[0])
	var group model.ID
	if group.UnmarshalText([]byte(strings.TrimPrefix(r.URL.Path, prefix))) != nil {
		http.Error(w, "invalid", http.StatusBadRequest)
		return nil, 0, false
	}
	t.mu.RLock()
	g = t.groups[group]
	t.mu.RUnlock()
	if g == nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return nil, 0, false
	}
	members := g.transportMembers()
	for _, m := range members.Nodes {
		if m.NodeIdentity == identity {
			sender = m.ID
		}
	}
	if sender == 0 {
		http.Error(w, "forbidden", http.StatusForbidden)
		return nil, 0, false
	}
	return g, sender, true
}

// stepMessage decodes a whole message from the member sender and steps the group with it.
func (t *MTLS) stepMessage(w http.ResponseWriter, r *http.Request, g *Group, sender uint64, raw []byte) {
	message := &pb.Message{}
	if proto.Unmarshal(raw, message) != nil || message.GetFrom() != sender || message.GetTo() != t.id || raft.IsLocalMsg(message.GetType()) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := g.Step(r.Context(), message); err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// serveSnapshotPart takes one part of a message in parts; the last one steps the group.
func (t *MTLS) serveSnapshotPart(w http.ResponseWriter, r *http.Request) {
	g, sender, ok := t.authenticatePeer(w, r, snapshotPartPath)
	if !ok {
		return
	}
	q := r.URL.Query()
	id := q.Get("id")
	seq, e1 := strconv.Atoi(q.Get("seq"))
	total, e2 := strconv.Atoi(q.Get("total"))
	size, e3 := strconv.Atoi(q.Get("size"))
	if id == "" || len(id) > 64 || e1 != nil || e2 != nil || e3 != nil || total < 2 || seq < 0 || seq >= total || size <= 0 || size > maxTransferBytes || total > size {
		http.Error(w, "invalid", http.StatusBadRequest)
		return
	}
	limit := maxReady()
	part, err := io.ReadAll(io.LimitReader(r.Body, int64(limit)+1))
	if err != nil || len(part) == 0 || len(part) > limit {
		http.Error(w, "invalid", http.StatusBadRequest)
		return
	}
	key := transferKey{group: g.group, sender: sender}
	t.partMu.Lock()
	if t.transfers == nil {
		t.transfers = map[transferKey]*transfer{}
	}
	cur := t.transfers[key]
	if seq == 0 {
		t.dropTransferLocked(key)
		fresh := &transfer{id: id, total: total, size: size, buf: make([]byte, 0, size)}
		fresh.timer = time.AfterFunc(transferIdle, func() {
			t.partMu.Lock()
			defer t.partMu.Unlock()
			if t.transfers[key] == fresh {
				delete(t.transfers, key)
			}
		})
		t.transfers[key], cur = fresh, fresh
	} else if cur == nil || cur.id != id || cur.total != total || cur.size != size || cur.next != seq {
		t.dropTransferLocked(key)
		t.partMu.Unlock()
		http.Error(w, "invalid", http.StatusBadRequest)
		return
	}
	if len(cur.buf)+len(part) > cur.size {
		t.dropTransferLocked(key)
		t.partMu.Unlock()
		http.Error(w, "invalid", http.StatusBadRequest)
		return
	}
	cur.buf = append(cur.buf, part...)
	cur.next = seq + 1
	if cur.next < cur.total {
		cur.timer.Reset(transferIdle)
		t.partMu.Unlock()
		w.WriteHeader(http.StatusNoContent)
		return
	}
	t.dropTransferLocked(key)
	t.partMu.Unlock()
	if len(cur.buf) != cur.size {
		http.Error(w, "invalid", http.StatusBadRequest)
		return
	}
	t.stepMessage(w, r, g, sender, cur.buf)
}

// dropTransferLocked forgets the transfer of key. partMu is held.
func (t *MTLS) dropTransferLocked(key transferKey) {
	if cur := t.transfers[key]; cur != nil {
		cur.timer.Stop()
		delete(t.transfers, key)
	}
}
