// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

// Calls to the leader.
//
// A command that is judged against the state of a group (an admission transition judged against the books, a data append
// ordered after the previous one) is judged by the member that proposes it, and a proposal that names a state the leader has
// moved past is refused: when every member judges and proposes, the members that are not the leader lose that race almost every
// time, because their read of the state is a round trip older than the leader's own. A call lets a member hand the judging to
// the leader instead: the leader's handler runs where the state is current and its own queue batches the calls of every member
// with its own.
//
// The route is the proposal route's sibling (forward.go): POST under callPath, one group, one named handler, answered only by
// the leader and only for a member of the group whose transport certificate authenticated the hop. A call that failed before the
// request left this member, or that a member answered 503 because it does not lead, is ErrNoLeader (nothing ran: a retry is safe);
// one whose request was sent and whose answer did not come back is ErrCallOutcomeUnknown (the handler may have run); an
// overloaded leader, a transport failure and a handler's own error are the handler's fault or unavailable (CallFailure says which are
// retryable): the leader is the one that judges, and the caller's request is retried by its sender. A leader that does not know the
// name (another release) answers ErrNoCall, and only that sends the caller back to judging the command itself, as it did before there
// were calls.

const callPath = raftPath + "call/"

// callLimit is the largest request or answer of a call.
const callLimit = 8 << 20

// ErrNoCall: the leader does not serve the call (a release that has no such handler or no call route).
var ErrNoCall = errors.New("replica: the leader serves no such call")

// ErrCallOutcomeUnknown is an ErrUnavailable: the whole request left this member and the answer did not come back (the connection
// dropped, the answer was cut or unreadable), so the leader may have run the handler. A caller retries it only when the call is
// idempotent under a retry with the same key; ErrNoLeader, by contrast, is returned only when nothing was sent (or the member
// answered before it ran the call), and a retry of it is always safe.
var ErrCallOutcomeUnknown = fmt.Errorf("%w: the call may have reached the leader", ErrUnavailable)

// A CallHandler answers a call at the leader: from is the member whose certificate authenticated the hop. The error it
// returns reaches the caller as that error's model.Code and Retryable bit (anything that is not a model.Fault as Unavailable, not retryable).
type CallHandler func(ctx context.Context, from uint64, body []byte) ([]byte, error)

type callResult struct {
	Code model.Code `json:"code,omitempty"`
	// Retryable is the fault's retryable bit (a leader's retryable unavailable or stale). It is additive: a member that does not know
	// the field reads the answer without it (json.Unmarshal), which is what every answer was before it.
	Retryable bool   `json:"retryable,omitempty"`
	Body      []byte `json:"body,omitempty"`
}

// CallFailure is what a caller of CallLeader answers when the call failed and the leader did not answer with a fault of its own:
// unavailable, retryable when a retry is safe. It is when nothing was sent (ErrNoLeader), and when the request was sent and no
// answer came back (ErrCallOutcomeUnknown) only if the call is idempotent, that is, a retry with the same key finds what the first
// run committed and commits nothing more; otherwise the outcome stays ambiguous and the answer says no retry mends it. A fault the
// leader answered keeps its code and retryable bit as it is.
func CallFailure(err error, idempotent bool) error {
	var fault *model.Fault
	if errors.As(err, &fault) {
		return err
	}
	f := model.Fail(model.Unavailable)
	f.Retryable = errors.Is(err, ErrNoLeader) || idempotent && errors.Is(err, ErrCallOutcomeUnknown)
	return f
}

// leaderCaller is the optional Transport capability that carries a call to the leader (MTLS.CallLeader).
type leaderCaller interface {
	CallLeader(ctx context.Context, group model.ID, name string, body []byte) ([]byte, error)
}

// HandleCall installs fn as the handler of the calls named name that reach this member while it leads the group.
func (g *Group) HandleCall(name string, fn CallHandler) { g.calls.Store(name, fn) }

// CallLeader runs the handler name on the leader of the group with body and returns its answer. ErrNoLeader: nothing was sent (no
// leader is known, it was refused or unreachable, or the member answered that it does not lead): a retry is always safe.
// ErrCallOutcomeUnknown: the request was sent and no answer came back, so the handler may have run. ErrUnavailable: this member
// leads (nothing to call). ErrNoCall: the leader serves no such call. Any other error is the handler's own, as the model.Fault it
// answered, with its Retryable bit.
func (g *Group) CallLeader(ctx context.Context, name string, body []byte) ([]byte, error) {
	caller, ok := g.transport.(leaderCaller)
	if !ok {
		return nil, ErrUnavailable
	}
	return caller.CallLeader(ctx, g.group, name, body)
}

// ServeCall is the leader's half of CallLeader for a transport that is not MTLS (the in-process wires of the tests): it runs
// the handler name for the member from, and answers as the route does, the handler's faults as they are and anything else as
// unavailable. ErrNoLeader: this member does not lead the group (nothing ran); ErrNoCall: it leads and has no handler of that name.
func (g *Group) ServeCall(ctx context.Context, from uint64, name string, body []byte) ([]byte, error) {
	value, found := g.calls.Load(name)
	if _, self := g.Leader(); !self {
		return nil, ErrNoLeader
	} else if !found {
		return nil, ErrNoCall
	}
	answer, err := value.(CallHandler)(ctx, from, body)
	if errors.Is(err, ErrNoCall) {
		return nil, ErrNoCall
	}
	if err != nil {
		var fault *model.Fault
		if errors.As(err, &fault) && fault.Code != "" {
			return nil, err
		}
		return nil, model.Fail(model.Unavailable)
	}
	return answer, nil
}

// CallLeader is Group.CallLeader over the mutually authenticated transport.
func (t *MTLS) CallLeader(ctx context.Context, group model.ID, name string, body []byte) ([]byte, error) {
	if name == "" || strings.ContainsAny(name, "/?#") {
		return nil, ErrInvalid
	}
	t.mu.RLock()
	g := t.groups[group]
	t.mu.RUnlock()
	if g == nil {
		return nil, ErrInvalid
	}
	leader, self := g.Leader()
	if self {
		return nil, ErrUnavailable
	}
	if leader == 0 {
		return nil, ErrNoLeader // an election: nothing was sent
	}
	var target Member
	for _, member := range g.transportView.Load().Nodes {
		if member.ID == leader {
			target = member
		}
	}
	if target.ID == 0 || target.ID == t.id {
		return nil, ErrNoLeader // the transport does not know the member this one follows: nothing was sent
	}
	client, err := t.peerClient(target)
	if err != nil {
		return nil, err
	}
	// The leader certainly ran nothing when no connection was made (refused, unreachable, the handshake failed) or the transport failed
	// to write the request; any other failure of Do came after the request may have reached it, whatever the connection does after.
	var connected, writeFailed atomic.Bool
	trace := &httptrace.ClientTrace{
		GotConn:      func(httptrace.GotConnInfo) { connected.Store(true) },
		WroteRequest: func(info httptrace.WroteRequestInfo) { writeFailed.Store(info.Err != nil) },
	}
	request, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), "POST", strings.TrimSuffix(target.Address, "/")+callPath+group.String()+"/"+url.PathEscape(name), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/octet-stream")
	request.Header.Set("X-Soundpost-Raft-Hop", "1")
	response, err := client.Do(request)
	if err != nil {
		if !connected.Load() || writeFailed.Load() {
			return nil, fmt.Errorf("%w: the call: %v", ErrNoLeader, err) // the leader ran nothing
		}
		return nil, fmt.Errorf("%w: the call: %v", ErrCallOutcomeUnknown, err)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, callLimit+1))
	if err == nil && (response.StatusCode == http.StatusNotFound || response.StatusCode == http.StatusBadRequest) {
		return nil, ErrNoCall // a release that knows no call route reads the path as a group it cannot parse
	}
	if err == nil && response.StatusCode == http.StatusServiceUnavailable {
		return nil, fmt.Errorf("%w: the member answered unavailable before it ran the call", ErrNoLeader) // serveCall: not the leader (any more), or no such group
	}
	if err != nil || len(raw) > callLimit || response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: the answer: status %d, %d bytes, %v", ErrCallOutcomeUnknown, response.StatusCode, len(raw), err)
	}
	var result callResult
	if json.Unmarshal(raw, &result) != nil {
		return nil, fmt.Errorf("%w: the answer is not a call result", ErrCallOutcomeUnknown)
	}
	if result.Code != "" {
		fault := model.Fail(result.Code)
		fault.Retryable = result.Retryable
		return nil, fault
	}
	return result.Body, nil
}

// serveCall answers a call made to this member as the leader of a group.
func (t *MTLS) serveCall(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" || r.Header.Get("X-Soundpost-Raft-Hop") != "1" || r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	groupText, name, ok := strings.Cut(strings.TrimPrefix(r.URL.Path, callPath), "/")
	var group model.ID
	if !ok || name == "" || strings.Contains(name, "/") || group.UnmarshalText([]byte(groupText)) != nil {
		http.Error(w, "invalid", http.StatusBadRequest)
		return
	}
	t.mu.RLock()
	g := t.groups[group]
	t.mu.RUnlock()
	if g == nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	identity := certificateIdentity(r.TLS.PeerCertificates[0])
	var from uint64
	for _, member := range g.transportView.Load().Nodes {
		if member.NodeIdentity == identity {
			from = member.ID
		}
	}
	if from == 0 {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	value, found := g.calls.Load(name)
	if !found {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if _, self := g.Leader(); !self {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, callLimit+1))
	if err != nil || len(body) > callLimit {
		http.Error(w, "invalid", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	answer, err := value.(CallHandler)(ctx, from, body)
	w.Header().Set("Content-Type", "application/json")
	if errors.Is(err, ErrNoCall) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if err != nil {
		noteCallError(name, err)
		code, retryable := model.Unavailable, false
		var fault *model.Fault
		if errors.As(err, &fault) && fault.Code != "" {
			code, retryable = fault.Code, fault.Retryable
		}
		_ = json.NewEncoder(w).Encode(callResult{Code: code, Retryable: retryable})
		return
	}
	_ = json.NewEncoder(w).Encode(callResult{Body: answer})
}
