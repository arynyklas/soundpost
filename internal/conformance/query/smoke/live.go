// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package smoke

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query"
	"github.com/arynyklas/soundpost/internal/retention"
)

type liveFile struct {
	Schema  string `json:"schema"`
	Fixture struct {
		Projects []string `json:"projects"`
		Sources  []struct {
			ID       string              `json:"id"`
			Project  string              `json:"project"`
			Kinds    []string            `json:"kinds"`
			Labels   map[string][]string `json:"labels"`
			Template struct {
				ID       string   `json:"id"`
				Revision int      `json:"revision"`
				Line     string   `json:"line"`
				Field    string   `json:"field"`
				Values   []string `json:"values"`
			} `json:"template"`
		} `json:"sources"`
		Principals []struct {
			ID     string              `json:"id"`
			Grants map[string][]string `json:"grants"`
		} `json:"principals"`
	} `json:"fixture"`
	Steps []liveStep `json:"steps"`
}

type liveStep struct {
	ID     string          `json:"id"`
	Route  string          `json:"route"`
	As     string          `json:"as"`
	Body   json.RawMessage `json:"body"`
	Query  map[string]any  `json:"query"`
	Stream bool            `json:"stream"`
	Save   string          `json:"save"`
	Append []struct {
		Source string `json:"source"`
		Field  string `json:"field"`
	} `json:"append"`
	Disconnect string `json:"disconnect_stream"`
	Revoke     string `json:"revoke"`
	Regrant    string `json:"regrant"`
	Reopen     bool   `json:"reopen_stream"`
	Delete     string `json:"delete"`
	ThenConn   *struct {
		Route       string `json:"route"`
		LastEventID string `json:"last_event_id"`
	} `json:"then_connect"`
	Expect       map[string]json.RawMessage `json:"expect"`
	StreamExpect map[string]json.RawMessage `json:"stream_expect"`
}

type sseEvent struct {
	ID    string
	Event string
	Data  liveData
}

type liveData struct {
	Type     string `json:"type"`
	StreamID string `json:"stream_id"`
	Sequence string `json:"sequence"`
	Project  string `json:"project"`
	Reason   string `json:"reason"`
	Entry    *struct {
		Line string `json:"line"`
	} `json:"entry"`
	Gap *struct {
		Reason string `json:"reason"`
		From   string `json:"from_sequence"`
		To     string `json:"to_sequence"`
	} `json:"gap"`
}

// liveConn is one attached SSE stream.
type liveConn struct {
	cancel context.CancelFunc
	events chan sseEvent
	status int
	ended  chan struct{}
}

func (e *Env) openStream(who *Person, ticket, lastEventID string) *liveConn {
	return e.openStreamAt(0, who, ticket, lastEventID)
}

// openStreamAt attaches an SSE stream to the live route of node (0 is the
// primary node).
func (e *Env) openStreamAt(node uint64, who *Person, ticket, lastEventID string) *liveConn {
	ctx, cancel := context.WithCancel(e.ctx)
	base, client := e.endpoint(node)
	req, _ := http.NewRequestWithContext(ctx, "GET", base+"/api/v1/live?ticket="+ticket, nil)
	req.Header.Set("Cookie", "__Host-soundpost="+who.Session.Token)
	req.Header.Set("X-CSRF-Token", who.Session.CSRF)
	req.Header.Set("Origin", base)
	if lastEventID != "" {
		req.Header.Set("Last-Event-ID", lastEventID)
	}
	resp, err := client.Do(req)
	c := &liveConn{cancel: cancel, events: make(chan sseEvent, 64), ended: make(chan struct{})}
	if err != nil {
		cancel()
		c.status = 0
		close(c.events)
		close(c.ended)
		return c
	}
	c.status = resp.StatusCode
	go func() {
		defer close(c.ended)
		defer close(c.events)
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return
		}
		sc := bufio.NewScanner(resp.Body)
		sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
		var cur sseEvent
		for sc.Scan() {
			line := sc.Text()
			switch {
			case line == "":
				if cur.Event != "" {
					c.events <- cur
				}
				cur = sseEvent{}
			case strings.HasPrefix(line, "id: "):
				cur.ID = line[4:]
			case strings.HasPrefix(line, "event: "):
				cur.Event = line[7:]
			case strings.HasPrefix(line, "data: "):
				_ = json.Unmarshal([]byte(line[6:]), &cur.Data)
			}
		}
	}()
	return c
}

func (c *liveConn) next(within time.Duration) (sseEvent, bool) {
	select {
	case ev, ok := <-c.events:
		return ev, ok
	case <-time.After(within):
		return sseEvent{}, false
	}
}

// expectRecords reads the next events and requires exactly these record lines
// (id and line), then silence for a short window.
func (c *liveConn) expectRecords(want []liveWant) {
	for _, w := range want {
		ev, ok := c.next(10 * time.Second)
		checkf(ok, "stream ended or stalled waiting for %v", w)
		checkf(ev.Event == "record" && ev.ID == w.ID && ev.Data.Entry != nil && ev.Data.Entry.Line == w.Line, "got %s id=%s %+v want record id=%s %q", ev.Event, ev.ID, ev.Data, w.ID, w.Line)
	}
}

type liveWant struct{ ID, Line, Project string }

func (c *liveConn) silent(window time.Duration) (sseEvent, bool) {
	return c.next(window)
}

// RunLive executes live-smoke.json against the production live service
// (app.Live) behind the real HTTPS routes.
func RunLive(ctx context.Context, layout Layout, dir, path string) (steps []StepResult, notRun []string, err error) {
	defer recoverFailure(&err)
	var file liveFile
	check(readJSON(path, &file))
	checkf(file.Schema == "soundpost-live-smoke/1", "unknown schema %s", file.Schema)
	env, err := NewEnv(ctx, layout, dir)
	check(err)
	defer env.Close()
	for _, p := range file.Fixture.Projects {
		env.AddProject(p)
	}
	for _, s := range file.Fixture.Sources {
		var values []model.Scalar
		for _, v := range s.Template.Values {
			var sc model.Scalar
			check(json.Unmarshal([]byte(`"`+v+`"`), &sc))
			values = append(values, sc)
		}
		tpl := model.LogTemplate{ID: s.Template.ID, Revision: model.Revision(s.Template.Revision), Line: s.Template.Line, Severity: "info", Fields: []model.TemplateField{{Name: s.Template.Field, Type: "string", MaxBytes: 16, Sensitivity: "metadata", Values: values}}}
		env.AddSource(SourceSpec{Name: s.ID, Project: s.Project, Kinds: []model.Kind{model.Log}, Labels: s.Labels, Logs: &tpl})
	}
	for _, p := range file.Fixture.Principals {
		env.AddPerson(p.ID)
		for project, perms := range p.Grants {
			env.Grant(p.ID, project, true, perms...)
		}
	}
	templates := map[string]struct {
		id, field string
		revision  int
	}{}
	for _, s := range file.Fixture.Sources {
		templates[s.ID] = struct {
			id, field string
			revision  int
		}{s.Template.ID, s.Template.Field, s.Template.Revision}
	}
	appendLine := func(source, name string) {
		s := env.Sources[source]
		tpl := templates[source]
		var v model.Scalar
		check(json.Unmarshal([]byte(`"`+name+`"`), &v))
		env.tick++
		ts := model.UnixNano(env.tick)
		env.Ingest(s, model.Record{ID: model.NewID(), Kind: model.Log, ObservedAt: ts, Resource: s.Resource, Payload: model.Payload{Log: &model.LogRecord{Timestamp: &ts, TemplateID: tpl.id, TemplateRevision: model.Revision(tpl.revision), Fields: map[string]model.Scalar{tpl.field: v}, StreamLabels: model.Labels{{Name: "app", Value: "web"}}, Metadata: map[string]model.Scalar{}}}})
	}
	ticketBody := func(raw json.RawMessage) map[string]any {
		var m map[string]any
		check(json.Unmarshal(raw, &m))
		m["org"] = env.org.String()
		if ps, ok := m["projects"].([]any); ok {
			for i, p := range ps {
				if id, ok := env.Projects[p.(string)]; ok {
					ps[i] = id.String()
				}
			}
		}
		m["feature_set"] = env.Features["logql-loki-3.5.2"]
		return m
	}
	saved := map[string]string{}
	conns := map[string]*liveConn{}
	var current *liveConn
	reader := "reader"
	var lastExpression json.RawMessage
	for _, st := range file.Steps {
		result := StepResult{Name: st.ID}
		func() {
			defer func() {
				switch r := recover().(type) {
				case nil:
				case failure:
					result.Detail = r.err.Error()
				default:
					panic(r)
				}
			}()
			who := env.People[st.As]
			if st.As == "" {
				who = env.People[reader]
			}
			switch {
			case st.Route == "/api/v1/live-tickets":
				body := ticketBody(st.Body)
				if v, ok := body["resume_stream_id"].(string); ok && strings.HasPrefix(v, "$") {
					body["resume_stream_id"] = saved[v[1:]]
				}
				lastExpression = st.Body
				code, out := env.Post(who, st.Route, body)
				want := 200
				if raw, ok := st.Expect["status"]; ok {
					check(json.Unmarshal(raw, &want))
				}
				checkf(code == want, "ticket status %d want %d: %s", code, want, trim(out))
				if code == 200 {
					var t struct {
						Ticket string `json:"ticket"`
					}
					check(json.Unmarshal(out, &t))
					checkf(!strings.Contains(string(out), "{app"), "the ticket response carries the expression")
					if st.Save != "" {
						saved[st.Save] = t.Ticket
					} else {
						saved["_last"] = t.Ticket
					}
					if st.ThenConn != nil {
						current = env.openStream(who, t.Ticket, st.ThenConn.LastEventID)
						checkf(current.status == 200, "reconnect status %d", current.status)
					}
				} else {
					if same, _ := jsonBool(st.Expect, "same_body_as_nonexistent_project"); same {
						ghost := ticketBody(st.Body)
						ghost["projects"] = []string{model.NewID().String()}
						gcode, gout := env.Post(who, st.Route, ghost)
						checkf(gcode == code && stripVolatile(gout) == stripVolatile(out), "foreign project is distinguishable from nonexistent: %d %s vs %d %s", code, trim(out), gcode, trim(gout))
					}
				}
				if st.ThenConn != nil {
					var wantEvents []struct {
						Type    string `json:"type"`
						ID      string `json:"id"`
						Reason  string `json:"reason"`
						From    string `json:"from_sequence"`
						To      string `json:"to_sequence"`
						Line    string `json:"line"`
						Project string `json:"project"`
						SameAs  string `json:"same_stream_id_as"`
					}
					check(json.Unmarshal(st.Expect["events"], &wantEvents))
					for _, w := range wantEvents {
						ev, ok := current.next(10 * time.Second)
						checkf(ok, "stream ended before %s", w.Type)
						checkf(ev.Event == w.Type, "event %s want %s (%+v)", ev.Event, w.Type, ev.Data)
						switch w.Type {
						case "open":
							checkf(ev.Data.StreamID != "" && ev.Data.StreamID == saved[w.SameAs], "resumed stream id %q is not %q", ev.Data.StreamID, saved[w.SameAs])
						case "gap":
							checkf(ev.ID == w.ID && ev.Data.Gap != nil && ev.Data.Gap.Reason == w.Reason && ev.Data.Gap.From == w.From && ev.Data.Gap.To == w.To, "gap %+v id=%s want id=%s %s %s..%s", ev.Data.Gap, ev.ID, w.ID, w.Reason, w.From, w.To)
						case "record":
							checkf(ev.ID == w.ID && ev.Data.Entry != nil && ev.Data.Entry.Line == w.Line && ev.Data.Project == env.Projects[w.Project].String(), "record id=%s %+v want id=%s %q", ev.ID, ev.Data, w.ID, w.Line)
						}
					}
					conns["stream-1"] = current
				}
			case st.Route == "/api/v1/live":
				ticket := fmt.Sprint(st.Query["ticket"])
				ticket = saved[strings.TrimPrefix(ticket, "$")]
				preOpen := false
				if st.Stream {
					if v, ok := jsonBool(st.Expect, "no_record_for_data_committed_before_open"); ok && v {
						// Commit a record before the stream opens; it must never be delivered.
						src := file.Fixture.Sources[0]
						appendLine(src.ID, src.Template.Values[len(src.Template.Values)-1])
						preOpen = true
					}
				}
				c := env.openStream(who, ticket, "")
				if st.Stream {
					checkf(c.status == 200, "open status %d", c.status)
					ev, ok := c.next(10 * time.Second)
					checkf(ok && ev.Event == "open" && ev.Data.StreamID != "" && ev.ID == "", "first event %+v", ev)
					saved[st.Save] = ev.Data.StreamID
					conns[st.Save] = c
					current = c
					if preOpen {
						if late, got := c.silent(500 * time.Millisecond); got {
							checkf(false, "data committed before the stream opened was delivered: %s %+v", late.Event, late.Data)
						}
					}
				} else {
					checkf(c.status == 404, "a copied ticket answered %d, want 404", c.status)
					c.cancel()
					// The sibling lacks the project grant, which alone would refuse it.
					// The same principal in a second session holds every grant, so only
					// the ticket's session binding can refuse this one.
					other := env.openStream(env.SecondSession(reader), ticket, "")
					checkf(other.status == 404, "a ticket copied to another session of the issuing principal answered %d, want 404", other.status)
					other.cancel()
				}
			case len(st.Append) > 0 || st.Revoke != "" || st.Regrant != "" || st.Delete != "":
				if st.Revoke != "" {
					env.Grant(reader, "project-a", false, "telemetry.read")
				}
				if st.Regrant != "" {
					env.Grant(reader, "project-a", true, "telemetry.read")
				}
				if st.Reopen {
					raw := lastExpression
					body := ticketBody(raw)
					delete(body, "resume_stream_id")
					code, out := env.Post(env.People[reader], "/api/v1/live-tickets", body)
					checkf(code == 200, "reopen ticket %d %s", code, trim(out))
					var t struct {
						Ticket string `json:"ticket"`
					}
					check(json.Unmarshal(out, &t))
					current = env.openStream(env.People[reader], t.Ticket, "")
					ev, ok := current.next(10 * time.Second)
					checkf(ok && ev.Event == "open", "reopened stream did not open: %+v", ev)
				}
				if st.Delete != "" {
					admin, err := env.app.Auth.Authorize(ctx, env.owner.Cred, env.org, []model.ID{env.Projects["project-a"]}, "org.admin")
					check(err)
					var rev model.Revision
					check(env.app.Control.View(ctx, func(s model.ControlState) error { rev = s.Revision; return nil }))
					_, err = env.app.Retention.Delete(ctx, admin, retention.DeleteRequest{CommandID: model.NewID(), ExpectedRevision: rev, Mode: model.DeleteHistoricalRange, OrgID: env.org, ProjectIDs: []model.ID{env.Projects["project-a"]}, Signals: []model.Kind{model.Log}, Start: 0, End: model.UnixNano(env.tick), Reason: "live smoke deletion"})
					check(err)
				}
				for _, a := range st.Append {
					appendLine(a.Source, a.Field)
				}
				if st.StreamExpect == nil {
					result.Passed = true
					return
				}
				checkf(current != nil, "no stream is attached (an earlier step failed)")
				if raw, ok := st.StreamExpect["records"]; ok {
					var want []struct {
						ID      string `json:"id"`
						Project string `json:"project"`
						Line    string `json:"line"`
					}
					check(json.Unmarshal(raw, &want))
					var ws []liveWant
					for _, w := range want {
						ws = append(ws, liveWant{w.ID, w.Line, w.Project})
					}
					current.expectRecords(ws)
					if lines, ok := jsonStrings(st.StreamExpect, "never_delivered_lines"); ok {
						ev, got := current.silent(500 * time.Millisecond)
						if got {
							for _, l := range lines {
								checkf(ev.Data.Entry == nil || ev.Data.Entry.Line != l, "line %q from another project was delivered", l)
							}
						}
					}
				}
				if raw, ok := st.StreamExpect["terminal"]; ok {
					var term struct {
						Type   string `json:"type"`
						Reason string `json:"reason"`
					}
					check(json.Unmarshal(raw, &term))
					for {
						ev, ok := current.next(10 * time.Second)
						checkf(ok, "the stream ended without a terminal %s event", term.Type)
						checkf(ev.Event != "record", "a record %q followed the revocation/deletion", fmt.Sprint(ev.Data.Entry))
						if ev.Event == "heartbeat" {
							continue
						}
						checkf(ev.Event == term.Type && ev.Data.Reason == term.Reason, "terminal %s/%s want %s/%s", ev.Event, ev.Data.Reason, term.Type, term.Reason)
						break
					}
					select {
					case <-current.ended:
					case <-time.After(10 * time.Second):
						checkf(false, "the stream body did not end after the terminal event")
					}
				}
			case st.Disconnect == "" && len(st.Append) == 0 && st.Route == "":
				// Only counter expectations: every attachment is closed, then every
				// live-service and storage counter must drain to zero.
				for _, c := range conns {
					c.cancel()
					<-c.ended
				}
				if current != nil {
					current.cancel()
					<-current.ended
				}
				var u query.LiveUsage
				var iterators uint64
				deadline := time.Now().Add(10 * time.Second)
				for {
					u, iterators = env.app.Live.Usage(), env.app.Storage.Stats().ActiveIterators
					if u.OpenIterators == 0 && u.MemoryUsed == 0 && u.Streams == 0 && u.Goroutines == 0 && iterators == 0 && env.gate.openCount() == 0 {
						break
					}
					checkf(time.Now().Before(deadline), "teardown did not release everything: live %+v, storage iterators %d, gate %d", u, iterators, env.gate.openCount())
					time.Sleep(50 * time.Millisecond)
				}
				result.Detail = fmt.Sprintf("open_iterators=%d open_subscriptions=%d accounted_memory_bytes=%d live_streams=%d goroutines_owned_by_live_service=%d", iterators, u.OpenIterators, u.MemoryUsed, u.Streams, u.Goroutines)
			case st.Disconnect != "":
				c := conns[st.Disconnect]
				checkf(c != nil, "unknown stream %s", st.Disconnect)
				c.cancel()
				<-c.ended
			}
			for _, expect := range []map[string]json.RawMessage{st.Expect, st.StreamExpect} {
				if n, ok := jsonInt(expect, "feed_subscriptions_opened"); ok {
					u := env.app.Live.Usage()
					checkf(u.OpenIterators == n, "feed subscriptions open: %d, want %d (streams %d)", u.OpenIterators, n, u.Streams)
				}
				if n, ok := jsonInt(expect, "steady_state_scan_polls"); ok {
					before := env.app.Storage.Stats()
					time.Sleep(1500 * time.Millisecond)
					after := env.app.Storage.Stats()
					polls := int64(after.IndexLookups-before.IndexLookups) + int64(after.PagesRead-before.PagesRead)
					checkf(polls == n, "scan polls in a 1.5 s steady state: %d, want %d", polls, n)
				}
				if n, ok := jsonInt(expect, "stream_retained_for_replay_seconds"); ok {
					checkf(query.DefaultLiveLimits().ReplayWindow == time.Duration(n)*time.Second, "the replay window is %v, want %ds", query.DefaultLiveLimits().ReplayWindow, n)
					time.Sleep(2 * time.Second)
					checkf(env.app.Live.Usage().Streams == 1, "the stream is not retained after the disconnect: %+v", env.app.Live.Usage())
				}
			}
			result.Passed = true
		}()
		steps = append(steps, result)
	}
	for _, c := range conns {
		c.cancel()
	}
	return steps, nil, nil
}

func jsonInt(m map[string]json.RawMessage, key string) (int64, bool) {
	raw, ok := m[key]
	if !ok {
		return 0, false
	}
	var v int64
	check(json.Unmarshal(raw, &v))
	return v, true
}

func jsonBool(m map[string]json.RawMessage, key string) (bool, bool) {
	raw, ok := m[key]
	if !ok {
		return false, false
	}
	var v bool
	check(json.Unmarshal(raw, &v))
	return v, true
}

func jsonStrings(m map[string]json.RawMessage, key string) ([]string, bool) {
	raw, ok := m[key]
	if !ok {
		return nil, false
	}
	var v []string
	check(json.Unmarshal(raw, &v))
	return v, true
}

var _ = bytes.NewReader
