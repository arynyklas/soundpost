// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package incidents_test

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/incidents"
	"github.com/arynyklas/soundpost/internal/model"
)

// The control group refuses an incident state above this size (control.maxIncidentStateBytes).
const controlStateLimit = 256 << 10

func detail(err error) string {
	if f, ok := err.(*model.Fault); ok {
		return f.SafeDetail
	}
	return ""
}

func (r *run) title(text string) incidents.Action {
	a := r.cmd(incidents.TypeTitle, incidents.OriginHuman, alice)
	a.Title = text
	return a
}

func (r *run) note(text string) incidents.Action {
	a := r.cmd(incidents.TypeNote, incidents.OriginHuman, alice)
	a.Note = text
	return a
}

func (r *run) external(typ incidents.Type, op model.ExternalOp) incidents.Action {
	a := r.cmd(typ, incidents.OriginHuman, alice)
	a.External = &op
	return a
}

// refused asserts the action is refused with the typed fault and that nothing was produced.
func (r *run) refused(a incidents.Action, want model.Code, wantDetail string) {
	r.t.Helper()
	_, effects, err := incidents.Apply(r.state, a, r.at+sec)
	if code(err) != want || detail(err) != wantDetail || len(effects) != 0 {
		r.t.Fatalf("%s: got %v (%v), want %s/%s", a.Type, err, effects, want, wantDetail)
	}
}

func onlyAudit(t *testing.T, effects []incidents.Effect, typ incidents.Type) {
	t.Helper()
	if len(effects) != 1 || effects[0].Kind != incidents.EffectAudit || effects[0].Action != typ {
		t.Fatalf("effects %+v, want one audit of %s", effects, typ)
	}
}

const trackerIssue = "https://git.example.test/shop/web/-/issues/3"

func linkedEnd(marker string) model.ExternalOp {
	return model.ExternalOp{Provider: "gitlab", Kind: model.ExternalEnd, Marker: marker, Project: "shop/web", Result: model.ExternalLinked, IID: 3, URL: trackerIssue}
}

func TestIncidentTitle(t *testing.T) {
	r := newRun(t)
	r.open(incidents.SeverityMajor)
	if r.state.Title != "" {
		t.Fatalf("a never-named incident has the title %q", r.state.Title)
	}
	onlyAudit(t, r.do(r.title("Checkout latency spike")), incidents.TypeTitle)
	if r.state.Title != "Checkout latency spike" || r.state.Version != 2 || r.state.Status != incidents.StatusOpen {
		t.Fatalf("state %+v", r.state)
	}
	if e := r.state.Timeline[1]; e.Action.Type != incidents.TypeTitle || e.Action.Title != "Checkout latency spike" || e.Action.Actor != alice || e.At != r.at {
		t.Fatalf("entry %+v", e)
	}
	// Renaming replaces the title; the history keeps the earlier one.
	r.do(r.title("Checkout errors"))
	if r.state.Title != "Checkout errors" || r.state.Timeline[1].Action.Title != "Checkout latency spike" {
		t.Fatalf("rename %+v", r.state)
	}
	r.refused(r.title("Checkout errors"), model.Conflict, "incident_title_unchanged")

	// It is metadata: allowed after the incident was resolved, and it changes nothing else.
	r.human(incidents.TypeResolve, "fixed")
	before := r.state
	r.do(r.title("Checkout errors (post-mortem)"))
	after := r.state
	if after.Title != "Checkout errors (post-mortem)" || after.Status != incidents.StatusResolved {
		t.Fatalf("title after resolve: %+v", after)
	}
	after.Title, before.Title = "", ""
	after.Version, before.Version = 0, 0
	after.Timeline, before.Timeline = nil, nil
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("a title changed more than the title:\n%+v\n%+v", before, after)
	}
}

func TestIncidentTitleValidation(t *testing.T) {
	r := newRun(t)
	r.open(incidents.SeverityMinor)
	for i, title := range []string{"a", strings.Repeat("a", incidents.MaxTitleBytes), strings.Repeat("é", incidents.MaxTitleBytes/2), strings.Repeat("日", 53), "inner  spaces stay", "<b>markup</b> & \"quotes\""} {
		if next, _, err := incidents.Apply(r.state, r.title(title), r.at+sec); err != nil || next.Title != title {
			t.Fatalf("valid title %d (%d bytes): %v", i, len(title), err)
		}
	}
	for name, title := range map[string]string{
		"empty":            "",
		"too long":         strings.Repeat("a", incidents.MaxTitleBytes+1),
		"too long, runes":  strings.Repeat("日", 54), // 162 bytes
		"leading space":    " a",
		"trailing space":   "a ",
		"trailing newline": "a\n",
		"newline":          "a\nb",
		"tab":              "a\tb",
		"carriage return":  "a\rb",
		"nul":              "a\x00b",
		"escape":           "a\x1bb",
		"c1 control":       "a\u0085b",
		"del":              "a\x7fb",
		"invalid utf-8":    "a\xffb",
		"truncated utf-8":  "a\xe6\x97",
		"only whitespace":  " \u00a0 ",
	} {
		a := r.title(title)
		if _, _, err := incidents.Apply(r.state, a, r.at+sec); code(err) != model.Invalid || detail(err) != "incident_title_invalid" {
			t.Fatalf("%s: %v", name, err)
		}
	}
	// The reducer never trims (Service.Act does, before it validates): what it stores is exactly what was validated.
	a := r.title("a")
	a.Reason = "why"
	r.refused(a, model.Invalid, "incident_reason_invalid")

	// The fields belong to their type.
	ack := r.cmd(incidents.TypeAck, incidents.OriginHuman, alice)
	ack.Title = "x"
	r.refused(ack, model.Invalid, "incident_action_fields")
	ack = r.cmd(incidents.TypeAck, incidents.OriginHuman, alice)
	ack.Note = "x"
	r.refused(ack, model.Invalid, "incident_action_fields")
	both := r.title("x")
	both.Note = "x"
	r.refused(both, model.Invalid, "incident_action_fields")
	// A title is a human decision.
	sys := r.title("x")
	sys.Origin, sys.Actor = incidents.OriginSystem, bot
	r.refused(sys, model.Forbidden, "incident_origin_forbidden")
	// And it is not a first action: there is no incident to name yet.
	empty := newRun(t)
	empty.refused(empty.title("x"), model.NotFound, "not_found")
}

func TestIncidentNote(t *testing.T) {
	r := newRun(t)
	r.open(incidents.SeverityMajor)
	r.human(incidents.TypeAck, "")
	text := "Rolled back the 14:02 deploy.\nWatching error rate; next check at 15:00 <ok> & \"quoted\""
	before := r.state
	effects := r.do(r.note(text))
	onlyAudit(t, effects, incidents.TypeNote)
	raw, _ := json.Marshal(effects)
	if strings.Contains(string(raw), "Rolled") || strings.Contains(string(raw), "deploy") {
		t.Fatalf("an effect carries the note text: %s", raw)
	}
	s := r.state
	if s.Version != before.Version+1 || len(s.Timeline) != len(before.Timeline)+1 {
		t.Fatalf("a note is one timeline entry: %+v", s)
	}
	if e := s.Timeline[len(s.Timeline)-1]; e.Action.Type != incidents.TypeNote || e.Action.Note != text || e.Action.Actor != alice || e.At != r.at {
		t.Fatalf("entry %+v", e)
	}
	// It changes nothing else: not the ack, the owner, the status or the title.
	s.Version, before.Version = 0, 0
	s.Timeline, before.Timeline = nil, nil
	if !reflect.DeepEqual(s, before) {
		t.Fatalf("a note changed state:\n%+v\n%+v", s, before)
	}

	// Allowed after the incident was resolved, and it never reopens it.
	r.human(incidents.TypeResolve, "done")
	r.do(r.note("post-incident: the alert threshold was too tight"))
	if r.state.Status != incidents.StatusResolved || r.state.Timeline[len(r.state.Timeline)-1].Action.Type != incidents.TypeNote {
		t.Fatalf("note after resolve: %+v", r.state)
	}
	// There is no edit or delete: the same command with other text is a reuse conflict, the same text a no-op retry.
	n := r.note("x")
	r.do(n)
	retried, effects, err := incidents.Apply(r.state, n, r.at+sec)
	if err != nil || len(effects) != 0 || len(retried.Timeline) != len(r.state.Timeline) {
		t.Fatalf("retry: %v %+v", err, effects)
	}
	n.Note = "y"
	r.refused(n, model.Conflict, "incident_command_reused")
}

func TestIncidentNoteValidation(t *testing.T) {
	r := newRun(t)
	r.open(incidents.SeverityMinor)
	for name, text := range map[string]string{
		"one char":       "a",
		"multi-line":     "a\nb\n\nc",
		"max":            strings.Repeat("a", incidents.MaxNoteBytes),
		"unicode":        "日本語 — тест ✓",
		"leading blanks": "  indented\n    code",
	} {
		if _, _, err := incidents.Apply(r.state, r.note(text), r.at+sec); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	for name, text := range map[string]string{
		"empty":         "",
		"only blanks":   "  \n \n",
		"too long":      strings.Repeat("a", incidents.MaxNoteBytes+1),
		"tab":           "a\tb",
		"carriage":      "a\r\nb",
		"nul":           "a\x00b",
		"escape":        "\x1b[31mred",
		"c1":            "a\u0085b",
		"invalid utf-8": "a\xffb",
		"del":           "a\x7fb",
		"form feed":     "a\fb",
		"vertical tab":  "a\vb",
	} {
		if _, _, err := incidents.Apply(r.state, r.note(text), r.at+sec); code(err) != model.Invalid || detail(err) != "incident_note_invalid" {
			t.Fatalf("%s: %v", name, err)
		}
	}
	a := r.note("a")
	a.Reason = "why"
	r.refused(a, model.Invalid, "incident_reason_invalid")
	sys := r.note("a")
	sys.Origin, sys.Actor = incidents.OriginSystem, bot
	r.refused(sys, model.Forbidden, "incident_origin_forbidden")
	// Only its own type carries a note.
	link := r.cmd(incidents.TypeLink, incidents.OriginSystem, bot)
	link.Link = &incidents.Link{Kind: incidents.LinkService, ID: model.ID{0x71}}
	link.Note = "x"
	r.refused(link, model.Invalid, "incident_action_fields")
}

// Notes (and titles and external links) leave TimelineReserve entries free, so an
// incident can always be acknowledged and resolved however many notes it holds.
func TestIncidentNotesLeaveRoomToAcknowledgeAndResolve(t *testing.T) {
	r := newRun(t)
	r.open(incidents.SeverityMajor)
	for len(r.state.Timeline) < incidents.MaxTimeline-incidents.TimelineReserve {
		r.do(r.note("n"))
	}
	r.refused(r.note("one too many"), model.Quota, "incident_notes_full")
	r.refused(r.title("a title"), model.Quota, "incident_timeline_full")
	r.refused(r.external(incidents.TypeExternalBegin, model.ExternalOp{Provider: "gitlab", Kind: model.ExternalBegin, Marker: "soundpost-ref-aa", Project: "g/p", Until: r.at + 2*sec}), model.Quota, "incident_timeline_full")

	r.human(incidents.TypeAck, "")
	r.human(incidents.TypeResolve, "done")
	if r.state.Status != incidents.StatusResolved || len(r.state.Timeline) != incidents.MaxTimeline-incidents.TimelineReserve+2 {
		t.Fatalf("not resolved in time: %v, %d entries", r.state.Status, len(r.state.Timeline))
	}
	// The reserve is not for notes after resolution either.
	r.refused(r.note("late"), model.Quota, "incident_notes_full")
}

// The total note text is bounded by its JSON size (the control group refuses a state above
// 256 KiB), so notes made of characters the encoder expands cannot crowd out the rest.
func TestIncidentNoteTotalIsBoundedByItsJSONSize(t *testing.T) {
	for name, tc := range map[string]struct {
		note string
		size int // JSON bytes of one note
	}{
		"ascii":          {strings.Repeat("a", incidents.MaxNoteBytes), 2000},
		"quote":          {strings.Repeat("\"", incidents.MaxNoteBytes), 4000},
		"html":           {strings.Repeat("<", incidents.MaxNoteBytes), 12000},
		"ampersand":      {strings.Repeat("&", incidents.MaxNoteBytes), 12000},
		"newline":        {strings.Repeat("a\n", incidents.MaxNoteBytes/2), 3000},
		"line separator": {strings.Repeat("a\u2028", 500), 3500},
		"cjk":            {strings.Repeat("日", 666), 1998},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRun(t)
			r.open(incidents.SeverityMinor)
			fits := incidents.MaxNoteTotal / tc.size
			for range fits {
				r.do(r.note(tc.note))
			}
			r.refused(r.note(tc.note), model.Quota, "incident_notes_full")
			if raw, _ := json.Marshal(r.state); len(raw) >= controlStateLimit {
				t.Fatalf("%d bytes of state with the note budget full", len(raw))
			}
		})
	}
}

// The worst case of the whole state, with every free-text member as large as it may be and
// escape-heavy: acknowledge and resolve (with the longest reason) still fit in the control limit.
func TestIncidentStateStaysUnderTheControlLimitWithNotesAndTitles(t *testing.T) {
	r := newRun(t)
	r.open(incidents.SeverityMajor)
	heavy := strings.Repeat("<", incidents.MaxNoteBytes)
	for {
		a := r.note(heavy)
		if _, _, err := incidents.Apply(r.state, a, r.at+sec); err != nil {
			break
		}
		r.do(a)
	}
	for i := 0; len(r.state.Timeline) < incidents.MaxTimeline-incidents.TimelineReserve; i++ {
		r.do(r.title(strings.Repeat("<", incidents.MaxTitleBytes-1) + string(rune('a'+i%2))))
	}
	r.human(incidents.TypeAck, "")
	r.human(incidents.TypeResolve, strings.Repeat("<", incidents.MaxReasonBytes))
	raw, err := json.Marshal(r.state)
	if err != nil || len(raw) >= controlStateLimit {
		t.Fatalf("worst-case state is %d bytes (limit %d): %v", len(raw), controlStateLimit, err)
	}
	t.Logf("worst-case state: %d of %d bytes in %d entries", len(raw), controlStateLimit, len(r.state.Timeline))
}

func TestIncidentExternalLinkLifecycle(t *testing.T) {
	r := newRun(t)
	r.open(incidents.SeverityMajor)
	marker := model.ExternalMarker(org, "incident", inc)
	begin := model.ExternalOp{Provider: "gitlab", Kind: model.ExternalBegin, Marker: marker, Project: "shop/web", Until: r.at + 60*sec}
	onlyAudit(t, r.do(r.external(incidents.TypeExternalBegin, begin)), incidents.TypeExternalBegin)
	if len(r.state.External) != 1 || r.state.External[0].State != model.ExternalCreating || r.state.External[0].Actor != alice || r.state.External[0].At != r.at {
		t.Fatalf("begin: %+v", r.state.External)
	}
	// A second begin while the lease is held is a typed refusal, not a second creation.
	r.refused(r.external(incidents.TypeExternalBegin, begin), model.Conflict, "external_in_progress")
	adopt := linkedEnd(marker)
	adopt.Kind = model.ExternalAdopt
	r.refused(r.external(incidents.TypeExternalAdopt, adopt), model.Conflict, "external_in_progress")

	onlyAudit(t, r.do(r.external(incidents.TypeExternalEnd, linkedEnd(marker))), incidents.TypeExternalEnd)
	got := r.state.External[0]
	if got.State != model.ExternalLinked || got.IID != 3 || got.URL != trackerIssue || got.Marker != marker {
		t.Fatalf("end: %+v", got)
	}
	// Linked is terminal, also for an adopt.
	r.refused(r.external(incidents.TypeExternalAdopt, adopt), model.Conflict, "external_already_linked")

	// The link is an action on its own: it works after the incident was resolved.
	r.human(incidents.TypeResolve, "done")
	other := model.ExternalOp{Provider: "other", Kind: model.ExternalAdopt, Marker: marker, Project: "a/b", Result: model.ExternalLinked, IID: 9, URL: "https://tracker.example.test/a/b/9"}
	r.do(r.external(incidents.TypeExternalAdopt, other))
	if len(r.state.External) != 2 || r.state.Status != incidents.StatusResolved {
		t.Fatalf("after resolve: %+v", r.state)
	}
	replayed, err := incidents.Replay(r.state.Timeline)
	if err != nil || !reflect.DeepEqual(replayed, r.state) {
		t.Fatalf("not the replay of its timeline: %v\n%+v\n%+v", err, replayed, r.state)
	}
}

func TestIncidentExternalTakeoverIsADeterministicReplay(t *testing.T) {
	r := newRun(t)
	r.open(incidents.SeverityMajor)
	marker := model.ExternalMarker(org, "incident", inc)
	begin := func(until model.UnixNano) model.ExternalOp {
		return model.ExternalOp{Provider: "gitlab", Kind: model.ExternalBegin, Marker: marker, Project: "shop/web", Until: until}
	}
	first := r.external(incidents.TypeExternalBegin, begin(r.at+3*sec))
	r.do(first)
	// The lease runs out (the clock the reducer is given moves past Until): a later begin takes it over.
	r.at += 10 * sec
	until := r.at + 30*sec
	r.do(r.external(incidents.TypeExternalBegin, begin(until)))
	if got := r.state.External[0]; got.State != model.ExternalCreating || got.Until != until {
		t.Fatalf("takeover: %+v", got)
	}
	// A retry of the first begin long after its lease ran out is the original result, not "invalid".
	if got, effects, err := incidents.Apply(r.state, first, r.at+3600*sec); err != nil || len(effects) != 0 || got.Version != 2 {
		t.Fatalf("a late retry of a committed begin: %v %+v", err, got.Version)
	}
	replayed, err := incidents.Replay(r.state.Timeline)
	if err != nil || !reflect.DeepEqual(replayed, r.state) {
		t.Fatalf("a takeover does not replay: %v", err)
	}
	for v := model.Revision(1); v <= r.state.Version; v++ {
		if past, err := r.state.At(v); err != nil || past.Version != v {
			t.Fatalf("At(%d): %v", v, err)
		}
	}
}

func TestIncidentExternalValidation(t *testing.T) {
	r := newRun(t)
	r.open(incidents.SeverityMajor)
	marker := model.ExternalMarker(org, "incident", inc)
	ok := model.ExternalOp{Provider: "gitlab", Kind: model.ExternalBegin, Marker: marker, Project: "shop/web", Until: r.at + 30*sec}

	// The type and the operation's own kind must agree: no begin smuggled in as an end.
	r.refused(r.external(incidents.TypeExternalEnd, ok), model.Invalid, "external_invalid")
	adopt := ok
	adopt.Kind = model.ExternalAdopt
	r.refused(r.external(incidents.TypeExternalBegin, adopt), model.Invalid, "external_invalid")
	// A lease in the past or beyond the cap (judged when the action is applied), an http URL: the shared validation.
	past := ok
	past.Until = r.at
	r.refused(r.external(incidents.TypeExternalBegin, past), model.Invalid, "external_invalid")
	long := ok
	long.Until = r.at + model.ExternalMaxLease + sec*2
	r.refused(r.external(incidents.TypeExternalBegin, long), model.Invalid, "external_invalid")
	insecure := linkedEnd(marker)
	insecure.URL = "http://git.example.test/shop/web/-/issues/3"
	r.refused(r.external(incidents.TypeExternalEnd, insecure), model.Invalid, "external_invalid")
	// The operation is required for its types and refused for the others.
	none := r.cmd(incidents.TypeExternalBegin, incidents.OriginHuman, alice)
	r.refused(none, model.Invalid, "incident_action_fields")
	ack := r.cmd(incidents.TypeAck, incidents.OriginHuman, alice)
	ack.External = &ok
	r.refused(ack, model.Invalid, "incident_action_fields")
	// Human only, no reason.
	sys := r.external(incidents.TypeExternalBegin, ok)
	sys.Origin, sys.Actor = incidents.OriginSystem, bot
	r.refused(sys, model.Forbidden, "incident_origin_forbidden")
	withReason := r.external(incidents.TypeExternalBegin, ok)
	withReason.Reason = "why"
	r.refused(withReason, model.Invalid, "incident_reason_invalid")
	// The end of a lease that was never begun.
	end := model.ExternalOp{Provider: "gitlab", Kind: model.ExternalEnd, Marker: marker, Project: "shop/web", Result: model.ExternalUnknown, Code: "gitlab_timeout"}
	r.refused(r.external(incidents.TypeExternalEnd, end), model.Conflict, "external_not_creating")
}

// A refused action leaves the incident exactly as it was (no half-applied entry).
func TestIncidentEntityActionsRefusedLeaveTheStateUntouched(t *testing.T) {
	r := newRun(t)
	r.open(incidents.SeverityMajor)
	r.do(r.title("kept"))
	before, _ := json.Marshal(r.state)
	for _, a := range []incidents.Action{r.title("kept"), r.title(""), r.note(""), r.note(strings.Repeat("x", incidents.MaxNoteBytes+1))} {
		if _, _, err := incidents.Apply(r.state, a, r.at+sec); err == nil {
			t.Fatalf("%s %q accepted", a.Type, a.Title+a.Note)
		}
	}
	after, _ := json.Marshal(r.state)
	if string(before) != string(after) {
		t.Fatal("a refused action changed the state")
	}
}
