// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/symbolicate"
)

// framesSensMaxText is the documented bound of one frame text field (maxFrameText).
const framesSensMaxText = 512

// framesSensEnv is one org and project with an artifact reader and a
// telemetry-only reader, and the frames resolver double behind the route.
type framesSensEnv struct {
	e        *evEnv
	resolver *fakeResolver
	org, p   model.ID
	artifact person // artifacts.read
	reader   person // telemetry read only
}

func newFramesSensEnv(t *testing.T) *framesSensEnv {
	t.Helper()
	resolver := &fakeResolver{answer: mapFrames}
	e := newEvEnv(t, resolver, nil, true)
	p := model.NewID()
	org := e.org("evidence frames sensitivity", p)
	artifact := e.user(org, "frames-sens-artifact@example.test")
	e.grant(org, artifact, p, true, auth.ArtifactRead)
	reader := e.user(org, "frames-sens-reader@example.test")
	e.grant(org, reader, p, true, auth.Read)
	return &framesSensEnv{e: e, resolver: resolver, org: org, p: p, artifact: artifact, reader: reader}
}

func (s *framesSensEnv) post(who person, body map[string]any) (int, []byte) {
	s.e.t.Helper()
	return s.e.post(who, "/api/v1/evidence/frames", body, nil)
}

// framesSensFault decodes a typed refusal body.
func framesSensFault(t *testing.T, raw []byte) (code, detail string) {
	t.Helper()
	var f struct {
		Code   string `json:"code"`
		Detail string `json:"detail"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("not a typed fault: %v\n%s", err, raw)
	}
	return f.Code, f.Detail
}

func TestEvidenceSensFramesTextIsBoundedPlainText(t *testing.T) {
	s := newFramesSensEnv(t)
	build := model.NewID()
	for _, key := range []string{"module_id", "function", "artifact_id"} {
		with := func(text string) map[string]any {
			f := frame(10, "boom")
			f[key] = text
			return framesBody(s.org, s.p, build, false, f)
		}
		if status, raw := s.post(s.artifact, with(strings.Repeat("a", framesSensMaxText))); status != 200 {
			t.Fatalf("%s of exactly the bound is accepted: %d %s", key, status, raw)
		}
		for name, text := range map[string]string{
			"over the bound": strings.Repeat("a", framesSensMaxText+1),
			"control char":   "ab\x01cd",
			"nul":            "ab\x00cd",
			"newline":        "ab\ncd",
		} {
			before := s.resolver.calls.Load()
			status, raw := s.post(s.artifact, with(text))
			code, detail := framesSensFault(t, raw)
			if status != 400 || code != string(model.Invalid) || detail != "evidence_frame_invalid" || s.resolver.calls.Load() != before {
				t.Fatalf("%s %s: %d %s (resolver calls %d -> %d)", key, name, status, raw, before, s.resolver.calls.Load())
			}
		}
	}
}

// The wire form of JSON cannot carry invalid UTF-8 (the decoder substitutes it), so
// the handler is called directly: bytes that are not UTF-8 are refused.
func TestEvidenceSensFramesInvalidUTF8IsRefused(t *testing.T) {
	s := newFramesSensEnv(t)
	ev := httpapi.NewEvidence(s.resolver, nil, nil)
	for _, field := range []string{"module", "function", "artifact"} {
		f := model.Frame{Module: "app", Function: "boom", Artifact: "a", Line: 10}
		switch field {
		case "module":
			f.Module = "bad\xff"
		case "function":
			f.Function = "bad\xff"
		default:
			f.Artifact = "bad\xff"
		}
		before := s.resolver.calls.Load()
		_, _, err := ev.Frames(s.e.ctx, s.e.app.Auth, s.artifact.Cred, httpapi.FramesBody{Org: s.org, Project: s.p, Build: model.NewID(), Frames: []model.Frame{f}})
		if faultCode(err) != model.Invalid || s.resolver.calls.Load() != before {
			t.Fatalf("invalid UTF-8 in %s: %v (resolver calls %d -> %d)", field, err, before, s.resolver.calls.Load())
		}
	}
}

func TestEvidenceSensFramesRefusalDoesNotEchoFrameText(t *testing.T) {
	s := newFramesSensEnv(t)
	f := frame(10, "ECHO-CANARY\x01tail")
	status, raw := s.post(s.artifact, framesBody(s.org, s.p, model.NewID(), false, f))
	code, detail := framesSensFault(t, raw)
	if status != 400 || code != string(model.Invalid) || detail != "evidence_frame_invalid" || strings.Contains(string(raw), "ECHO-CANARY") {
		t.Fatalf("a refused frame must answer the fixed typed fault, never its own text: %d %s", status, raw)
	}
}

func TestEvidenceSensFramesRequestNeedsOrgProjectAndBuild(t *testing.T) {
	s := newFramesSensEnv(t)
	zero := model.ID{}
	ev := httpapi.NewEvidence(s.resolver, nil, nil)
	frames := []model.Frame{{Module: "app", Function: "boom", Artifact: "a", Line: 10}}
	for name, body := range map[string]httpapi.FramesBody{
		"org":     {Org: zero, Project: s.p, Build: model.NewID(), Frames: frames},
		"project": {Org: s.org, Project: zero, Build: model.NewID(), Frames: frames},
		"build":   {Org: s.org, Project: s.p, Build: zero, Frames: frames},
	} {
		before := s.resolver.calls.Load()
		// Over the route the request is refused whichever layer sees it first.
		wire := framesBody(body.Org, body.Project, body.Build, false, frame(10, "boom"))
		status, raw := s.post(s.artifact, wire)
		if code, _ := framesSensFault(t, raw); status != 400 || code != string(model.Invalid) {
			t.Fatalf("zero %s over the route: %d %s", name, status, raw)
		}
		// The handler itself refuses it as invalid, before any authorization answer (a zero org or project would be not-found).
		_, _, err := ev.Frames(s.e.ctx, s.e.app.Auth, s.artifact.Cred, body)
		var f *model.Fault
		if !errors.As(err, &f) || f.Code != model.Invalid || f.SafeDetail != "evidence_request_invalid" || s.resolver.calls.Load() != before {
			t.Fatalf("zero %s: %v (resolver calls %d -> %d)", name, err, before, s.resolver.calls.Load())
		}
	}
}

// A telemetry-only reader sees her sanitized frames with an explicit reason, an
// incomplete view and a not_available symbolication section; nothing mapped.
func TestEvidenceSensFramesTelemetryReaderGetsOriginalsWithAnExplicitGrantReason(t *testing.T) {
	s := newFramesSensEnv(t)
	build := model.NewID()
	for _, sources := range []bool{false, true} {
		before := s.resolver.calls.Load()
		status, raw := s.post(s.reader, framesBody(s.org, s.p, build, sources, frame(10, "boom"), frame(11, "other")))
		v := decodeFrames(t, raw)
		if status != 200 || v.State != httpapi.StateIncomplete || v.Reason != httpapi.ReasonArtifactGrantAbsent || s.resolver.calls.Load() != before || strings.Contains(string(raw), secretSource) {
			t.Fatalf("sources=%v view: %d %s", sources, status, raw)
		}
		if len(v.Sections) != 1 || v.Sections[0].Name != "symbolication" || v.Sections[0].State != httpapi.StateNotAvailable || v.Sections[0].Reason != httpapi.ReasonArtifactGrantAbsent {
			t.Fatalf("sources=%v the symbolication section must be not_available for the grant: %s", sources, raw)
		}
		if len(v.Frames) != 2 || v.Frames[0].Original.Function != "boom" || v.Frames[1].Original.Function != "other" {
			t.Fatalf("sources=%v originals: %s", sources, raw)
		}
		for i, fe := range v.Frames {
			wantState, wantReason := "withheld", httpapi.ReasonSourcesNotRequested
			if sources {
				wantReason = httpapi.ReasonSourcesGrantRequired
			}
			if fe.Reason != httpapi.ReasonArtifactGrantAbsent || fe.Resolved != nil || fe.MapSHA256 != nil || fe.Source.State != wantState || fe.Source.Reason != wantReason || fe.Source.Context != nil {
				t.Fatalf("sources=%v frame %d: %s", sources, i, raw)
			}
		}
	}
}

// A frame is mapped only when the resolver says it is resolved: a position the
// resolver attaches to any other reason is not shown, and the view is not ready.
func TestEvidenceSensFramesResolvedIdentityRequiresTheResolvedReason(t *testing.T) {
	s := newFramesSensEnv(t)
	s.resolver.answer = func(frames []model.Frame, o symbolicate.Options) ([]symbolicate.SymbolicatedFrame, error) {
		out, _ := mapFrames(frames, o)
		for i := range out {
			out[i].Reason = symbolicate.IdentityMismatch
		}
		return out, nil
	}
	status, raw := s.post(s.artifact, framesBody(s.org, s.p, model.NewID(), true, frame(10, "boom")))
	v := decodeFrames(t, raw)
	if status != 200 || len(v.Frames) != 1 {
		t.Fatalf("frames: %d %s", status, raw)
	}
	fe := v.Frames[0]
	if fe.Reason != string(symbolicate.IdentityMismatch) || fe.Resolved != nil || fe.MapSHA256 != nil || fe.Source.State == "present" || strings.Contains(string(raw), secretSource) {
		t.Fatalf("an unresolved frame was shown as mapped: %s", raw)
	}
	if v.State != httpapi.StateIncomplete || v.Reason != "frames_unmapped" || len(v.Sections) != 1 || v.Sections[0].State != httpapi.StateIncomplete {
		t.Fatalf("nothing was mapped, the view cannot be ready: %s", raw)
	}
}

// The view owns its original frames: the caller's frame, including its column
// pointer, is copied, so later changes to the request cannot rewrite the answer.
func TestEvidenceSensFramesOriginalIsACopyOfTheRequestFrame(t *testing.T) {
	s := newFramesSensEnv(t)
	ev := httpapi.NewEvidence(s.resolver, nil, nil)
	column := uint32(7)
	body := httpapi.FramesBody{Org: s.org, Project: s.p, Build: model.NewID(), Frames: []model.Frame{{Module: "app", Function: "boom", Artifact: "a", Line: 10, Column: &column, InApp: true}}}
	view, _, err := ev.Frames(s.e.ctx, s.e.app.Auth, s.artifact.Cred, body)
	if err != nil || len(view.Frames) != 1 || view.Frames[0].Original.Column == nil {
		t.Fatalf("frames: %v %+v", err, view)
	}
	column = 99
	if got := *view.Frames[0].Original.Column; got != 7 {
		t.Fatalf("the original frame aliases the request's column: %d", got)
	}
	// And the resolver receives its own copy: scribbling over it cannot reach the original.
	s.resolver.answer = func(frames []model.Frame, o symbolicate.Options) ([]symbolicate.SymbolicatedFrame, error) {
		*frames[0].Column = 55
		return mapFrames(frames, o)
	}
	column = 7
	view, _, err = ev.Frames(s.e.ctx, s.e.app.Auth, s.artifact.Cred, body)
	if err != nil || *view.Frames[0].Original.Column != 7 || column != 7 {
		t.Fatalf("the resolver's copy aliases the original or the request: %v column=%d original=%d", err, column, *view.Frames[0].Original.Column)
	}
}

// A request names at least one and at most MaxEvidenceFrames frames.
func TestEvidenceSensFramesCountIsBounded(t *testing.T) {
	s := newFramesSensEnv(t)
	many := func(n int) map[string]any {
		frames := make([]map[string]any, n)
		for i := range frames {
			frames[i] = frame(10, "boom")
		}
		return framesBody(s.org, s.p, model.NewID(), false, frames...)
	}
	if status, raw := s.post(s.artifact, many(httpapi.MaxEvidenceFrames)); status != 200 {
		t.Fatalf("exactly the bound of frames is accepted: %d %s", status, raw)
	}
	ev := httpapi.NewEvidence(s.resolver, nil, nil)
	for name, n := range map[string]int{"none": 0, "over the bound": httpapi.MaxEvidenceFrames + 1} {
		before := s.resolver.calls.Load()
		status, _ := s.post(s.artifact, many(n))
		frames := make([]model.Frame, n)
		for i := range frames {
			frames[i] = model.Frame{Module: "app", Function: "boom", Artifact: "a", Line: 10}
		}
		_, _, err := ev.Frames(s.e.ctx, s.e.app.Auth, s.artifact.Cred, httpapi.FramesBody{Org: s.org, Project: s.p, Build: model.NewID(), Frames: frames})
		var f *model.Fault
		if status != 400 || !errors.As(err, &f) || f.Code != model.Invalid || f.SafeDetail != "evidence_request_invalid" || s.resolver.calls.Load() != before {
			t.Fatalf("%s: status %d, handler %v (resolver calls %d -> %d)", name, status, err, before, s.resolver.calls.Load())
		}
	}
}
