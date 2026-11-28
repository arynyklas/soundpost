// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package model_test

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

const (
	extProvider = "gitlab"
	extProject  = "shop/storefront-web"
	extURL      = "https://git.example.test/shop/storefront-web/-/issues/7"
)

var (
	extActor  = model.ID{0xa1}
	extOther  = model.ID{0xa2}
	extMarker = model.ExternalMarker(model.ID{0x01}, "incident", model.ID{0x02})
)

func wantExternalFault(t *testing.T, err error, code model.Code, detail string) {
	t.Helper()
	var f *model.Fault
	if !errors.As(err, &f) || f.Code != code || f.SafeDetail != detail {
		t.Fatalf("got %v, want %s/%s", err, code, detail)
	}
}

func extBegin(until model.UnixNano) model.ExternalOp {
	return model.ExternalOp{Provider: extProvider, Kind: model.ExternalBegin, Marker: extMarker, Project: extProject, Until: until}
}

func extEnd(result string) model.ExternalOp {
	op := model.ExternalOp{Provider: extProvider, Kind: model.ExternalEnd, Marker: extMarker, Project: extProject, Result: result}
	if result == model.ExternalLinked {
		op.IID, op.URL = 7, extURL
	} else {
		op.Code = "gitlab_timeout"
	}
	return op
}

func extAdopt() model.ExternalOp {
	return model.ExternalOp{Provider: extProvider, Kind: model.ExternalAdopt, Marker: extMarker, Project: extProject, Result: model.ExternalLinked, IID: 7, URL: extURL}
}

func mustApplyExternal(t *testing.T, links []model.ExternalLink, op model.ExternalOp, actor model.ID, at model.UnixNano) []model.ExternalLink {
	t.Helper()
	out, err := model.ApplyExternal(links, op, actor, at)
	if err != nil {
		t.Fatalf("%+v at %d: %v", op, at, err)
	}
	return out
}

func TestExternalMarkerIsDeterministicAndScoped(t *testing.T) {
	a := model.ExternalMarker(model.ID{1}, "incident", model.ID{2})
	if a != model.ExternalMarker(model.ID{1}, "incident", model.ID{2}) {
		t.Fatal("the marker is not deterministic")
	}
	if !strings.HasPrefix(a, "soundpost-ref-") || len(a) != len("soundpost-ref-")+32 {
		t.Fatalf("marker shape %q", a)
	}
	for name, other := range map[string]string{
		"org":    model.ExternalMarker(model.ID{9}, "incident", model.ID{2}),
		"kind":   model.ExternalMarker(model.ID{1}, "issue", model.ID{2}),
		"entity": model.ExternalMarker(model.ID{1}, "incident", model.ID{3}),
	} {
		if other == a {
			t.Fatalf("a different %s gave the same marker", name)
		}
	}
	// A marker must pass the operation's own token check, or no link could ever be begun.
	if err := model.ValidExternalOp(extBegin(2_000), 1_000); err != nil {
		t.Fatal(err)
	}
}

func TestApplyExternalBeginTakesTheLease(t *testing.T) {
	links := mustApplyExternal(t, nil, extBegin(2_000), extActor, 1_000)
	want := []model.ExternalLink{{Provider: extProvider, State: model.ExternalCreating, Marker: extMarker, Project: extProject, Actor: extActor, At: 1_000, Until: 2_000}}
	if !reflect.DeepEqual(links, want) {
		t.Fatalf("got %+v, want %+v", links, want)
	}
}

func TestApplyExternalEndLinkedIsTerminal(t *testing.T) {
	creating := mustApplyExternal(t, nil, extBegin(2_000), extActor, 1_000)
	linked := mustApplyExternal(t, creating, extEnd(model.ExternalLinked), extOther, 1_500)
	want := []model.ExternalLink{{Provider: extProvider, State: model.ExternalLinked, Marker: extMarker, Project: extProject, IID: 7, URL: extURL, Actor: extOther, At: 1_500}}
	if !reflect.DeepEqual(linked, want) {
		t.Fatalf("got %+v, want %+v", linked, want)
	}
	if linked[0].Until != 0 {
		t.Fatal("a linked link keeps a lease expiry")
	}
	for _, op := range []model.ExternalOp{extBegin(9_000), extEnd(model.ExternalLinked), extEnd(model.ExternalUnknown), extAdopt()} {
		_, err := model.ApplyExternal(linked, op, extActor, 1_600)
		wantExternalFault(t, err, model.Conflict, "external_already_linked")
	}
}

func TestApplyExternalEndKeepsOnlyAClosedCodeWhenItDoesNotLink(t *testing.T) {
	for _, result := range []string{model.ExternalUnknown, model.ExternalRefused} {
		creating := mustApplyExternal(t, nil, extBegin(2_000), extActor, 1_000)
		links := mustApplyExternal(t, creating, extEnd(result), extActor, 1_200)
		got := links[0]
		if got.State != result || got.Code != "gitlab_timeout" || got.IID != 0 || got.URL != "" || got.Until != 0 || got.Project != extProject || got.Marker != extMarker {
			t.Fatalf("%s: %+v", result, got)
		}
	}
}

func TestApplyExternalBeginAgainAfterUnknownOrRefused(t *testing.T) {
	for _, result := range []string{model.ExternalUnknown, model.ExternalRefused} {
		creating := mustApplyExternal(t, nil, extBegin(2_000), extActor, 1_000)
		ended := mustApplyExternal(t, creating, extEnd(result), extActor, 1_200)
		again := mustApplyExternal(t, ended, extBegin(5_000), extOther, 1_300)
		got := again[0]
		if got.State != model.ExternalCreating || got.Until != 5_000 || got.Actor != extOther || got.At != 1_300 || got.Code != "" || got.Marker != extMarker {
			t.Fatalf("%s: %+v", result, got)
		}
	}
}

func TestApplyExternalLeaseIsExclusiveUntilItExpires(t *testing.T) {
	held := mustApplyExternal(t, nil, extBegin(2_000), extActor, 1_000)
	for _, at := range []model.UnixNano{1_001, 1_999} {
		_, err := model.ApplyExternal(held, extBegin(at+2_000), extOther, at)
		wantExternalFault(t, err, model.Conflict, "external_in_progress")
		_, err = model.ApplyExternal(held, extAdopt(), extOther, at)
		wantExternalFault(t, err, model.Conflict, "external_in_progress")
	}
	// At exactly Until the lease is over: another request takes it over.
	taken := mustApplyExternal(t, held, extBegin(9_000), extOther, 2_000)
	if got := taken[0]; got.State != model.ExternalCreating || got.Actor != extOther || got.At != 2_000 || got.Until != 9_000 {
		t.Fatalf("takeover: %+v", got)
	}
	// Once the takeover linked the issue, the first (late) holder cannot overwrite it: a link is terminal.
	linked := mustApplyExternal(t, taken, extEnd(model.ExternalLinked), extOther, 2_100)
	_, err := model.ApplyExternal(linked, extEnd(model.ExternalUnknown), extActor, 2_200)
	wantExternalFault(t, err, model.Conflict, "external_already_linked")
}

func TestApplyExternalAdoptFromEveryStartThatAllowsIt(t *testing.T) {
	creating := mustApplyExternal(t, nil, extBegin(2_000), extActor, 1_000)
	unknown := mustApplyExternal(t, creating, extEnd(model.ExternalUnknown), extActor, 1_100)
	refused := mustApplyExternal(t, creating, extEnd(model.ExternalRefused), extActor, 1_100)
	for name, start := range map[string]struct {
		links []model.ExternalLink
		at    model.UnixNano
	}{
		"none":            {nil, 3_000},
		"unknown":         {unknown, 3_000},
		"refused":         {refused, 3_000},
		"expired lease":   {creating, 2_000},
		"long dead lease": {creating, 99_000},
	} {
		got := mustApplyExternal(t, start.links, extAdopt(), extOther, start.at)
		want := []model.ExternalLink{{Provider: extProvider, State: model.ExternalLinked, Marker: extMarker, Project: extProject, IID: 7, URL: extURL, Actor: extOther, At: start.at}}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: got %+v, want %+v", name, got, want)
		}
	}
}

func TestApplyExternalEndNeedsACreatingLease(t *testing.T) {
	creating := mustApplyExternal(t, nil, extBegin(2_000), extActor, 1_000)
	unknown := mustApplyExternal(t, creating, extEnd(model.ExternalUnknown), extActor, 1_100)
	refused := mustApplyExternal(t, creating, extEnd(model.ExternalRefused), extActor, 1_100)
	for name, links := range map[string][]model.ExternalLink{"none": nil, "unknown": unknown, "refused": refused} {
		_, err := model.ApplyExternal(links, extEnd(model.ExternalLinked), extActor, 1_200)
		if f := new(*model.Fault); !errors.As(err, f) || (*f).Code != model.Conflict || (*f).SafeDetail != "external_not_creating" {
			t.Fatalf("%s: got %v", name, err)
		}
	}
}

func TestApplyExternalRefusesAnotherEntitysMarker(t *testing.T) {
	foreign := extMarker[:len(extMarker)-1] + "0"
	if foreign == extMarker {
		foreign = extMarker[:len(extMarker)-1] + "1"
	}
	creating := mustApplyExternal(t, nil, extBegin(2_000), extActor, 1_000)
	unknown := mustApplyExternal(t, creating, extEnd(model.ExternalUnknown), extActor, 1_100)
	for name, links := range map[string][]model.ExternalLink{"creating": creating, "unknown": unknown} {
		for _, op := range []model.ExternalOp{extBegin(9_000), extEnd(model.ExternalLinked), extAdopt()} {
			op.Marker = foreign
			// The marker is checked before the lease: a live lease of another entity is a mismatch, not "busy".
			_, err := model.ApplyExternal(links, op, extActor, 1_500)
			if f := new(*model.Fault); !errors.As(err, f) || (*f).Code != model.Conflict || (*f).SafeDetail != "external_marker_mismatch" {
				t.Fatalf("%s/%s: got %v", name, op.Kind, err)
			}
		}
	}
}

func TestApplyExternalRefusesAnotherTrackerProject(t *testing.T) {
	creating := mustApplyExternal(t, nil, extBegin(2_000), extActor, 1_000)
	unknown := mustApplyExternal(t, creating, extEnd(model.ExternalUnknown), extActor, 1_100)

	other := extBegin(9_000)
	other.Project = "shop/other"
	_, err := model.ApplyExternal(unknown, other, extActor, 1_200)
	wantExternalFault(t, err, model.Conflict, "external_project_mismatch")
	_, err = model.ApplyExternal(creating, other, extActor, 2_500) // an expired lease is no licence to move the project
	wantExternalFault(t, err, model.Conflict, "external_project_mismatch")

	end := extEnd(model.ExternalLinked)
	end.Project = "shop/other"
	_, err = model.ApplyExternal(creating, end, extActor, 1_200)
	wantExternalFault(t, err, model.Conflict, "external_project_mismatch")

	// An end that names no project (unknown/refused) cannot mismatch.
	end = extEnd(model.ExternalUnknown)
	end.Project = ""
	if got := mustApplyExternal(t, creating, end, extActor, 1_200); got[0].Project != extProject {
		t.Fatalf("the lease's project was lost: %+v", got[0])
	}
}

func TestApplyExternalKeepsProvidersApartAndBoundsThem(t *testing.T) {
	links := mustApplyExternal(t, nil, extBegin(2_000), extActor, 1_000)
	second := extBegin(2_000)
	second.Provider = "forge2"
	links = mustApplyExternal(t, links, second, extActor, 1_000)
	if len(links) != 2 || links[0].Provider != extProvider || links[1].Provider != "forge2" {
		t.Fatalf("providers: %+v", links)
	}
	// The second provider's lease does not make the first one busy for itself, and an end of one touches only it.
	ended := mustApplyExternal(t, links, extEnd(model.ExternalLinked), extActor, 1_100)
	if ended[0].State != model.ExternalLinked || ended[1].State != model.ExternalCreating {
		t.Fatalf("end touched the other provider: %+v", ended)
	}
	for i := 2; i < model.MaxExternalLinks; i++ {
		p := extBegin(2_000)
		p.Provider = "forge" + string(rune('a'+i))
		links = mustApplyExternal(t, links, p, extActor, 1_000)
	}
	extra := extBegin(2_000)
	extra.Provider = "onetoomany"
	_, err := model.ApplyExternal(links, extra, extActor, 1_000)
	wantExternalFault(t, err, model.Quota, "external_full")
	extra.Kind = model.ExternalAdopt
	extra.Until, extra.Result, extra.IID, extra.URL = 0, model.ExternalLinked, 7, extURL
	_, err = model.ApplyExternal(links, extra, extActor, 1_000)
	wantExternalFault(t, err, model.Quota, "external_full")
	// A known provider is still served when the list is full.
	if _, err = model.ApplyExternal(links, extEnd(model.ExternalLinked), extActor, 1_100); err != nil {
		t.Fatal(err)
	}
}

func TestApplyExternalEndWithoutAnyLinkIsNotCreating(t *testing.T) {
	_, err := model.ApplyExternal(nil, extEnd(model.ExternalLinked), extActor, 1_000)
	wantExternalFault(t, err, model.Conflict, "external_not_creating")
}

func TestApplyExternalNeverModifiesItsInput(t *testing.T) {
	links := mustApplyExternal(t, nil, extBegin(2_000), extActor, 1_000)
	before := append([]model.ExternalLink(nil), links...)
	for _, op := range []model.ExternalOp{extEnd(model.ExternalLinked), extEnd(model.ExternalRefused), extAdopt(), extBegin(9_000)} {
		_, _ = model.ApplyExternal(links, op, extOther, 2_500)
		if !reflect.DeepEqual(links, before) {
			t.Fatalf("%s changed its input: %+v", op.Kind, links)
		}
	}
}

func TestApplyExternalRefusesWhatNeedsNoState(t *testing.T) {
	long := strings.Repeat("a", 65)
	cases := map[string]func(*model.ExternalOp){
		"empty provider":       func(o *model.ExternalOp) { o.Provider = "" },
		"provider with space":  func(o *model.ExternalOp) { o.Provider = "git lab" },
		"empty marker":         func(o *model.ExternalOp) { o.Marker = "" },
		"marker too long":      func(o *model.ExternalOp) { o.Marker = long },
		"project with space":   func(o *model.ExternalOp) { o.Project = "a b" },
		"project too long":     func(o *model.ExternalOp) { o.Project = strings.Repeat("p", 201) },
		"code too long":        func(o *model.ExternalOp) { o.Code = long },
		"unknown kind":         func(o *model.ExternalOp) { o.Kind = "retry" },
		"empty kind":           func(o *model.ExternalOp) { o.Kind = "" },
		"begin without a path": func(o *model.ExternalOp) { o.Project = "" },
		"begin lease in past":  func(o *model.ExternalOp) { o.Until = 1_000 },
		"begin lease too long": func(o *model.ExternalOp) { o.Until = 1_000 + model.ExternalMaxLease + 1 },
		"begin with result":    func(o *model.ExternalOp) { o.Result = model.ExternalLinked },
		"begin with iid":       func(o *model.ExternalOp) { o.IID = 7 },
		"begin with url":       func(o *model.ExternalOp) { o.URL = extURL },
		"begin with code":      func(o *model.ExternalOp) { o.Code = "x" },
	}
	for name, mutate := range cases {
		op := extBegin(2_000)
		mutate(&op)
		_, err := model.ApplyExternal(nil, op, extActor, 1_000)
		wantExternalFault(t, err, model.Invalid, "external_invalid")
		_ = name
	}
	endCases := map[string]func(*model.ExternalOp){
		"result missing":          func(o *model.ExternalOp) { o.Result = "" },
		"result creating":         func(o *model.ExternalOp) { o.Result = model.ExternalCreating },
		"http url":                func(o *model.ExternalOp) { o.URL = "http://git.example.test/a/b/-/issues/7" },
		"url with user":           func(o *model.ExternalOp) { o.URL = "https://u:p@git.example.test/a/b/-/issues/7" },
		"url without host":        func(o *model.ExternalOp) { o.URL = "https:///a" },
		"url too long":            func(o *model.ExternalOp) { o.URL = "https://git.example.test/" + strings.Repeat("a", 520) },
		"linked without iid":      func(o *model.ExternalOp) { o.IID = 0 },
		"linked without project":  func(o *model.ExternalOp) { o.Project = "" },
		"linked with code":        func(o *model.ExternalOp) { o.Code = "x" },
		"end with lease":          func(o *model.ExternalOp) { o.Until = 5_000 },
		"unparsable url":          func(o *model.ExternalOp) { o.URL = "https://%zz" },
		"url with invalid utf-8":  func(o *model.ExternalOp) { o.URL = "https://git.example.test/\xff" },
		"url scheme only":         func(o *model.ExternalOp) { o.URL = "https:" },
		"url with relative path":  func(o *model.ExternalOp) { o.URL = "/a/b" },
		"url with a ftp scheme":   func(o *model.ExternalOp) { o.URL = "ftp://git.example.test/a" },
		"url with a blank scheme": func(o *model.ExternalOp) { o.URL = "//git.example.test/a" },
	}
	for name, mutate := range endCases {
		op := extEnd(model.ExternalLinked)
		mutate(&op)
		_, err := model.ApplyExternal(nil, op, extActor, 1_000)
		wantExternalFault(t, err, model.Invalid, "external_invalid")
		_ = name
	}
	for name, mutate := range map[string]func(*model.ExternalOp){
		"unknown without code": func(o *model.ExternalOp) { o.Code = "" },
		"unknown with iid":     func(o *model.ExternalOp) { o.IID = 7 },
		"unknown with url":     func(o *model.ExternalOp) { o.URL = extURL },
		"unknown with lease":   func(o *model.ExternalOp) { o.Until = 5_000 },
	} {
		op := extEnd(model.ExternalUnknown)
		mutate(&op)
		_, err := model.ApplyExternal(nil, op, extActor, 1_000)
		wantExternalFault(t, err, model.Invalid, "external_invalid")
		_ = name
	}
	adopt := extAdopt()
	adopt.Result, adopt.IID, adopt.URL, adopt.Code = model.ExternalUnknown, 0, "", "x"
	_, err := model.ApplyExternal(nil, adopt, extActor, 1_000)
	wantExternalFault(t, err, model.Invalid, "external_invalid")
	adopt = extAdopt()
	adopt.Until = 5_000
	_, err = model.ApplyExternal(nil, adopt, extActor, 1_000)
	wantExternalFault(t, err, model.Invalid, "external_invalid")
}

func TestApplyExternalNeedsAnActorAndATime(t *testing.T) {
	_, err := model.ApplyExternal(nil, extBegin(2_000), model.ID{}, 1_000)
	wantExternalFault(t, err, model.Invalid, "external_invalid")
	for _, at := range []model.UnixNano{0, -5} {
		_, err = model.ApplyExternal(nil, extBegin(2_000), extActor, at)
		wantExternalFault(t, err, model.Invalid, "external_invalid")
	}
}

func TestApplyExternalAdoptTakesTheOperationsProject(t *testing.T) {
	creating := mustApplyExternal(t, nil, extBegin(2_000), extActor, 1_000)
	moved := extAdopt()
	moved.Project = "shop/moved"
	got := mustApplyExternal(t, creating, moved, extOther, 3_000)
	if got[0].Project != "shop/moved" || got[0].State != model.ExternalLinked || got[0].Marker != extMarker {
		t.Fatalf("adopt: %+v", got[0])
	}
}
