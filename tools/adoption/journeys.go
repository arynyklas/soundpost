// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"soundpost/internal/httpapi"
	"soundpost/internal/model"
	"soundpost/internal/query"
)

// Task 08.03: verify the application journeys from product evidence.
//
// A journey is accepted only from scoped product reads: the spans, the release
// and source-map identities, the job attempts, the replay stream and the
// capability records the product itself holds for the caller-named IDs. An ID
// alone is never a pass. The detailed JourneyReport is private operator
// material; JourneyPublicSummary is the only shape that may leave the private
// directory and it carries counts and closed enum values, nothing copied from
// evidence.

const journeySchemaVersion = 1

// JourneyKind names one required section of the acceptance. The first three are
// the three contract shapes; the last two are the replay privacy and runtime
// capability evidence that must accompany them.
type JourneyKind string

const (
	JourneyGatewayDependency JourneyKind = "gateway_dependency"
	JourneyFrontendAPIDB     JourneyKind = "frontend_api_db"
	JourneySchedulerRetry    JourneyKind = "scheduler_retry"
	JourneyReplayPrivacy     JourneyKind = "replay_privacy"
	JourneyRuntimeCapability JourneyKind = "runtime_capability"
)

var journeyKinds = []JourneyKind{JourneyGatewayDependency, JourneyFrontendAPIDB, JourneySchedulerRetry, JourneyReplayPrivacy, JourneyRuntimeCapability}

// JourneyStatus is the verdict of a section.
type JourneyStatus string

const (
	JourneyPassed JourneyStatus = "passed"
	JourneyFailed JourneyStatus = "failed"
)

// JourneyRowStatus is the closed status of an evidence row that may be
// inaccessible by design. Unavailable and denied are never counted as passed
// evidence and are never replaced by invented spans or records.
type JourneyRowStatus string

const (
	JourneyRowExercised   JourneyRowStatus = "exercised"
	JourneyRowUnavailable JourneyRowStatus = "unavailable"
	JourneyRowDenied      JourneyRowStatus = "denied"
)

// JourneyRowBasis says whether a row status was observed in product evidence or
// only declared by the caller (an inaccessible internal cannot be observed).
type JourneyRowBasis string

const (
	JourneyBasisObserved JourneyRowBasis = "observed"
	JourneyBasisDeclared JourneyRowBasis = "declared"
)

// JourneyCode is the closed vocabulary of failure reasons.
type JourneyCode string

const (
	JourneyCodeExpectationMissing   JourneyCode = "expectation_missing"
	JourneyCodeExpectationInvalid   JourneyCode = "expectation_invalid"
	JourneyCodeReadFailed           JourneyCode = "read_failed"
	JourneyCodeTargetNotFound       JourneyCode = "target_not_found"
	JourneyCodeCredentialDenied     JourneyCode = "credential_denied"
	JourneyCodeScopeMismatch        JourneyCode = "scope_mismatch"
	JourneyCodeViewNotReady         JourneyCode = "view_not_ready"
	JourneyCodeEvidencePartial      JourneyCode = "evidence_partial"
	JourneyCodeRootMissing          JourneyCode = "root_span_missing"
	JourneyCodeRootAmbiguous        JourneyCode = "root_span_ambiguous"
	JourneyCodeSpanMissing          JourneyCode = "dependency_span_missing"
	JourneyCodeSpanUnlinked         JourneyCode = "dependency_span_unlinked"
	JourneyCodeSpanInvalid          JourneyCode = "span_invalid"
	JourneyCodeClockContradiction   JourneyCode = "clock_contradiction"
	JourneyCodeInternalsReason      JourneyCode = "third_party_reason_missing"
	JourneyCodeReleaseNotMapped     JourneyCode = "release_not_mapped"
	JourneyCodeDebugHashMismatch    JourneyCode = "debug_hash_mismatch"
	JourneyCodeFrameNotInBuild      JourneyCode = "frame_not_in_build"
	JourneyCodeFrameMismatch        JourneyCode = "frame_position_mismatch"
	JourneyCodeLocalMapInconsistent JourneyCode = "local_map_inconsistent"
	JourneyCodeErrorNotMapped       JourneyCode = "error_release_not_mapped"
	JourneyCodeFailedAttemptMissing JourneyCode = "failed_attempt_missing"
	JourneyCodeFailedAttemptChanged JourneyCode = "failed_attempt_overwritten"
	JourneyCodeRecoveryMissing      JourneyCode = "recovery_attempt_missing"
	JourneyCodeAttemptIDsNotUnique  JourneyCode = "attempt_ids_not_distinct"
	JourneyCodeAttemptOrder         JourneyCode = "attempt_order_invalid"
	JourneyCodeRunNotRecovered      JourneyCode = "run_not_recovered"
	JourneyCodeHistoryErased        JourneyCode = "job_history_erased"
	JourneyCodeCauseMismatch        JourneyCode = "failure_cause_mismatch"
	JourneyCodeReplayIncomplete     JourneyCode = "replay_incomplete"
	JourneyCodePrivacyViolation     JourneyCode = "replay_privacy_violation"
	JourneyCodeCapabilityMismatch   JourneyCode = "capability_mismatch"
)

var journeyCodes = map[JourneyCode]bool{
	JourneyCodeExpectationMissing: true, JourneyCodeExpectationInvalid: true, JourneyCodeReadFailed: true,
	JourneyCodeTargetNotFound: true, JourneyCodeCredentialDenied: true, JourneyCodeScopeMismatch: true,
	JourneyCodeViewNotReady: true, JourneyCodeEvidencePartial: true, JourneyCodeRootMissing: true,
	JourneyCodeRootAmbiguous: true, JourneyCodeSpanMissing: true, JourneyCodeSpanUnlinked: true,
	JourneyCodeSpanInvalid: true, JourneyCodeClockContradiction: true, JourneyCodeInternalsReason: true,
	JourneyCodeReleaseNotMapped: true, JourneyCodeDebugHashMismatch: true, JourneyCodeFrameNotInBuild: true,
	JourneyCodeFrameMismatch: true, JourneyCodeLocalMapInconsistent: true, JourneyCodeErrorNotMapped: true,
	JourneyCodeFailedAttemptMissing: true, JourneyCodeFailedAttemptChanged: true, JourneyCodeRecoveryMissing: true,
	JourneyCodeAttemptIDsNotUnique: true, JourneyCodeAttemptOrder: true, JourneyCodeRunNotRecovered: true,
	JourneyCodeHistoryErased: true, JourneyCodeCauseMismatch: true, JourneyCodeReplayIncomplete: true,
	JourneyCodePrivacyViolation: true, JourneyCodeCapabilityMismatch: true,
}

// JourneyCheckName is the closed set of checks a section can run.
type JourneyCheckName string

const (
	JourneyCheckExpectation  JourneyCheckName = "expectation"
	JourneyCheckRead         JourneyCheckName = "read"
	JourneyCheckScope        JourneyCheckName = "scope"
	JourneyCheckCompleteness JourneyCheckName = "completeness"
	JourneyCheckRoot         JourneyCheckName = "root_span"
	JourneyCheckDependency   JourneyCheckName = "dependency_span"
	JourneyCheckClock        JourneyCheckName = "clock_order"
	JourneyCheckInternals    JourneyCheckName = "third_party_internals"
	JourneyCheckRelease      JourneyCheckName = "release_identity"
	JourneyCheckDebugHash    JourneyCheckName = "debug_hash"
	JourneyCheckFrame        JourneyCheckName = "frame_mapping"
	JourneyCheckLocalMap     JourneyCheckName = "local_map"
	JourneyCheckErrorMap     JourneyCheckName = "error_release"
	JourneyCheckFailed       JourneyCheckName = "failed_attempt"
	JourneyCheckRecovery     JourneyCheckName = "recovery_attempt"
	JourneyCheckIdentity     JourneyCheckName = "attempt_identity"
	JourneyCheckOrder        JourneyCheckName = "attempt_order"
	JourneyCheckRun          JourneyCheckName = "run_status"
	JourneyCheckCause        JourneyCheckName = "failure_cause"
	JourneyCheckReplay       JourneyCheckName = "replay_stream"
	JourneyCheckPrivacy      JourneyCheckName = "replay_privacy"
	JourneyCheckCapability   JourneyCheckName = "capability"
)

// JourneyCheck is one verdict. Detail is private operator text built from fixed
// wording and caller-named IDs; it never carries response bodies.
type JourneyCheck struct {
	Name   JourneyCheckName
	Passed bool
	Code   JourneyCode
	Detail string
}

// JourneyRow is one typed evidence row whose inaccessibility is a legitimate,
// reported outcome. Name and Reason are private caller labels.
type JourneyRow struct {
	Name   string
	Basis  JourneyRowBasis
	Status JourneyRowStatus
	Reason string
}

// JourneyResult is the private detail of one section.
type JourneyResult struct {
	Kind   JourneyKind
	Status JourneyStatus
	Checks []JourneyCheck
	Rows   []JourneyRow
}

// JourneyReport is the private, detailed report. It is not publishable; use
// JourneyPublicProjection.
type JourneyReport struct {
	SchemaVersion int
	VerifiedAt    time.Time
	Passed        bool
	Results       []JourneyResult
}

// JourneyTargets names where evidence is read. Org and Project are the scope
// the reads are made under; every response must echo exactly this scope.
type JourneyTargets struct {
	ServerURL string        `json:"server_url"`
	Bearer    string        `json:"-"`
	Org       string        `json:"org"`
	Project   string        `json:"project"`
	Reader    JourneyReader `json:"-"` // in-process alternative to ServerURL+Bearer
}

// JourneyWindow is the half-open [start,end) nanosecond range spans or samples
// are read from.
type JourneyWindow struct {
	StartNS int64 `json:"start_ns"`
	EndNS   int64 `json:"end_ns"`
}

// JourneySpanMatch selects a span by what the application emitted. At least an
// operation or a dependency alias is required so that a match cannot be vacuous.
type JourneySpanMatch struct {
	Operation  string `json:"operation,omitempty"`
	Kind       string `json:"span_kind,omitempty"`
	Dependency string `json:"dependency_alias,omitempty"`
	Status     string `json:"status,omitempty"`
}

// JourneyThirdPartyInternals declares that spans below a dependency are not
// observable (the provider is not ours to instrument). The verifier reports
// them as unavailable with this reason and never invents them.
type JourneyThirdPartyInternals struct {
	Reason string `json:"reason"`
}

// JourneyDependency is one required real child of the gateway request.
type JourneyDependency struct {
	Name                string                      `json:"name"`
	Span                JourneySpanMatch            `json:"span"`
	ThirdPartyInternals *JourneyThirdPartyInternals `json:"third_party_internals,omitempty"`
}

// JourneyGatewayLink is gateway -> model/dependency: one trace from an actual
// request whose root and named dependency children must all be present.
type JourneyGatewayLink struct {
	Trace        string              `json:"trace"`
	Window       JourneyWindow       `json:"window"`
	Root         JourneySpanMatch    `json:"root"`
	Dependencies []JourneyDependency `json:"dependencies"`
}

// JourneyFrame is the generated-code frame an error captured.
type JourneyFrame struct {
	Module   string `json:"module_id"`
	Function string `json:"function"`
	Line     uint32 `json:"line"`
	Column   uint32 `json:"column"`
}

// JourneyOriginalPosition is where the build's source map must place the frame.
type JourneyOriginalPosition struct {
	Source   string `json:"source"`
	Function string `json:"function,omitempty"`
	Line     uint32 `json:"line"`
	Column   uint32 `json:"column"`
}

// JourneyFrontendLink is frontend -> API -> DB with a mapped release and error.
// Chain is ordered root first; each element must be a direct child of the one
// before. DebugSHA256 is the hex SHA-256 of the exact source map uploaded for
// Artifact. MapFile names a local build output the CLI loads into MapBytes; with
// it the expected original position is checked against the build itself.
type JourneyFrontendLink struct {
	Trace       string                  `json:"trace"`
	Window      JourneyWindow           `json:"window"`
	Chain       []JourneySpanMatch      `json:"chain"`
	Release     string                  `json:"release"`
	Build       string                  `json:"build"`
	Issue       string                  `json:"issue"`
	Artifact    string                  `json:"artifact"`
	DebugID     string                  `json:"debug_id"`
	DebugSHA256 string                  `json:"debug_sha256"`
	Frame       JourneyFrame            `json:"frame"`
	Original    JourneyOriginalPosition `json:"original"`
	MapFile     string                  `json:"map_file,omitempty"`
	MapBytes    []byte                  `json:"-"`
}

// JourneySchedulerLink is scheduler/background failure -> retry/recovery. Both
// attempt IDs are explicit: the failed attempt must remain and the recovery must
// be a different attempt of the same run.
type JourneySchedulerLink struct {
	Job             string `json:"job"`
	Run             string `json:"run"`
	FailedAttempt   string `json:"failed_attempt"`
	RecoveryAttempt string `json:"recovery_attempt"`
	FailureTrace    string `json:"failure_trace,omitempty"`
}

// JourneyReplayLink names one replay captured while the caller typed the
// sentinel values into protected fields. Sentinels must never appear.
type JourneyReplayLink struct {
	Replay    string   `json:"replay"`
	Sentinels []string `json:"sentinels"`
}

// JourneyCapabilityExpectation is one runtime/native capability row. Expect is
// exercised (default), unavailable or denied. A row with a Profile is observed
// from that profile's capability records and samples; a row without one can only
// be a declared unavailable/denied with a Reason.
type JourneyCapabilityExpectation struct {
	Name    string        `json:"name"`
	Profile string        `json:"profile,omitempty"`
	Window  JourneyWindow `json:"window,omitempty"`
	Runtime string        `json:"runtime"`
	Method  string        `json:"method"`
	OS      string        `json:"os,omitempty"`
	Arch    string        `json:"arch,omitempty"`
	Expect  string        `json:"expect,omitempty"`
	Reason  string        `json:"reason,omitempty"`
}

// JourneyCapabilityLink lists the required capability rows.
type JourneyCapabilityLink struct {
	Rows []JourneyCapabilityExpectation `json:"rows"`
}

// ExpectedLinks names the contract shapes with caller-supplied names and IDs.
// Nothing here has a default: no hostname, service or customer name is built in.
// A nil section is a failed section, never a skipped one.
type ExpectedLinks struct {
	Gateway      *JourneyGatewayLink    `json:"gateway,omitempty"`
	Frontend     *JourneyFrontendLink   `json:"frontend,omitempty"`
	Scheduler    *JourneySchedulerLink  `json:"scheduler,omitempty"`
	Replay       *JourneyReplayLink     `json:"replay,omitempty"`
	Capabilities *JourneyCapabilityLink `json:"capabilities,omitempty"`
}

func journeyDone(res JourneyResult) JourneyResult {
	res.Status = JourneyPassed
	if len(res.Checks) == 0 {
		res.Status = JourneyFailed
	}
	for _, c := range res.Checks {
		if !c.Passed {
			res.Status = JourneyFailed
		}
	}
	return res
}

func journeyMissing(kind JourneyKind) JourneyResult {
	return journeyDone(JourneyResult{Kind: kind, Checks: []JourneyCheck{journeyBad(JourneyCheckExpectation, JourneyCodeExpectationMissing, "section expectation not supplied")}})
}

// journeyReadCheck turns a failed read into a closed check. A cancelled or
// expired context is not a verdict: it aborts the whole verification.
func journeyReadCheck(ctx context.Context, err error) (JourneyCheck, error) {
	if ctx.Err() != nil {
		return JourneyCheck{}, ctx.Err()
	}
	return journeyBad(JourneyCheckRead, journeyReadCode(err), "product read failed: "+string(journeyReadCode(err))), nil
}

func (t JourneyTargets) resolve() (org, project model.ID, reader JourneyReader, err error) {
	if org, err = model.ParseID(t.Org); err != nil {
		return org, project, nil, errors.New("invalid org")
	}
	if project, err = model.ParseID(t.Project); err != nil {
		return org, project, nil, errors.New("invalid project")
	}
	switch {
	case t.Reader != nil && t.ServerURL != "":
		return org, project, nil, errors.New("exactly one evidence source is allowed")
	case t.Reader != nil:
		return org, project, t.Reader, nil
	}
	reader, err = newJourneyHTTPReader(t.ServerURL, t.Bearer)
	return org, project, reader, err
}

// VerifyJourneys reads the product evidence for each required section and
// returns the private report. A failed acceptance is a report with Passed false,
// not an error; an error means the verification itself could not run (invalid
// targets, cancellation). It performs reads only.
func VerifyJourneys(ctx context.Context, targets JourneyTargets, links ExpectedLinks) (JourneyReport, error) {
	org, project, reader, err := targets.resolve()
	if err != nil {
		return JourneyReport{}, err
	}
	report := JourneyReport{SchemaVersion: journeySchemaVersion, VerifiedAt: time.Now().UTC(), Passed: true}
	sections := []func() (JourneyResult, error){
		func() (JourneyResult, error) { return journeyRunGateway(ctx, reader, org, project, links.Gateway) },
		func() (JourneyResult, error) { return journeyRunFrontend(ctx, reader, org, project, links.Frontend) },
		func() (JourneyResult, error) { return journeyRunScheduler(ctx, reader, org, project, links.Scheduler) },
		func() (JourneyResult, error) { return journeyRunReplay(ctx, reader, org, project, links.Replay) },
		func() (JourneyResult, error) {
			return journeyRunCapabilities(ctx, reader, org, project, links.Capabilities)
		},
	}
	for _, run := range sections {
		res, err := run()
		if err != nil {
			return JourneyReport{}, err
		}
		report.Passed = report.Passed && res.Status == JourneyPassed
		report.Results = append(report.Results, res)
	}
	return report, nil
}

func journeyRunGateway(ctx context.Context, rd JourneyReader, org, project model.ID, link *JourneyGatewayLink) (JourneyResult, error) {
	if link == nil {
		return journeyMissing(JourneyGatewayDependency), nil
	}
	res := JourneyResult{Kind: JourneyGatewayDependency}
	trace, window, bad := journeyTraceRequest(link.Trace, link.Window)
	if bad == "" && (!journeyMatchValid(link.Root) || len(link.Dependencies) == 0) {
		bad = "gateway root and at least one dependency must be named"
	}
	for _, d := range link.Dependencies {
		if bad == "" && !journeyMatchValid(d.Span) {
			bad = "dependency span needs an operation or alias"
		}
	}
	if bad != "" {
		res.Checks = append(res.Checks, journeyBad(JourneyCheckExpectation, JourneyCodeExpectationInvalid, bad))
		return journeyDone(res), nil
	}
	view, err := rd.Trace(ctx, httpapi.TraceBody{ScopeFields: httpapi.ScopeFields{Org: org}, Project: project, Trace: trace, Window: window})
	if err != nil {
		check, ctxErr := journeyReadCheck(ctx, err)
		if ctxErr != nil {
			return JourneyResult{}, ctxErr
		}
		res.Checks = append(res.Checks, check)
		return journeyDone(res), nil
	}
	res.Checks, res.Rows = journeyAssertGateway(link, org, project, trace, view)
	return journeyDone(res), nil
}

func journeyRunFrontend(ctx context.Context, rd JourneyReader, org, project model.ID, link *JourneyFrontendLink) (JourneyResult, error) {
	if link == nil {
		return journeyMissing(JourneyFrontendAPIDB), nil
	}
	res := JourneyResult{Kind: JourneyFrontendAPIDB}
	exp, bad := journeyParseFrontend(link)
	if bad != "" {
		res.Checks = append(res.Checks, journeyBad(JourneyCheckExpectation, JourneyCodeExpectationInvalid, bad))
		return journeyDone(res), nil
	}
	fail := func(err error) (bool, error) {
		check, ctxErr := journeyReadCheck(ctx, err)
		if ctxErr != nil {
			return false, ctxErr
		}
		res.Checks = append(res.Checks, check)
		return true, nil
	}

	trace, err := rd.Trace(ctx, httpapi.TraceBody{ScopeFields: httpapi.ScopeFields{Org: org}, Project: project, Trace: exp.trace, Window: exp.window})
	if err != nil {
		if _, ctxErr := fail(err); ctxErr != nil {
			return JourneyResult{}, ctxErr
		}
	} else {
		res.Checks = append(res.Checks, journeyAssertChain(link.Chain, org, project, exp.trace, trace)...)
	}

	release, err := rd.Release(ctx, httpapi.ReleaseBody{Org: org, Project: project, Release: exp.release})
	if err != nil {
		if _, ctxErr := fail(err); ctxErr != nil {
			return JourneyResult{}, ctxErr
		}
	} else {
		res.Checks = append(res.Checks, journeyAssertRelease(exp, org, project, release)...)
	}

	frames, err := rd.Frames(ctx, httpapi.FramesBody{Org: org, Project: project, Build: exp.build, Frames: []model.Frame{exp.frame}})
	if err != nil {
		if _, ctxErr := fail(err); ctxErr != nil {
			return JourneyResult{}, ctxErr
		}
	} else {
		res.Checks = append(res.Checks, journeyAssertFrames(exp, org, project, frames)...)
	}

	issue, err := rd.Issue(ctx, httpapi.IssueBody{Org: org, Project: project, Issue: exp.issue})
	if err != nil {
		if _, ctxErr := fail(err); ctxErr != nil {
			return JourneyResult{}, ctxErr
		}
	} else {
		res.Checks = append(res.Checks, journeyAssertIssue(exp, org, project, issue)...)
	}

	checks, rows := journeyAssertLocalMap(link)
	res.Checks, res.Rows = append(res.Checks, checks...), append(res.Rows, rows...)
	return journeyDone(res), nil
}

func journeyRunScheduler(ctx context.Context, rd JourneyReader, org, project model.ID, link *JourneySchedulerLink) (JourneyResult, error) {
	if link == nil {
		return journeyMissing(JourneySchedulerRetry), nil
	}
	res := JourneyResult{Kind: JourneySchedulerRetry}
	exp, bad := journeyParseScheduler(link)
	if bad != "" {
		res.Checks = append(res.Checks, journeyBad(JourneyCheckExpectation, JourneyCodeExpectationInvalid, bad))
		if bad == journeyBadAttemptIDs {
			res.Checks[0].Code = JourneyCodeAttemptIDsNotUnique
		}
		return journeyDone(res), nil
	}
	view, err := rd.Job(ctx, httpapi.JobViewBody{Org: org, Project: project, Job: exp.job, Run: exp.run})
	if err != nil {
		check, ctxErr := journeyReadCheck(ctx, err)
		if ctxErr != nil {
			return JourneyResult{}, ctxErr
		}
		res.Checks = append(res.Checks, check)
		return journeyDone(res), nil
	}
	res.Checks = journeyAssertScheduler(exp, org, project, view)
	return journeyDone(res), nil
}

func journeyRunReplay(ctx context.Context, rd JourneyReader, org, project model.ID, link *JourneyReplayLink) (JourneyResult, error) {
	if link == nil {
		return journeyMissing(JourneyReplayPrivacy), nil
	}
	res := JourneyResult{Kind: JourneyReplayPrivacy}
	replay, bad := journeyParseReplay(link)
	if bad != "" {
		res.Checks = append(res.Checks, journeyBad(JourneyCheckExpectation, JourneyCodeExpectationInvalid, bad))
		return journeyDone(res), nil
	}
	lines, err := rd.Replay(ctx, httpapi.ReplayBody{ScopeFields: httpapi.ScopeFields{Org: org}, Project: project, Replay: replay})
	if err != nil {
		check, ctxErr := journeyReadCheck(ctx, err)
		if ctxErr != nil {
			return JourneyResult{}, ctxErr
		}
		res.Checks = append(res.Checks, check)
		return journeyDone(res), nil
	}
	res.Checks = journeyAssertReplay(link, org, project, replay, lines)
	return journeyDone(res), nil
}

func journeyRunCapabilities(ctx context.Context, rd JourneyReader, org, project model.ID, link *JourneyCapabilityLink) (JourneyResult, error) {
	if link == nil {
		return journeyMissing(JourneyRuntimeCapability), nil
	}
	res := JourneyResult{Kind: JourneyRuntimeCapability}
	if len(link.Rows) == 0 {
		res.Checks = append(res.Checks, journeyBad(JourneyCheckExpectation, JourneyCodeExpectationInvalid, "at least one capability row must be named"))
		return journeyDone(res), nil
	}
	exps := make([]journeyCapabilityExpect, len(link.Rows))
	for i, row := range link.Rows {
		var bad string
		if exps[i], bad = journeyParseCapability(row); bad != "" {
			res.Checks = append(res.Checks, journeyBad(JourneyCheckExpectation, JourneyCodeExpectationInvalid, bad))
		}
	}
	if len(res.Checks) != 0 {
		return journeyDone(res), nil // an invalid expectation is refused before any read
	}
	type profileKey struct {
		profile model.ID
		window  JourneyWindow
	}
	type profileRead struct {
		view *httpapi.ProfileResponse
		err  error
	}
	reads := map[profileKey]profileRead{}
	for i, row := range link.Rows {
		exp := exps[i]
		var read profileRead
		if exp.profile != (model.ID{}) {
			key := profileKey{exp.profile, exp.window}
			var done bool
			if read, done = reads[key]; !done {
				view, err := rd.Profile(ctx, httpapi.ProfileBody{ScopeFields: httpapi.ScopeFields{Org: org}, Project: project, Profile: exp.profile, Window: query.TimeRange{Start: model.UnixNano(exp.window.StartNS), End: model.UnixNano(exp.window.EndNS)}})
				if err != nil {
					if ctx.Err() != nil {
						return JourneyResult{}, ctx.Err()
					}
					read = profileRead{err: err}
				} else {
					read = profileRead{view: &view}
				}
				reads[key] = read
			}
		}
		check, evidence := journeyAssertCapability(row, exp, org, project, read.view, read.err)
		res.Checks = append(res.Checks, check)
		res.Rows = append(res.Rows, evidence)
	}
	return journeyDone(res), nil
}

// ---------------------------------------------------------------- public

// JourneyPublicSection is the publishable shape of one section: a fixed enum and
// counts.
type JourneyPublicSection struct {
	Kind         JourneyKind
	Passed       bool
	ChecksPassed int
	ChecksFailed int
}

// JourneyPublicCode counts one closed failure code.
type JourneyPublicCode struct {
	Code  JourneyCode
	Count int
}

// JourneyPublicSummary is the closed, allowlisted public projection. It has no
// identifier or free-text field; every string is a member of a fixed enum.
// CustomerAcceptance is always false: this tool never certifies a customer.
type JourneyPublicSummary struct {
	SchemaVersion             int
	Sections                  []JourneyPublicSection
	SectionsPassed            int
	SectionsFailed            int
	ChecksPassed              int
	ChecksFailed              int
	RowsExercised             int
	RowsUnavailable           int
	RowsDenied                int
	FailureCodes              []JourneyPublicCode
	AllRequiredSectionsPassed bool
	CustomerAcceptance        bool
}

// JourneyPublicProjection derives the public summary from a private report. It
// copies no evidence-derived string: kinds and codes are re-selected from the
// fixed enums, and anything outside them is dropped.
func JourneyPublicProjection(report JourneyReport) JourneyPublicSummary {
	out := JourneyPublicSummary{SchemaVersion: journeySchemaVersion, Sections: []JourneyPublicSection{}, FailureCodes: []JourneyPublicCode{}}
	counts := map[JourneyCode]int{}
	seen := map[JourneyKind]bool{}
	for _, kind := range journeyKinds {
		for _, res := range report.Results {
			if res.Kind != kind || seen[kind] {
				continue
			}
			seen[kind] = true
			section := JourneyPublicSection{Kind: kind, Passed: res.Status == JourneyPassed}
			for _, c := range res.Checks {
				if c.Passed {
					section.ChecksPassed++
					continue
				}
				section.ChecksFailed++
				if journeyCodes[c.Code] {
					counts[c.Code]++
				}
			}
			for _, row := range res.Rows {
				switch row.Status {
				case JourneyRowExercised:
					out.RowsExercised++
				case JourneyRowUnavailable:
					out.RowsUnavailable++
				case JourneyRowDenied:
					out.RowsDenied++
				}
			}
			if section.Passed {
				out.SectionsPassed++
			} else {
				out.SectionsFailed++
			}
			out.ChecksPassed += section.ChecksPassed
			out.ChecksFailed += section.ChecksFailed
			out.Sections = append(out.Sections, section)
		}
	}
	codes := make([]string, 0, len(counts))
	for code := range counts {
		codes = append(codes, string(code))
	}
	sort.Strings(codes)
	for _, code := range codes {
		out.FailureCodes = append(out.FailureCodes, JourneyPublicCode{Code: JourneyCode(code), Count: counts[JourneyCode(code)]})
	}
	out.AllRequiredSectionsPassed = report.Passed && len(out.Sections) == len(journeyKinds) && out.SectionsFailed == 0
	return out
}

// ---------------------------------------------------------------- CLI

// journeyAuthorize requires an explicit read-only grant whose single scope names
// this exact server URL and only the product-journey-read collector. A grant is
// an operator assertion, not cryptographic identity.
func journeyAuthorize(grant Authorization, server string, now time.Time) error {
	if !grant.ReadOnly || !nonempty(grant.GrantID, grant.Authority) || grant.NotBefore.IsZero() || now.Before(grant.NotBefore) || !now.Before(grant.ExpiresAt) {
		return errors.New("authorization validation failed")
	}
	matches := 0
	for _, scope := range grant.Scopes {
		if scope.EvidenceURL != server {
			continue
		}
		if len(scope.Collectors) != 1 || scope.Collectors[0] != "product-journey-read" {
			return errors.New("authorization validation failed")
		}
		matches++
	}
	if matches != 1 {
		return errors.New("authorization validation failed")
	}
	return nil
}

func journeyLoadMap(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, journeyMaxMapBytes+1))
	if err != nil || len(raw) > journeyMaxMapBytes {
		return nil, errors.New("map file unreadable or too large")
	}
	return raw, nil
}

// runJourneys is the `journeys` subcommand. The parent dispatches
// `adoption journeys <flags>` by passing the flags (without the subcommand name).
//
//	--server URL                    exact Soundpost server base URL (matches the grant)
//	--org ID --project ID           scope of every read
//	--expected FILE                 private ExpectedLinks JSON
//	--authorization FILE            private read-only grant for this exact URL
//	--private-output DIRECTORY      existing external private directory
//	--public-summary FILE           new file for the closed public projection
//	--bearer-env NAME               environment variable holding the bearer
//	                                (default SOUNDPOST_JOURNEY_BEARER)
//	--private-directory-acl-confirmed  operator verified the NTFS ACL (Windows)
//	--timeout DURATION              overall deadline, positive, at most 1h (default 2m)
func runJourneys(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("journeys", flag.ContinueOnError)
	server := fs.String("server", "", "exact Soundpost server base URL")
	org := fs.String("org", "", "organization ID")
	project := fs.String("project", "", "project ID")
	expectedPath := fs.String("expected", "", "private expected links JSON")
	grantPath := fs.String("authorization", "", "private read-only grant JSON")
	output := fs.String("private-output", "", "external private directory")
	summaryPath := fs.String("public-summary", "", "new public summary file")
	bearerEnv := fs.String("bearer-env", "SOUNDPOST_JOURNEY_BEARER", "environment variable holding the bearer token")
	acl := fs.Bool("private-directory-acl-confirmed", false, "operator verified restrictive NTFS ACL")
	timeout := fs.Duration("timeout", 2*time.Minute, "overall operator deadline (positive, at most 1h)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || !nonempty(*server, *org, *project, *expectedPath, *grantPath, *output, *summaryPath, *bearerEnv) {
		return errors.New("usage: adoption journeys --server URL --org ID --project ID --expected FILE --authorization FILE --private-output DIRECTORY --public-summary FILE")
	}
	if *timeout <= 0 || *timeout > time.Hour {
		return errors.New("timeout must be positive and at most 1h")
	}
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	var links ExpectedLinks
	var grant Authorization
	if readInput(*expectedPath, &links) != nil || readInput(*grantPath, &grant) != nil {
		return errors.New("invalid private operator input")
	}
	if err := journeyAuthorize(grant, *server, time.Now().UTC()); err != nil {
		return err
	}
	if links.Frontend != nil && links.Frontend.MapFile != "" {
		raw, err := journeyLoadMap(links.Frontend.MapFile)
		if err != nil {
			return errors.New("local build map unreadable")
		}
		links.Frontend.MapBytes = raw
	}
	resolved, err := privateDirectory(ctx, *output, nil, *acl)
	if err != nil {
		return err
	}
	report, err := VerifyJourneys(ctx, JourneyTargets{ServerURL: *server, Bearer: os.Getenv(*bearerEnv), Org: *org, Project: *project}, links)
	if err != nil {
		if ctx.Err() != nil {
			return errors.New("journey verification cancelled or deadline exceeded")
		}
		return err
	}
	if ctx.Err() != nil {
		return errors.New("journey verification cancelled or deadline exceeded")
	}
	if err := writeExclusive(filepath.Join(resolved, "journeys.json"), report); err != nil {
		return errors.New("private output creation failed")
	}
	if err := writeExclusive(*summaryPath, JourneyPublicProjection(report)); err != nil {
		return errors.New("summary creation failed; private evidence retained")
	}
	if !report.Passed {
		return fmt.Errorf("journey acceptance failed: %d of %d sections did not pass", journeyFailedSections(report), len(report.Results))
	}
	return nil
}

func journeyFailedSections(report JourneyReport) int {
	n := 0
	for _, res := range report.Results {
		if res.Status != JourneyPassed {
			n++
		}
	}
	return n
}
