//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"time"

	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/profiles"
)

// verifiedClient trusts the system roots plus (when given) the fixture CA file:
// certificate and host verification stay on.
func verifiedClient(caFile string) (*http.Client, error) {
	pool, e := x509.SystemCertPool()
	if e != nil {
		return nil, errors.New("fixture_tls_roots_unavailable")
	}
	if caFile != "" {
		b, e := os.ReadFile(caFile)
		if e != nil || len(b) > 1<<20 || !pool.AppendCertsFromPEM(b) {
			return nil, errors.New("fixture_tls_ca_invalid")
		}
	}
	return &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}}, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("fixture_redirect_denied") }}, nil
}

// profileSummary is what a full read of one profile contains, in the closed
// numeric terms the fixture compares: it carries no stack, frame or path text.
type profileSummary struct {
	Pages             int               `json:"pages"`
	Samples           int               `json:"samples"`
	Intervals         int               `json:"intervals"`
	BlockedIntervals  int               `json:"blocked_intervals"`
	RunnableIntervals int               `json:"runnable_intervals"`
	UnknownIntervals  int               `json:"unknown_offcpu_intervals"`
	CensoredIntervals int               `json:"censored_intervals"`
	BlockedNS         uint64            `json:"blocked_ns"`
	RunnableNS        uint64            `json:"runnable_ns"`
	UnknownNS         uint64            `json:"unknown_offcpu_ns"`
	IntervalUnitsOK   bool              `json:"interval_units_nanoseconds"`
	Threads           int               `json:"threads_with_intervals"`
	ThreadsDisjoint   bool              `json:"per_thread_intervals_disjoint"`
	NativeBad         int               `json:"samples_without_native_period_or_rate"`
	PeriodUnit        string            `json:"period_unit"`
	SampleUnits       string            `json:"sample_units"`
	LossCount         uint64            `json:"loss_count"`
	LossReports       int               `json:"loss_reports"`
	NativeLoss        int               `json:"native_loss_records"`
	Truncated         bool              `json:"truncated"`
	Completeness      string            `json:"completeness"`
	Reasons           []string          `json:"reasons"`
	Capabilities      map[string]string `json:"capability_status"`
	Coverage          map[string]string `json:"capability_coverage"`
}

type pageReader func(cursor string) (profiles.ProfileView, error)

// readAllPages reads one profile page by page through read, folding every page
// into one summary.
func readAllPages(read pageReader) (profileSummary, error) {
	s := profileSummary{IntervalUnitsOK: true, Capabilities: map[string]string{}, Coverage: map[string]string{}}
	spans := map[model.Uint64][][2]model.MonoNano{}
	cursor := ""
	for range 128 {
		view, e := read(cursor)
		if e != nil {
			return s, e
		}
		s.Pages++
		s.Samples += len(view.Samples)
		s.SampleUnits = view.Units
		for _, sample := range view.Samples {
			if !nativeSampleOK(sample) {
				s.NativeBad++
			}
			if s.PeriodUnit == "" && sample.Native != nil {
				s.PeriodUnit = sample.Native.Unit
			}
		}
		for _, i := range view.Intervals {
			s.Intervals++
			if i.Unit != "nanoseconds" || i.End < i.Start {
				s.IntervalUnitsOK = false
			}
			d := uint64(i.End - i.Start)
			switch i.Kind {
			case "blocked":
				s.BlockedIntervals++
				s.BlockedNS += d
			case "runnable":
				s.RunnableIntervals++
				s.RunnableNS += d
			default:
				s.UnknownIntervals++
				s.UnknownNS += d
			}
			if i.Censored {
				s.CensoredIntervals++
			}
			spans[i.Thread] = append(spans[i.Thread], [2]model.MonoNano{i.Start, i.End})
		}
		s.LossCount, s.LossReports, s.NativeLoss = uint64(view.LossCount), len(view.Loss), len(view.NativeLoss)
		s.Truncated = s.Truncated || view.Truncated
		s.Completeness, s.Reasons = view.Completeness, view.Reasons
		for _, c := range view.Capabilities {
			s.Capabilities[c.Value.Method] = c.Value.Status
			s.Coverage[c.Value.Method] = "frames=" + c.Value.Coverage.Frames + ",threads=" + c.Value.Coverage.Threads
		}
		if view.NextCursor == "" {
			s.finishThreads(spans)
			return s, nil
		}
		cursor = view.NextCursor
	}
	return s, errors.New("profile_read_did_not_terminate")
}

// finishThreads checks the physical invariant a scheduler read-back must keep: one thread is in
// one state at a time, so the intervals of a thread never overlap (no double-counted time).
func (s *profileSummary) finishThreads(spans map[model.Uint64][][2]model.MonoNano) {
	s.Threads, s.ThreadsDisjoint = len(spans), true
	for _, list := range spans {
		sort.Slice(list, func(a, b int) bool { return list[a][0] < list[b][0] })
		for i := 1; i < len(list); i++ {
			if list[i][0] < list[i-1][1] {
				s.ThreadsDisjoint = false
			}
		}
	}
}

// summarizeChunk is the same summary taken from the assembled (pre-export) chunk.
func summarizeChunk(c model.ProfileChunk) profileSummary {
	s := profileSummary{IntervalUnitsOK: true, Samples: len(c.Samples), SampleUnits: c.Units}
	for _, sample := range c.Samples {
		if !nativeSampleOK(sample) {
			s.NativeBad++
		}
		if s.PeriodUnit == "" && sample.Native != nil {
			s.PeriodUnit = sample.Native.Unit
		}
	}
	for _, i := range c.Intervals {
		s.Intervals++
		if i.Unit != "nanoseconds" || i.End < i.Start {
			s.IntervalUnitsOK = false
		}
		d := uint64(i.End - i.Start)
		switch i.Kind {
		case "blocked":
			s.BlockedIntervals++
			s.BlockedNS += d
		case "runnable":
			s.RunnableIntervals++
			s.RunnableNS += d
		default:
			s.UnknownIntervals++
			s.UnknownNS += d
		}
		if i.Censored {
			s.CensoredIntervals++
		}
	}
	s.LossCount = uint64(c.Loss)
	s.NativeLoss = len(c.NativeLoss)
	return s
}

// sameContent compares the numeric content two reads (or a read and the
// assembled chunk) must agree on.
func (s profileSummary) sameContent(o profileSummary) bool {
	return s.Samples == o.Samples && s.Intervals == o.Intervals && s.BlockedIntervals == o.BlockedIntervals && s.RunnableIntervals == o.RunnableIntervals && s.UnknownIntervals == o.UnknownIntervals && s.CensoredIntervals == o.CensoredIntervals && s.BlockedNS == o.BlockedNS && s.RunnableNS == o.RunnableNS && s.UnknownNS == o.UnknownNS && s.IntervalUnitsOK == o.IntervalUnitsOK && s.SampleUnits == o.SampleUnits && s.NativeBad == o.NativeBad && s.PeriodUnit == o.PeriodUnit
}

// profileHTTP reads a profile through the canonical POST /api/v1/profiles/view
// route with a bearer server token over verified TLS.
type profileHTTP struct {
	client   *http.Client
	endpoint string
	token    string
	org      model.ID
	project  model.ID
	profile  model.ID
	start    model.UnixNano
	end      model.UnixNano
	max      uint32
	// States collects the response state of every page.
	States []string
}

// post returns the HTTP status and the raw body of one profile view request.
func (p *profileHTTP) post(ctx context.Context, cursor string) (int, []byte, error) {
	body := map[string]any{"org": p.org.String(), "project": p.project.String(), "profile": p.profile.String(), "window": map[string]any{"start": strconv.FormatInt(int64(p.start), 10), "end": strconv.FormatInt(int64(p.end), 10)}, "max_samples": p.max}
	if cursor != "" {
		body["cursor"] = cursor
	}
	raw, e := json.Marshal(body)
	if e != nil {
		return 0, nil, e
	}
	request, e := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint+"/api/v1/profiles/view", bytes.NewReader(raw))
	if e != nil {
		return 0, nil, errors.New("fixture_profile_request_invalid")
	}
	request.Header.Set("Authorization", "Bearer "+p.token)
	request.Header.Set("Content-Type", "application/json")
	response, e := p.client.Do(request)
	if e != nil {
		return 0, nil, errors.New("verified_tls_profile_read_unavailable")
	}
	defer response.Body.Close()
	out, e := io.ReadAll(io.LimitReader(response.Body, 8<<20+1))
	if e != nil || len(out) > 8<<20 {
		return response.StatusCode, nil, errors.New("profile_view_response_unreadable")
	}
	return response.StatusCode, out, nil
}

// page is the pageReader of this transport.
func (p *profileHTTP) page(ctx context.Context) pageReader {
	return func(cursor string) (profiles.ProfileView, error) {
		status, raw, e := p.post(ctx, cursor)
		if e != nil {
			return profiles.ProfileView{}, e
		}
		if status != http.StatusOK {
			return profiles.ProfileView{}, errors.New("profile_view_status_" + strconv.Itoa(status))
		}
		var response httpapi.ProfileResponse
		if model.StrictJSON(raw, &response) != nil || response.View == nil || response.Org != p.org || response.Project != p.project || response.Profile != p.profile {
			return profiles.ProfileView{}, errors.New("profile_view_response_invalid")
		}
		p.States = append(p.States, string(response.State))
		return *response.View, nil
	}
}

// nativeSampleOK is the numeric truth a native CPU sample must keep through
// assembly, storage and read: its period, its requested rate and a count of one.
func nativeSampleOK(s model.ProfileSample) bool {
	return s.Native != nil && s.Native.Period != 0 && s.Native.RequestedHz == 99 && s.Count == 1
}
