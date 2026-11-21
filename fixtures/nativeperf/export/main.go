//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/ingest"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/nativeperf"
	"github.com/arynyklas/soundpost/internal/policy"
	"github.com/arynyklas/soundpost/internal/profiles"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"syscall"
	"time"
	"unsafe"
)

type privateConfig struct {
	BackendDir         string            `json:"backend_dir"`
	SourceCredential   string            `json:"source_credential"`
	ReaderToken        string            `json:"reader_token"`
	ForeignReaderToken string            `json:"foreign_reader_token"`
	AdminToken         string            `json:"admin_token"`
	Org                model.ID          `json:"org_id"`
	Project            model.ID          `json:"project_id"`
	ForeignOrg         model.ID          `json:"foreign_org_id"`
	ForeignProject     model.ID          `json:"foreign_project_id"`
	Source             model.ID          `json:"source_id"`
	Producer           model.ID          `json:"producer_id"`
	Resource           model.Resource    `json:"resource"`
	Revision           model.Revision    `json:"policy_revision"`
	Target             nativeperf.Target `json:"target"`
	CAFile             string            `json:"ca_file,omitempty"`
}
type fixtureResult struct {
	Samples                    int               `json:"genuine_cpu_samples"`
	CPU                        nativeperf.Status `json:"cpu"`
	Scheduler                  nativeperf.Status `json:"scheduler"`
	Runqueue                   nativeperf.Status `json:"runqueue_split"`
	Units                      string            `json:"count_units"`
	PeriodUnit                 string            `json:"period_unit"`
	Visible                    bool              `json:"authorized_profile_visible"`
	ScopeDenied                bool              `json:"foreign_scope_denied"`
	ReaderRevoked              bool              `json:"reader_revocation_denied"`
	ReaderRevokedHTTP          bool              `json:"reader_revocation_http_denied"`
	ReaderRevocationExercised  bool              `json:"reader_revocation_exercised"`
	Historical                 bool              `json:"identical_historical_receipt_after_restriction"`
	ProfileDeleteExercised     bool              `json:"profile_delete_exercised"`
	DeleteFence                bool              `json:"profile_unreadable_at_delete_fence"`
	DeleteCompleted            bool              `json:"profile_delete_completed"`
	DeleteGeneration           bool              `json:"delete_generation_advanced"`
	HistoricalAfterDelete      bool              `json:"identical_historical_receipt_after_deletion"`
	NoResurrection             bool              `json:"no_resurrection_after_deletion"`
	RepostStatus               int               `json:"deleted_batch_repost_status,omitempty"`
	SourceDenied               bool              `json:"revoked_source_receipt_denied"`
	SourceDenialCode           model.Code        `json:"source_denial_code,omitempty"`
	HTTPReceipt                bool              `json:"verified_tls_receipt"`
	HTTPReceiptExercised       bool              `json:"verified_tls_receipt_exercised"`
	HTTPProfile                bool              `json:"canonical_http_profile_read"`
	HTTPProfileExercised       bool              `json:"canonical_http_profile_read_exercised"`
	Endpoint                   string            `json:"endpoint_kind,omitempty"`
	SchedulerExercised         bool              `json:"scheduler_exercised"`
	SchedulerIntervalsReadBack bool              `json:"scheduler_intervals_read_back"`
	Stream                     *schedulerStats   `json:"scheduler_stream,omitempty"`
	ReadBack                   *profileSummary   `json:"read_back"`
	HTTPReadBack               *profileSummary   `json:"http_read_back,omitempty"`
	ReadBackEqualsAssembled    bool              `json:"read_back_equals_assembled_profile"`
	Mapping                    string            `json:"mapping_coverage"`
	Symbolication              string            `json:"symbolication"`
}

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func readPrivateConfig(env string) (privateConfig, error) {
	var cfg privateConfig
	path := os.Getenv(env)
	if path == "" {
		return cfg, errors.New("missing_private_native_fixture_config")
	}
	f, e := os.Open(path)
	if e != nil {
		return cfg, errors.New("private_fixture_config_unavailable")
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || st.Size() > 1<<20 {
		return cfg, errors.New("private_fixture_config_permissions_or_budget")
	}
	raw, e := io.ReadAll(io.LimitReader(f, 1<<20+1))
	if e != nil || len(raw) > 1<<20 || model.StrictJSON(raw, &cfg) != nil {
		return cfg, errors.New("private_fixture_config_invalid")
	}
	if cfg.BackendDir == "" || cfg.SourceCredential == "" || cfg.ReaderToken == "" || cfg.Org == (model.ID{}) || cfg.Project == (model.ID{}) || cfg.Source == (model.ID{}) || cfg.Producer == (model.ID{}) || cfg.Revision == 0 || cfg.Target.Validate() != nil || cfg.Target.CgroupID == 0 || len(cfg.Target.AllowedBuildIDs) == 0 {
		return cfg, errors.New("private_fixture_config_incomplete")
	}
	return cfg, nil
}
func monoNow() (model.MonoNano, error) {
	var ts syscall.Timespec
	_, _, errno := syscall.Syscall(syscall.SYS_CLOCK_GETTIME, 1, uintptr(unsafe.Pointer(&ts)), 0)
	if errno != 0 || ts.Sec < 0 || ts.Nsec < 0 {
		return 0, errors.New("clock_mapping_unavailable")
	}
	return model.MonoNano(uint64(ts.Sec)*1000000000 + uint64(ts.Nsec)), nil
}
func clockMapping(producer model.ID) (model.TraceClock, error) {
	first, e := monoNow()
	if e != nil {
		return model.TraceClock{}, e
	}
	wall := model.UnixNano(time.Now().UnixNano())
	last, e := monoNow()
	if e != nil || last < first {
		return model.TraceClock{}, errors.New("clock_mapping_unavailable")
	}
	return model.TraceClock{Wall: wall, Mono: first, Domain: model.ClockDomain{Runtime: producer}, Uncertainty: last - first}, nil
}
func fixedClockID(label, value string) model.ID {
	h := sha256.Sum256([]byte("soundpost-native-clock-v1\x00" + label + "\x00" + value))
	var id model.ID
	copy(id[:], h[:])
	return id
}
func frameRead(c *net.UnixConn, v any) error {
	var length [4]byte
	if _, e := io.ReadFull(c, length[:]); e != nil {
		return e
	}
	n := binary.BigEndian.Uint32(length[:])
	if n == 0 || n > 64<<10 {
		return errors.New("invalid_helper_frame")
	}
	payload := make([]byte, n)
	if _, e := io.ReadFull(c, payload); e != nil {
		return e
	}
	return json.Unmarshal(payload, v)
}
func frameWrite(c *net.UnixConn, v any) error {
	payload, e := json.Marshal(v)
	if e != nil {
		return e
	}
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(payload)))
	if _, e = c.Write(length[:]); e != nil {
		return e
	}
	_, e = c.Write(payload)
	return e
}

type realCapture struct {
	Events       []nativeperf.SanitizedEvent
	Intervals    []nativeperf.Interval
	Mappings     []nativeperf.MappingTable
	Reservation  nativeperf.WorkingReservation
	Domain       nativeperf.ClockDomain
	Scheduler    schedulerStats
	Source       *nativeperf.ProfileSource
	Clock        model.TraceClock
	Capabilities nativeperf.Capabilities
	close        func()
}

func acquire(ctx context.Context, cfg privateConfig, scheduler bool) (realCapture, error) {
	var result realCapture
	probeTarget := cfg.Target
	probeTarget.CgroupID = 0 // exact task permission probe, not a wider collector selector
	caps, probeErr := nativeperf.Probe(ctx, []nativeperf.Target{probeTarget})
	if caps.CPU != nativeperf.Supported {
		return result, errors.New("real_cpu_probe_refused")
	}
	if scheduler && caps.OffCPU != nativeperf.Supported {
		return result, errors.New("real_scheduler_probe_refused")
	}
	if probeErr != nil && caps.OffCPU == nativeperf.Supported {
		return result, errors.New("real_probe_failed")
	}
	result.Capabilities = caps
	public, private, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return result, errors.New("fixture_operator_key_unavailable")
	}
	c := nativeperf.DefaultConfig(cfg.Revision)
	targets := []nativeperf.Target{cfg.Target}
	mode := nativeperf.ModeCPU
	if scheduler {
		mode = nativeperf.ModeCPUOffCPU
	}
	signed, e := nativeperf.SignStart(nativeperf.StartAuthorization{Installation: "public-native-export-fixture", UID: uint32(os.Getuid()), Revision: uint64(cfg.Revision), Expires: time.Now().Add(90 * time.Second).Unix(), Targets: targets, Config: c, Mode: mode}, private)
	if e != nil {
		return result, e
	}
	directory, e := os.MkdirTemp("", "soundpost-native-export-")
	if e != nil {
		return result, errors.New("fixture_socket_unavailable")
	}
	listener, e := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(directory, "acquire.sock"), Net: "unix"})
	if e != nil {
		os.RemoveAll(directory)
		return result, errors.New("fixture_socket_unavailable")
	}
	if e = os.Chmod(listener.Addr().String(), 0600); e != nil {
		listener.Close()
		os.RemoveAll(directory)
		return result, errors.New("fixture_socket_policy_failed")
	}
	helperCtx, cancel := context.WithCancel(ctx)
	active := make(chan *nativeperf.ProfileSource, 1)
	helper := nativeperf.Helper{Policy: nativeperf.OperatorPolicy{Installation: "public-native-export-fixture", UID: uint32(os.Getuid()), Revision: uint64(cfg.Revision), PublicKey: public, Allowlist: targets}, Budget: nativeperf.NewResourceBudget(), Acquire: func(ctx context.Context, a nativeperf.AuthorizedTargets, c nativeperf.Config, r *nativeperf.Reservation) (nativeperf.EventSource, error) {
		p := nativeperf.DefaultSymbolPolicy(uint64(c.PolicyRevision))
		p.AllowMappedELF = true
		s, e := nativeperf.NewProfileAcquisition(ctx, a, c, r, p)
		if e != nil {
			return nil, e
		}
		active <- s
		return s, nil
	}}
	helperDone := make(chan struct{})
	go func() { helper.Serve(helperCtx, listener); close(helperDone) }()
	conn, e := net.DialUnix("unix", nil, listener.Addr().(*net.UnixAddr))
	if e != nil {
		cancel()
		listener.Close()
		<-helperDone
		os.RemoveAll(directory)
		return result, errors.New("fixture_helper_connect_failed")
	}
	cleanup := func() { conn.Close(); cancel(); listener.Close(); <-helperDone; os.RemoveAll(directory) }
	fail := func(e error) (realCapture, error) { cleanup(); return realCapture{}, e }
	clock, e := clockMapping(cfg.Producer)
	if e != nil {
		return fail(e)
	}
	result.Clock = clock
	if e = frameWrite(conn, nativeperf.CaptureRequest{Authorization: signed, Targets: targets, Config: c, Mode: mode}); e != nil {
		return fail(errors.New("fixture_capture_request_failed"))
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var ready struct {
		Ready bool   `json:"ready"`
		Error string `json:"error"`
	}
	if e = frameRead(conn, &ready); e != nil || !ready.Ready || ready.Error != "" {
		if ready.Error != "" {
			return fail(errors.New("real_native_acquisition_refused:" + ready.Error))
		}
		return fail(errors.New("real_native_acquisition_refused"))
	}
	select {
	case result.Source = <-active:
	case <-ctx.Done():
		return fail(errors.New("real_native_setup_missing"))
	}
	// Input and output share the already reserved 8MiB assembly working set.
	// A bounded finite observation window is not a scheduler drain/final proof.
	if scheduler {
		if e = readScheduler(conn, c, &result); e != nil {
			return fail(e)
		}
		result.Reservation = fixtureLease{}
	} else {
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		for len(result.Events) < 128 {
			var reply struct {
				Event *nativeperf.SanitizedEvent `json:"event"`
				Error string                     `json:"error"`
			}
			e = frameRead(conn, &reply)
			if e != nil {
				if n, ok := e.(net.Error); ok && n.Timeout() {
					break
				}
				return fail(errors.New("real_capture_transport_failed"))
			}
			if reply.Error != "" || reply.Event == nil || reply.Event.Validate() != nil {
				return fail(errors.New("real_capture_refused_or_invalid"))
			}
			result.Events = append(result.Events, *reply.Event)
		}
	}
	if !scheduler {
		result.Mappings, result.Reservation = result.Source.FramesMappings(), result.Source.ExportReservation()
	}
	if len(result.Events) == 0 {
		return fail(errors.New("no_genuine_cpu_observations"))
	}
	for _, event := range result.Events {
		if event.Domain.HostID != "" && event.Domain.BootID != "" {
			result.Domain = event.Domain
			break
		}
	}
	if result.Domain.HostID == "" || result.Domain.BootID == "" {
		return fail(errors.New("no_clock_domain_in_the_capture"))
	}
	result.Clock.Domain.Host = fixedClockID("host", result.Domain.HostID)
	result.Clock.Domain.Boot = fixedClockID("boot", result.Domain.BootID)
	result.close = cleanup
	return result, nil
}

type loseReceipt struct {
	actual        *ingest.Service
	enabled, lost bool
	original      model.Receipt
	batch         model.Batch
}

func (l *loseReceipt) Admit(ctx context.Context, g policy.SourceGrant, b model.Batch) (model.Receipt, error) {
	r, e := l.actual.Admit(ctx, g, b)
	if e != nil {
		return r, e
	}
	if l.enabled && !l.lost {
		for _, row := range b.Records {
			if row.Kind == model.Profile {
				l.lost = true
				l.original = r
				l.batch = b
				return model.Receipt{}, errors.New("fixture_lost_durable_response")
			}
		}
	}
	return r, nil
}

type actualLookup struct {
	service    *ingest.Service
	credential auth.SourceCredential
}

func (l actualLookup) LookupReceipt(ctx context.Context, q model.ReceiptRequest) (model.Receipt, error) {
	return l.service.LookupReceipt(ctx, l.credential, q)
}
func canonicalEqual(a, b model.Receipt) bool {
	a.Historical = false
	b.Historical = false
	x, e := model.CanonicalJSON(a)
	if e != nil {
		return false
	}
	y, e := model.CanonicalJSON(b)
	return e == nil && bytes.Equal(x, y)
}
func countReservations(ctx context.Context, app *appcore.App) (int, error) {
	n := 0
	e := app.Control.View(ctx, func(st model.ControlState) error { n = len(st.Reservations); return nil })
	return n, e
}
func sourceConfigGrant(ctx context.Context, app *appcore.App, cfg privateConfig) (auth.SourceCredential, policy.SourceGrant, error) {
	credential, e := app.Auth.AuthenticateSource(ctx, cfg.SourceCredential, "", false)
	if e != nil {
		return credential, policy.SourceGrant{}, e
	}
	p, e := policy.New(app.Auth, nil)
	if e != nil {
		return credential, policy.SourceGrant{}, e
	}
	g, e := p.ResolveSource(ctx, credential, cfg.Project, cfg.Source, cfg.Revision)
	return credential, g, e
}
func authorizedReader(ctx context.Context, app *appcore.App, token string, org, project model.ID) (auth.Scope, error) {
	credential, e := app.Auth.Authenticate(ctx, token)
	if e != nil {
		return auth.Scope{}, e
	}
	return app.Auth.Authorize(ctx, credential, org, []model.ID{project}, auth.Permission("profiles.read"))
}
func verifyHTTPReceipt(ctx context.Context, endpoint, caFile, sourceKey string, q model.ReceiptRequest, want model.Receipt) error {
	u, e := url.Parse(endpoint)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return errors.New("fixture_endpoint_must_be_verified_https")
	}
	client, e := verifiedClient(caFile)
	if e != nil {
		return e
	}
	raw, _ := json.Marshal(q)
	u.Path = "/ingest/v1/receipts"
	u.RawQuery = ""
	u.Fragment = ""
	request, e := http.NewRequestWithContext(ctx, "POST", u.String(), bytes.NewReader(raw))
	if e != nil {
		return errors.New("fixture_receipt_request_invalid")
	}
	request.Header.Set("Authorization", "Bearer "+sourceKey)
	request.Header.Set("Content-Type", "application/json")
	response, e := client.Do(request)
	if e != nil {
		return errors.New("verified_tls_receipt_unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return errors.New("verified_tls_receipt_denied_or_missing")
	}
	var got model.Receipt
	b, e := io.ReadAll(io.LimitReader(response.Body, 64<<10+1))
	if e != nil || len(b) > 64<<10 || model.StrictJSON(b, &got) != nil || !got.Historical || !canonicalEqual(got, want) {
		return errors.New("verified_tls_receipt_mismatch")
	}
	return nil
}

// readerBearer is the bearer credential of the canonical HTTP profile read: the
// configured reader token when it already is a server token, else a server token
// the fixture administrator issues to the same reader principal.
func readerBearer(ctx context.Context, app *appcore.App, cfg privateConfig, reader auth.Scope) (string, error) {
	credential, e := app.Auth.Authenticate(ctx, cfg.ReaderToken)
	if e == nil && credential.IsServerToken() {
		return cfg.ReaderToken, nil
	}
	admin, e := app.Auth.Authenticate(ctx, cfg.AdminToken)
	if e != nil {
		return "", errors.New("fixture_admin_denied")
	}
	issued, e := app.Auth.IssueServerToken(ctx, admin, cfg.Org, reader.PrincipalID(), []model.ID{cfg.Project}, []auth.Permission{"profiles.read"}, time.Now().Add(time.Hour).Unix(), "disposable native export fixture reader bearer token")
	if e != nil {
		return "", errors.New("fixture_reader_bearer_issue_denied")
	}
	return issued.Token, nil
}

func setReaderGrant(ctx context.Context, app *appcore.App, cfg privateConfig, reader auth.Scope, enabled bool) error {
	admin, e := app.Auth.Authenticate(ctx, cfg.AdminToken)
	if e != nil {
		return errors.New("fixture_admin_denied")
	}
	var rev model.Revision
	if e = app.Control.View(ctx, func(st model.ControlState) error { rev = st.Revision; return nil }); e != nil {
		return errors.New("fixture_control_revision_unavailable")
	}
	payload := auth.AdminPayload{UserID: reader.PrincipalID(), ProjectID: cfg.Project, Enabled: enabled, Reason: "disposable native fixture reader revocation"}
	if enabled {
		payload.Reason = "disposable native fixture reader grant restored after the revocation check"
		payload.Permissions = []string{"profiles.read"}
	}
	raw, _ := json.Marshal(payload)
	if _, e = app.Auth.AdminCommand(ctx, admin, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: rev, OrgID: cfg.Org, Kind: "grant", Payload: raw}); e != nil {
		return errors.New("real_reader_grant_change_failed")
	}
	return nil
}

func isNotFound(e error) bool {
	var fault *model.Fault
	return errors.As(e, &fault) && fault.Code == model.NotFound
}

func run() error {
	configEnv := flag.String("config-env", "SOUNDPOST_NATIVE_EXPORT_CONFIG", "environment variable naming a private 0600 JSON config file")
	endpointEnv := flag.String("endpoint-env", "SOUNDPOST_FIXTURE_API", "environment variable naming a verified HTTPS endpoint that serves this same backend; when unset the fixture serves the product's real HTTP routes itself over TLS with a private CA it generates")
	targetPID := flag.Int("target-pid", 0, "exact private-config authorized process")
	scopeDenial := flag.Bool("verify-scope-denial", false, "require real foreign reader denial")
	revocation := flag.Bool("verify-revocation", false, "revoke disposable fixture reader project grant between two pages (and over HTTP when --require-http-profile-read), then restore it")
	historical := flag.Bool("verify-historical-restriction", false, "lose durable receipt then restrict fixture source policy")
	deletion := flag.Bool("verify-historical-policy-delete", false, "lose the durable receipt, restrict the source policy, then run the product's real profile deletion and require the identical historical receipt, an unreadable profile and no resurrection")
	revokedReceipt := flag.Bool("verify-revoked-receipt", false, "revoke disposable fixture source and require receipt403")
	httpProbe := flag.Bool("probe-receipts-http", false, "verify identical receipt through the actual HTTPS C03 receipt route (after any deletion)")
	requireProfileHTTP := flag.Bool("require-http-profile-read", false, "read the export back through the canonical POST /api/v1/profiles/view over verified TLS and require it to equal the C05 read")
	scheduler := flag.Bool("scheduler", false, "acquire CPU and scheduler evidence, correlate it per session and require the off-CPU/runqueue intervals to read back with their units, loss and coverage")
	flag.Parse()
	cfg, e := readPrivateConfig(*configEnv)
	if e != nil {
		return e
	}
	if *targetPID <= 0 || uint32(*targetPID) != cfg.Target.TGID {
		return errors.New("target_pid_must_match_private_operator_config")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	// The helper charges this process's resident memory (it is the exporter peer) against its
	// 64 MiB acquisition budget when it starts, so acquisition runs before the backend is opened.
	captured, e := acquire(ctx, cfg, *scheduler)
	if e != nil {
		return e
	}
	defer captured.close()
	app, e := appcore.Open(cfg.BackendDir)
	if e != nil {
		return errors.New("dedicated_fixture_backend_unavailable_or_running")
	}
	defer app.Close()
	credential, _, e := sourceConfigGrant(ctx, app, cfg)
	if e != nil {
		return errors.New("current_fixture_source_authority_denied")
	}
	reader, e := authorizedReader(ctx, app, cfg.ReaderToken, cfg.Org, cfg.Project)
	if e != nil {
		return errors.New("current_fixture_profile_read_denied")
	}
	now := captured.Clock.Wall
	end := model.UnixNano(time.Now().UnixNano())
	domain := captured.Domain
	capsRow := model.Record{Kind: model.CapabilityKind, Payload: model.Payload{Capability: &model.Capability{}}}
	lossRow := model.Record{Kind: model.Loss, Payload: model.Payload{Loss: &model.LossReport{}}}
	capSlot, _ := model.OwnerSlot(cfg.Org, cfg.Project, cfg.Source, cfg.Producer, capsRow)
	lossSlot, _ := model.OwnerSlot(cfg.Org, cfg.Project, cfg.Source, cfg.Producer, lossRow)
	if lossSlot > capSlot {
		capSlot = lossSlot
	}
	root := model.NewID()
	for n := range 4096 {
		row := model.Record{Kind: model.Profile, Payload: model.Payload{Profile: &model.ProfileChunk{Profile: root}}}
		slot, e := model.OwnerSlot(cfg.Org, cfg.Project, cfg.Source, cfg.Producer, row)
		if e != nil {
			return errors.New("fixture_profile_route_invalid")
		}
		if slot >= capSlot {
			break
		}
		root = model.NewID()
		if n == 4095 {
			return errors.New("fixture_profile_route_ordering_unavailable")
		}
	}
	limits := nativeperf.ProfileLimits{Profile: root, Process: model.NewID(), Capability: model.NewID(), Domain: domain, PolicyRevision: cfg.Revision, Sequence: 1, Start: now, End: end, Clock: captured.Clock, Complete: false, MaxBytes: 8 << 20, MaxSamples: 8192, MaxIntervals: 8192, MaxFrames: 4096, MaxStacks: 4096, Mappings: append([]nativeperf.MappingTable(nil), captured.Mappings...)}
	lose := &loseReceipt{actual: app.Ingest, enabled: *historical || *deletion || *revokedReceipt}
	exporter, e := nativeperf.NewExporter(lose, actualLookup{app.Ingest, credential}, nativeperf.ExportConfig{Project: cfg.Project, Source: cfg.Source, Producer: cfg.Producer, Resource: cfg.Resource, Limits: limits, Capabilities: captured.Capabilities}, captured.Reservation)
	if e != nil {
		switch reservation := captured.Reservation; {
		case captured.Capabilities.Validate() != nil:
			return errors.New("native_export_capabilities_invalid")
		case reservation == nil || reservation.Bytes() < 2<<20:
			return errors.New("native_export_reservation_unavailable")
		}
		return errors.New("native_export_limits_invalid")
	}
	defer exporter.Close()
	input := nativeperf.ProfileChunk{ProfileID: root, PolicyRevision: cfg.Revision, Domain: domain, Events: captured.Events, Intervals: captured.Intervals}
	assembledLimits := limits
	assembledLimits.Mappings = append([]nativeperf.MappingTable(nil), captured.Mappings...)
	assembled, e := nativeperf.AssembleProfile(ctx, input.Events, input.Intervals, captured.Capabilities, assembledLimits)
	if e != nil {
		return errors.New("native_assembly_failed: " + e.Error())
	}
	_, grant, e := sourceConfigGrant(ctx, app, cfg)
	if e != nil {
		return errors.New("current_fixture_source_grant_denied")
	}
	receipt, e := exporter.Send(ctx, grant, input)
	if lose.enabled {
		if e == nil || !lose.lost || exporter.Stats().Admitted {
			return errors.New("ambiguous_export_was_incorrectly_acked")
		}
	} else if e != nil {
		return errors.New("real_native_export_failed")
	}
	service := app.NewNativeProfiles()
	w := profiles.Window{Start: now, End: end + 1, MaxSamples: 512}
	readService := func(scope auth.Scope) (profileSummary, error) {
		return readAllPages(func(cursor string) (profiles.ProfileView, error) {
			page := w
			page.Cursor = cursor
			return service.Read(ctx, scope, root, page)
		})
	}
	summary, e := readService(reader)
	if e != nil || summary.Samples == 0 || len(summary.Capabilities) != 3 {
		return errors.New("real_native_profile_not_visible")
	}
	if summary.NativeBad != 0 {
		return errors.New("native_period_or_unit_lost")
	}
	if !summary.sameContent(summarizeChunk(assembled)) {
		return errors.New("read_back_differs_from_assembled_profile")
	}
	result := fixtureResult{Samples: summary.Samples, CPU: captured.Capabilities.CPU, Scheduler: captured.Capabilities.OffCPU, Runqueue: captured.Capabilities.RunqueueSplit, Units: summary.SampleUnits, PeriodUnit: summary.PeriodUnit, Visible: true, ReadBack: &summary, ReadBackEqualsAssembled: true, Mapping: "unresolved_pending_mapping_epoch_proof", Symbolication: "artifact_backend_unavailable"}
	if *scheduler {
		stream := captured.Scheduler
		result.SchedulerExercised, result.Stream = true, &stream
		if !stream.FinalProof || summary.Intervals == 0 || !summary.IntervalUnitsOK || summary.Capabilities["native_offcpu"] != string(nativeperf.Supported) || summary.Capabilities["native_runqueue_split"] != string(captured.Capabilities.RunqueueSplit) {
			return errors.New("scheduler_intervals_not_read_back")
		}
		if !summary.ThreadsDisjoint || summary.Threads == 0 {
			return errors.New("scheduler_intervals_overlap_within_a_thread_or_name_no_thread")
		}
		result.SchedulerIntervalsReadBack = true
	}
	var node *tlsNode
	defer func() { node.close() }()
	endpointFor := func() (string, string, error) {
		if external := os.Getenv(*endpointEnv); external != "" {
			result.Endpoint = "external_endpoint_from_" + *endpointEnv
			return external, cfg.CAFile, nil
		}
		if node == nil {
			started, e := startTLSNode(app)
			if e != nil {
				return "", "", e
			}
			node = started
		}
		result.Endpoint = "in_process_real_http_routes_over_tls_with_private_ca"
		return node.URL, node.CAFile, nil
	}
	if *scopeDenial {
		foreign, e := authorizedReader(ctx, app, cfg.ForeignReaderToken, cfg.ForeignOrg, cfg.ForeignProject)
		if e != nil {
			return errors.New("foreign_fixture_reader_setup_denied")
		}
		_, denied := service.Read(ctx, foreign, root, w)
		_, missing := service.Read(ctx, foreign, model.NewID(), w)
		var a, b *model.Fault
		if !errors.As(denied, &a) || !errors.As(missing, &b) || a.Code != model.NotFound || a.Code != b.Code {
			return errors.New("foreign_profile_denial_not_indistinguishable")
		}
		result.ScopeDenied = true
	}
	var httpReader *profileHTTP
	if *requireProfileHTTP {
		endpoint, ca, e := endpointFor()
		if e != nil {
			return e
		}
		client, e := verifiedClient(ca)
		if e != nil {
			return e
		}
		token, e := readerBearer(ctx, app, cfg, reader)
		if e != nil {
			return e
		}
		httpReader = &profileHTTP{client: client, endpoint: endpoint, token: token, org: cfg.Org, project: cfg.Project, profile: root, start: now, end: end + 1, max: 512}
		over, e := readAllPages(httpReader.page(ctx))
		if e != nil {
			return e
		}
		if !over.sameContent(summary) {
			return errors.New("http_profile_read_differs_from_c05_read")
		}
		for _, state := range httpReader.States {
			if state != "ready" && state != "incomplete" {
				return errors.New("http_profile_read_state_not_ready_or_incomplete")
			}
		}
		if node != nil {
			// Verified TLS is real: a client that trusts only the system roots must refuse the node.
			system, e := verifiedClient("")
			if e != nil {
				return e
			}
			probe := &profileHTTP{client: system, endpoint: endpoint, token: token, org: cfg.Org, project: cfg.Project, profile: root, start: now, end: end + 1, max: 1}
			if status, _, perr := probe.post(ctx, ""); perr == nil || status != 0 {
				return errors.New("tls_not_verified_a_client_without_the_ca_reached_the_route")
			}
		}
		result.HTTPReadBack, result.HTTPProfile, result.HTTPProfileExercised = &over, true, true
	}
	if *revocation {
		reader, e = authorizedReader(ctx, app, cfg.ReaderToken, cfg.Org, cfg.Project)
		if e != nil {
			return errors.New("pre_revocation_reader_unavailable")
		}
		w.MaxSamples = 1
		first, e := service.Read(ctx, reader, root, w)
		if e != nil || first.NextCursor == "" {
			return errors.New("revocation_fixture_requires_next_chunk")
		}
		httpCursor := ""
		if httpReader != nil {
			httpReader.max = 1
			status, raw, e := httpReader.post(ctx, "")
			var page httpapi.ProfileResponse
			if e != nil || status != http.StatusOK || model.StrictJSON(raw, &page) != nil || page.View == nil || page.View.NextCursor == "" {
				return errors.New("revocation_fixture_requires_next_http_page")
			}
			httpCursor = page.View.NextCursor
		}
		w.Cursor = first.NextCursor
		if e = setReaderGrant(ctx, app, cfg, reader, false); e != nil {
			return e
		}
		if _, e = service.Read(ctx, reader, root, w); e == nil {
			return errors.New("revoked_reader_released_next_chunk")
		}
		// A scope stale for any administrative change is not proof that the GRANT is gone: a fresh
		// authorization of the same principal, and a fresh first page over HTTP, must be denied too.
		if _, e = authorizedReader(ctx, app, cfg.ReaderToken, cfg.Org, cfg.Project); e == nil {
			return errors.New("revoked_reader_still_authorized_for_a_fresh_scope")
		}
		if httpReader != nil {
			status, raw, e := httpReader.post(ctx, httpCursor)
			if e != nil || status == http.StatusOK || bytes.Contains(raw, []byte(`"samples"`)) {
				return errors.New("revoked_reader_released_next_http_page")
			}
			status, raw, e = httpReader.post(ctx, "")
			if e != nil || status == http.StatusOK || bytes.Contains(raw, []byte(`"samples"`)) {
				return errors.New("revoked_reader_read_a_fresh_page_over_http")
			}
			result.ReaderRevokedHTTP = true
		}
		result.ReaderRevoked, result.ReaderRevocationExercised = true, true
		// The disposable grant is restored so the deletion checks below can read as the same reader.
		if e = setReaderGrant(ctx, app, cfg, reader, true); e != nil {
			return e
		}
		w.Cursor, w.MaxSamples = "", 512
		if httpReader != nil {
			httpReader.max = 512
		}
		if reader, e = authorizedReader(ctx, app, cfg.ReaderToken, cfg.Org, cfg.Project); e != nil {
			return errors.New("post_revocation_reader_restore_failed")
		}
		again, e := readService(reader)
		if e != nil || !again.sameContent(summary) {
			return errors.New("restored_reader_cannot_read_the_profile")
		}
	}
	if lose.enabled {
		admin, e := app.Auth.Authenticate(ctx, cfg.AdminToken)
		if e != nil {
			return errors.New("fixture_admin_denied")
		}
		source, e := app.Auth.SourceAuthority(ctx, credential, true)
		if e != nil {
			return errors.New("fixture_source_policy_unavailable")
		}
		next := source.Policy
		next.Revision++
		next.Enabled = false
		if _, e = app.Auth.ChangeSourcePolicy(ctx, admin, auth.SourcePolicyChange{CommandID: model.NewID(), Source: cfg.Source, ExpectedRevision: source.Policy.Revision, Policy: next, Reason: "disposable native export fixture restriction"}); e != nil {
			return errors.New("real_source_policy_restriction_failed")
		}
		if e = app.Auth.DrainSourceFences(ctx); e != nil {
			return errors.New("real_source_policy_barrier_failed")
		}
		before, e := countReservations(ctx, app)
		if e != nil {
			return errors.New("fixture_reservation_read_failed")
		}
		receipt, e = exporter.Send(ctx, grant, input)
		if e != nil || !receipt.Historical || !canonicalEqual(receipt, lose.original) {
			return errors.New("historical_receipt_changed_or_missing")
		}
		after, e := countReservations(ctx, app)
		if e != nil || after != before {
			return errors.New("historical_lookup_created_admission")
		}
		result.Historical = true
	}
	if *deletion {
		admin, e := app.Auth.Authenticate(ctx, cfg.AdminToken)
		if e != nil {
			return errors.New("fixture_admin_denied")
		}
		unreadable := func() (bool, error) {
			scope, e := authorizedReader(ctx, app, cfg.ReaderToken, cfg.Org, cfg.Project)
			if e != nil {
				return false, errors.New("fixture_reader_unavailable_for_deletion_check")
			}
			if _, e = service.Read(ctx, scope, root, w); !isNotFound(e) {
				return false, nil
			}
			if httpReader != nil {
				status, raw, e := httpReader.post(ctx, "")
				if e != nil || status != http.StatusNotFound || bytes.Contains(raw, []byte(`"samples"`)) {
					return false, nil
				}
			}
			return true, nil
		}
		deleted, e := deleteProfile(ctx, app, admin, cfg, root, unreadable)
		if e != nil {
			return e
		}
		if !deleted.FenceUnreadable {
			return errors.New("profile_readable_at_the_deletion_fence")
		}
		if !deleted.Completed || !deleted.GenerationAdvanced {
			return errors.New("real_profile_deletion_incomplete_or_generation_not_advanced")
		}
		if gone, e := unreadable(); e != nil || !gone {
			return errors.New("deleted_profile_still_readable")
		}
		before, e := countReservations(ctx, app)
		if e != nil {
			return errors.New("fixture_reservation_read_failed")
		}
		receipt, e = exporter.Send(ctx, grant, input)
		if e != nil || !receipt.Historical || !canonicalEqual(receipt, lose.original) {
			return errors.New("historical_receipt_changed_or_missing_after_deletion")
		}
		if after, e := countReservations(ctx, app); e != nil || after != before {
			return errors.New("historical_lookup_after_deletion_created_admission")
		}
		result.HistoricalAfterDelete = true
		// Nothing is resurrected: the committed batch bytes re-posted through the real route
		// neither bring the profile back nor reserve anything.
		endpoint, ca, e := endpointFor()
		if e != nil {
			return e
		}
		client, e := verifiedClient(ca)
		if e != nil {
			return e
		}
		status, body, e := postSourceBatch(ctx, client, endpoint, cfg.SourceCredential, lose.batch)
		if e != nil {
			return e
		}
		if status == http.StatusOK {
			var again model.Receipt
			if model.StrictJSON(body, &again) != nil || !canonicalEqual(again, lose.original) {
				return errors.New("repost_of_deleted_batch_answered_a_different_receipt")
			}
		}
		if after, e := countReservations(ctx, app); e != nil || after != before {
			return errors.New("repost_of_deleted_batch_reserved_quota")
		}
		if gone, e := unreadable(); e != nil || !gone {
			return errors.New("repost_of_deleted_batch_resurrected_the_profile")
		}
		result.ProfileDeleteExercised, result.DeleteFence, result.DeleteCompleted, result.DeleteGeneration = true, deleted.FenceUnreadable, deleted.Completed, deleted.GenerationAdvanced
		result.NoResurrection, result.RepostStatus = true, status
	}
	if *httpProbe {
		endpoint, ca, e := endpointFor()
		if e != nil {
			return e
		}
		if e = verifyHTTPReceipt(ctx, endpoint, ca, cfg.SourceCredential, exporter.LastReceiptRequest(), receipt); e != nil {
			return e
		}
		result.HTTPReceipt, result.HTTPReceiptExercised = true, true
	}
	var finalError error
	if *revokedReceipt {
		admin, e := app.Auth.Authenticate(ctx, cfg.AdminToken)
		if e != nil {
			return errors.New("fixture_admin_denied")
		}
		if e = app.Auth.RevokeSource(ctx, admin, cfg.Source, "disposable native fixture source revocation"); e != nil {
			return errors.New("real_source_revocation_failed")
		}
		_, e = app.Ingest.LookupReceipt(ctx, credential, exporter.LastReceiptRequest())
		var denied *model.Fault
		if !errors.As(e, &denied) {
			return errors.New("revoked_source_retrieved_historical_receipt")
		}
		result.SourceDenialCode = denied.Code
		if denied.Code != model.Forbidden {
			finalError = errors.New("revoked_receipt_status_not_required_403")
		} else {
			result.SourceDenied = true
		}
	}
	if e = json.NewEncoder(os.Stdout).Encode(result); e != nil {
		return errors.New("fixture_result_output_failed")
	}
	return finalError
}
