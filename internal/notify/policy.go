// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"math"
	"math/bits"
	"slices"
	"sort"

	"github.com/arynyklas/soundpost/internal/model"
)

// NewState starts the policy state of one notification subject. The subject
// is the first canonical owner; OwnerRevision starts at 1.
func NewState(org, project, policy model.ID, subject Entity) (PolicyState, error) {
	if org == (model.ID{}) || project == (model.ID{}) || policy == (model.ID{}) || !subject.valid() {
		return PolicyState{}, refuse(model.Invalid, ReasonInvalidState)
	}
	s := PolicyState{
		Org: org, Project: project, Policy: policy,
		Subject: subject, Owner: subject, OwnerRevision: 1, Linked: []Entity{subject},
		Mode: ModeActive, Source: SourceUnknown, SourceFresh: FreshnessUnknown, Human: HumanOpen,
		Tier: TierNone, Explanation: Explanation{Basis: BasisNone, Rate: RateNotApplicable},
	}
	s.QueueKey = s.queueKey()
	return s, nil
}

// Decide is the one canonical policy reducer. It is pure and deterministic:
// the same state, event and time always give the same state and intents, no
// clock is read and nothing is sent. The argument is never modified.
//
// On any refusal (typed *Error) it returns the original state and no intents,
// so a mismatched owner revision, a stale policy revision, an entity that is
// not linked and every malformed event fail closed.
//
// Intents are emitted in a deterministic order. Replaying an event that was
// already applied returns an unchanged state and no intents, and every intent
// carries the stable C08 key, so an outbox that sees one twice deduplicates it.
func Decide(state PolicyState, event PolicyEvent, at model.UnixNano) (PolicyState, []Intent, error) {
	r := &run{s: state.clone(), ev: event, at: at}
	if err := r.apply(); err != nil {
		return state, nil, err
	}
	return r.s, r.finish(), nil
}

type run struct {
	s   PolicyState
	ev  PolicyEvent
	at  model.UnixNano
	out []Intent

	// driving: the evidence came from the canonical owner and decides.
	driving bool
	// newCritical: a critical service was newly affected by this event.
	newCritical bool
	// wantImpact is the owner's own impact revision for an incident owner.
	wantImpact uint64
	// prevSource and adopted are the incident revision and adoption flag
	// before this event.
	prevSource uint64
	adopted    bool
}

func (r *run) apply() error {
	s, ev := &r.s, r.ev
	if err := validState(s); err != nil {
		return err
	}
	if r.at <= 0 {
		return refuse(model.Invalid, ReasonTimeRange)
	}
	if err := validEnvelope(s, ev); err != nil {
		return err
	}
	// A replayed cutover is a no-op even though the revision has advanced.
	if ev.Kind == EventCutover && s.LastCutover != nil && *s.LastCutover == ev.Cutover.Command {
		return nil
	}
	if err := r.adoptPolicy(); err != nil {
		return err
	}
	if ev.OwnerRevision != s.OwnerRevision {
		return refuse(model.Conflict, ReasonOwnerRevision)
	}
	if err := r.checkEntity(); err != nil {
		return err
	}
	if ev.Cursor != nil {
		if err := r.observeCursor(*ev.Cursor); err != nil {
			return err
		}
	}
	r.expire()
	before := r.snapshot()
	var err error
	switch ev.Kind {
	case EventIssue:
		err = r.issueEvidence()
	case EventCondition:
		err = r.conditionEvidence()
	case EventIncident:
		err = r.incidentEvidence()
	case EventAction:
		err = r.humanAction()
	case EventTimer:
		err = r.timer()
	case EventDestination:
		err = r.destination()
	case EventCutover:
		err = r.cutover()
	}
	if err != nil {
		return err
	}
	return r.settle(before)
}

func validState(s *PolicyState) error {
	switch {
	case s.Org == (model.ID{}), s.Project == (model.ID{}), s.Policy == (model.ID{}),
		!s.Subject.valid(), !s.Owner.valid(), s.OwnerRevision == 0,
		s.Mode != ModeActive && s.Mode != ModeShadow,
		!slices.Contains(s.Linked, s.Owner), len(s.Linked) > MaxLinked,
		len(s.Windows) > MaxWindows, len(s.Recipients) > MaxRecipients,
		len(s.Sent) > MaxSentMarks, len(s.Cursors) > MaxCursors:
		return refuse(model.Invalid, ReasonInvalidState)
	}
	for _, w := range s.Windows {
		if len(w.Occurrences) > MaxWindowOccurrences {
			return refuse(model.Invalid, ReasonInvalidState)
		}
	}
	return nil
}

func validEnvelope(s *PolicyState, ev PolicyEvent) error {
	if ev.Command == (model.ID{}) || ev.Org != s.Org || ev.Project != s.Project || ev.Policy != s.Policy {
		return refuse(model.Invalid, ReasonScope)
	}
	n := 0
	for _, present := range []bool{ev.Issue != nil, ev.Condition != nil, ev.Incident != nil, ev.Action != nil, ev.Timer != nil, ev.Destination != nil, ev.Cutover != nil} {
		if present {
			n++
		}
	}
	ok := n == 1
	switch ev.Kind {
	case EventIssue:
		ok = ok && ev.Issue != nil
	case EventCondition:
		ok = ok && ev.Condition != nil
	case EventIncident:
		ok = ok && ev.Incident != nil
	case EventAction:
		ok = ok && ev.Action != nil
	case EventTimer:
		ok = ok && ev.Timer != nil
	case EventDestination:
		ok = ok && ev.Destination != nil
	case EventCutover:
		ok = ok && ev.Cutover != nil
	default:
		ok = false
	}
	switch ev.Mode {
	case "", ModeLive, ModeBackfill, ModeOperatorReplay:
	default:
		ok = false
	}
	if !ok {
		return refuse(model.Invalid, ReasonInvalidEvent)
	}
	return nil
}

// adoptPolicy applies the scoped policy revision. An older revision is
// refused; a newer one must carry its config.
func (r *run) adoptPolicy() error {
	s, p := &r.s, r.ev.PolicyRef
	switch {
	case p.Revision == 0:
		return refuse(model.Invalid, ReasonInvalidEvent)
	case p.Revision < s.PolicyRevision:
		return refuse(model.Stale, ReasonPolicyStale)
	case p.Revision == s.PolicyRevision:
		if p.Config != nil && !configEqual(*p.Config, s.Config) {
			return refuse(model.Conflict, ReasonPolicyConflict)
		}
		return nil
	}
	if p.Config == nil {
		return refuse(model.Invalid, ReasonPolicyConfig)
	}
	if err := p.Config.validate(); err != nil {
		return err
	}
	zoneChanged := p.Config.DefaultZone != s.Config.DefaultZone
	s.Config = p.Config.clone()
	s.PolicyRevision = p.Revision
	// A changed default zone moves the digests of the recipients that use it.
	// Recipients with their own zone keep their schedule, so a due digest is
	// never skipped by an unrelated policy revision.
	for i := range s.Recipients {
		if zoneChanged && s.Recipients[i].Enabled && s.Recipients[i].Zone == "" {
			next, err := NextDigest(r.at, s.Config.DefaultZone)
			if err != nil {
				return err
			}
			s.Recipients[i].DigestNext = next
		}
	}
	return nil
}

func (c Config) validate() error {
	if c.MinOperations == 0 || c.MinFailures == 0 || c.RateBasisPoints == 0 || c.RateBasisPoints > 10000 || c.RegressionMin == 0 ||
		c.FirstReminder <= 0 || c.ReminderEvery <= 0 || c.MaxSuppression <= 0 || c.MaxSuppression > MaxSuppressionHard ||
		len(c.CriticalCodes) > MaxCriticalCodes {
		return refuse(model.Invalid, ReasonPolicyConfig)
	}
	for i, code := range c.CriticalCodes {
		if !safeName(code) || (i > 0 && c.CriticalCodes[i-1] >= code) {
			return refuse(model.Invalid, ReasonPolicyConfig)
		}
	}
	if _, err := location(c.DefaultZone); err != nil {
		return err
	}
	return nil
}

func configEqual(a, b Config) bool {
	return a.MinOperations == b.MinOperations && a.MinFailures == b.MinFailures && a.RateBasisPoints == b.RateBasisPoints &&
		a.RegressionMin == b.RegressionMin && slices.Equal(a.CriticalCodes, b.CriticalCodes) && a.FirstReminder == b.FirstReminder &&
		a.ReminderEvery == b.ReminderEvery && a.MaxSuppression == b.MaxSuppression && a.DefaultZone == b.DefaultZone
}

func (s *PolicyState) effectiveZone(r Recipient) string {
	if r.Zone != "" {
		return r.Zone
	}
	return s.Config.DefaultZone
}

// checkEntity enforces the one-owner rule: evidence and actions must name an
// entity linked to this state, and each evidence kind comes from its own
// entity kind. Only the canonical owner decides.
func (r *run) checkEntity() error {
	s, ev := &r.s, r.ev
	switch ev.Kind {
	case EventTimer, EventDestination:
		return nil
	}
	if ev.Entity == nil || !ev.Entity.valid() {
		return refuse(model.Invalid, ReasonInvalidEvent)
	}
	if ev.Kind == EventCutover {
		if *ev.Entity != s.Owner {
			return refuse(model.Conflict, ReasonOwnerRevision)
		}
		return nil
	}
	if !slices.Contains(s.Linked, *ev.Entity) {
		return refuse(model.Forbidden, ReasonNotLinked)
	}
	want := map[EventKind]EntityKind{EventIssue: EntityIssue, EventCondition: EntityCondition, EventIncident: EntityIncident}[ev.Kind]
	if want != "" && ev.Entity.Kind != want {
		return refuse(model.Invalid, ReasonInvalidEvent)
	}
	r.driving = *ev.Entity == s.Owner
	return nil
}

func (r *run) observeCursor(c model.Cursor) error {
	if c.Group == (model.ID{}) {
		return refuse(model.Invalid, ReasonInvalidEvent)
	}
	s := &r.s
	for i := range s.Cursors {
		if s.Cursors[i].Group == c.Group {
			if c.Index > s.Cursors[i].Index {
				s.Cursors[i].Index = c.Index
			}
			return nil
		}
	}
	if len(s.Cursors) >= MaxCursors {
		return refuse(model.Quota, ReasonQuota)
	}
	s.Cursors = append(s.Cursors, c)
	sort.Slice(s.Cursors, func(i, j int) bool { return bytes.Compare(s.Cursors[i].Group[:], s.Cursors[j].Group[:]) < 0 })
	return nil
}

// expire removes windows that ended before this event. Removal is the single
// exact-expiry transition: a replayed timer finds nothing to expire.
func (r *run) expire() {
	s := &r.s
	if w := s.Snooze; w != nil && r.at >= w.Until {
		s.SnoozeEnded = max(s.SnoozeEnded, w.Version)
		s.Snooze = nil
	}
	if w := s.Maintenance; w != nil && r.at >= w.Until {
		s.MaintenanceEnded = max(s.MaintenanceEnded, w.Version)
		s.Maintenance = nil
	}
}

type snapshot struct {
	human  HumanStatus
	source SourceState
	tier   Tier
	owner  Entity
}

func (r *run) snapshot() snapshot {
	s := &r.s
	return snapshot{human: s.Human, source: s.Source, tier: s.Tier, owner: s.Owner}
}

// ---- time arithmetic ----

func addNano(a, b model.UnixNano) (model.UnixNano, bool) {
	if (b > 0 && a > math.MaxInt64-b) || (b < 0 && a < math.MinInt64-b) {
		return 0, false
	}
	return a + b, true
}

func mulNano(a, k model.UnixNano) (model.UnixNano, bool) {
	if a < 0 || k < 0 {
		return 0, false
	}
	hi, lo := bits.Mul64(uint64(a), uint64(k))
	if hi != 0 || lo > math.MaxInt64 {
		return 0, false
	}
	return model.UnixNano(lo), true
}

// ---- evidence ----

func (r *run) late(mode Mode) {
	s := &r.s
	if mode == ModeBackfill {
		s.Backfilled = satAdd(s.Backfilled)
		return
	}
	s.Late = satAdd(s.Late)
}

func satAdd(v uint32) uint32 {
	if v == math.MaxUint32 {
		return v
	}
	return v + 1
}

func (e *IssueEvidence) validate() error {
	bad := e.WindowStart < 0 || e.WindowStart%ErrorWindow != 0 || !e.Freshness.valid() || len(e.Occurrences) > MaxEventOccurrences ||
		(e.Code != "" && (!safeName(e.Code) || len(e.Occurrences) == 0))
	for _, id := range e.Occurrences {
		bad = bad || id == (model.ID{})
	}
	if d := e.Denominator; d != nil {
		bad = bad || !safeName(d.Name) || d.WindowStart < 0
	}
	if g := e.Regression; g != nil {
		bad = bad || (g.Occurrences == 0 && g.Eligible) || (!g.Eligible && g.Occurrences != 0)
	}
	if v := e.Service; v != nil {
		bad = bad || v.ID == (model.ID{})
	}
	if bad {
		return refuse(model.Invalid, ReasonInvalidEvent)
	}
	return nil
}

func (r *run) mode() Mode {
	if r.ev.Mode == "" {
		return ModeLive
	}
	return r.ev.Mode
}

func (r *run) issueEvidence() error {
	s, e := &r.s, r.ev.Issue
	if err := e.validate(); err != nil {
		return err
	}
	end, ok := addNano(e.WindowStart, ErrorWindow)
	if !ok {
		return refuse(model.Invalid, ReasonTimeRange)
	}
	if horizon, ok := addNano(r.at, ErrorWindow); !ok || e.WindowStart > horizon {
		return refuse(model.Invalid, ReasonInvalidEvent)
	}
	mode := r.mode()
	if mode == ModeBackfill {
		r.late(mode)
		return nil
	}
	if limit, ok := addNano(end, LateAfter); mode == ModeLive && (!ok || r.at > limit) {
		r.late(mode)
		return nil
	}
	i := slices.IndexFunc(s.Windows, func(w WindowState) bool { return w.Start == e.WindowStart })
	if i < 0 {
		if len(s.Windows) == MaxWindows && e.WindowStart < s.Windows[0].Start {
			r.late(mode)
			return nil
		}
		s.Windows = append(s.Windows, WindowState{Start: e.WindowStart, Freshness: FreshnessFresh})
		sort.Slice(s.Windows, func(a, b int) bool { return s.Windows[a].Start < s.Windows[b].Start })
		if len(s.Windows) > MaxWindows {
			s.Windows = s.Windows[1:]
		}
		i = slices.IndexFunc(s.Windows, func(w WindowState) bool { return w.Start == e.WindowStart })
	}
	w := &s.Windows[i]
	w.merge(e, s.Config)
	if e.Service != nil {
		if err := r.service(*e.Service); err != nil {
			return err
		}
	}
	if !r.driving {
		return nil
	}
	// A qualifying reopen starts a new episode of a resolved issue.
	if s.Human == HumanResolved {
		if g := e.Regression; g != nil && g.Reopened {
			r.newEpisode()
			s.Human = HumanOpen
		} else {
			return nil // late history after resolution: recorded, not decided
		}
	}
	r.assessWindows()
	return nil
}

// merge folds one batch into the window. The merge is commutative and
// associative: the same batches in any order yield an identical window.
func (w *WindowState) merge(e *IssueEvidence, cfg Config) {
	if len(e.Occurrences) > 0 {
		all := append(append([]model.ID(nil), w.Occurrences...), e.Occurrences...)
		slices.SortFunc(all, func(a, b model.ID) int { return bytes.Compare(a[:], b[:]) })
		all = slices.Compact(all)
		if len(all) > MaxWindowOccurrences {
			all, w.Saturated = all[:MaxWindowOccurrences], true
		}
		w.Occurrences = all
	}
	if e.Code != "" && cfg.critical(e.Code) {
		w.Critical = true
	}
	w.Freshness = w.Freshness.worse(e.Freshness)
	if d := e.Denominator; d != nil {
		w.mergeDenominator(*d)
	}
	if g := e.Regression; g != nil {
		w.mergeRegression(*g)
	}
}

func (w *WindowState) mergeDenominator(d Denominator) {
	if d.WindowStart != w.Start {
		w.DenominatorMismatch = true
		return
	}
	cur := w.Denominator
	switch {
	case cur == nil:
		w.Denominator = &d
	case *cur == d:
	case cur.Complete && d.Complete:
		w.DenominatorConflict = true
	case d.Complete:
		w.Denominator = &d
	case cur.Complete:
	default: // both incomplete: keep the larger, then the smaller name
		if d.Operations > cur.Operations || (d.Operations == cur.Operations && d.Name < cur.Name) {
			w.Denominator = &d
		}
	}
}

func (w *WindowState) mergeRegression(g Regression) {
	if w.Regression == nil {
		w.Regression = &g
		return
	}
	c := w.Regression
	c.Eligible = c.Eligible || g.Eligible
	c.Occurrences = max(c.Occurrences, g.Occurrences)
	c.Reopened = c.Reopened || g.Reopened
	c.AncestryKnown = c.AncestryKnown && g.AncestryKnown
}

type assessment struct {
	tier Tier
	sev  Severity
	exp  Explanation
}

// assess applies the default urgency rule to one window: urgent on an
// approved critical code, or a qualifying regression with enough
// occurrences, or (enough operations AND enough deduplicated failures AND a
// high enough rate). A rate needs a complete named denominator for exactly
// this window and fresh data; otherwise it is unknown, never a percentage,
// and the other evidence still counts.
func assess(cfg Config, w WindowState) assessment {
	failures := uint32(len(w.Occurrences))
	exp := Explanation{Basis: BasisNone, Rate: RateNoDenominator, Failures: failures, Saturated: w.Saturated}
	if w.Regression != nil {
		g := *w.Regression
		exp.Regression = &g
	}
	rateRule := false
	switch d := w.Denominator; {
	case w.Freshness != FreshnessFresh:
		exp.Rate = RateStale
	case w.DenominatorConflict:
		exp.Rate = RateConflict
	case d == nil && w.DenominatorMismatch:
		exp.Rate = RateWindowMismatch
	case d == nil:
		exp.Rate = RateNoDenominator
	case !d.Complete:
		exp.Rate = RateIncomplete
	case uint64(failures) > uint64(d.Operations):
		exp.Rate = RateInconsistent
	default:
		exp.Rate = RateKnown
		exp.Operations = d.Operations
		if d.Operations > 0 {
			exp.RateBasisPoints = uint32(uint64(failures) * 10000 / uint64(d.Operations))
			hi, lo := bits.Mul64(uint64(d.Operations), uint64(cfg.RateBasisPoints))
			rateRule = uint64(d.Operations) >= uint64(cfg.MinOperations) && failures >= cfg.MinFailures &&
				hi == 0 && uint64(failures)*10000 >= lo
		}
	}
	regression := w.Regression != nil && w.Regression.Eligible && w.Regression.Occurrences >= cfg.RegressionMin
	switch {
	case w.Critical:
		exp.Basis = BasisCriticalCode
		return assessment{TierUrgent, SeverityCritical, exp}
	case regression:
		exp.Basis = BasisRegression
		return assessment{TierUrgent, SeverityMajor, exp}
	case rateRule:
		exp.Basis = BasisErrorRate
		return assessment{TierUrgent, SeverityMajor, exp}
	case w.Regression != nil && w.Regression.Eligible:
		exp.Basis = BasisRegression
		return assessment{TierQueue, SeverityMinor, exp}
	case failures > 0:
		exp.Basis = BasisCount
		return assessment{TierQueue, SeverityMinor, exp}
	}
	return assessment{TierNone, SeverityNone, exp}
}

// assessWindows sets the current tier, severity and explanation from the
// worst retained window, which is independent of the order batches arrived.
func (r *run) assessWindows() {
	s := &r.s
	var best assessment
	have := false
	for _, w := range s.Windows {
		a := assess(s.Config, w)
		if !have || a.tier.rank() > best.tier.rank() || (a.tier.rank() == best.tier.rank() && a.sev >= best.sev) {
			best, have = a, true
		}
	}
	if !have {
		return
	}
	s.Tier, s.Severity, s.Explanation = best.tier, best.sev, best.exp
	if best.tier != TierNone {
		s.Source = SourceFiring
		s.SourceFresh = s.windowFreshness()
	}
}

func (s *PolicyState) windowFreshness() Freshness {
	f := FreshnessFresh
	for _, w := range s.Windows {
		f = f.worse(w.Freshness)
	}
	return f
}

// service tracks the affected service; a newly affected critical service is a
// material impact change.
func (r *run) service(v ServiceRef) error {
	s := &r.s
	if !r.driving {
		return nil
	}
	if s.Service == nil || bytes.Compare(v.ID[:], s.Service.ID[:]) < 0 {
		c := v
		s.Service = &c
	} else if s.Service.ID == v.ID && v.Critical {
		s.Service.Critical = true
	}
	if v.Critical && !slices.Contains(s.CriticalServices, v.ID) {
		if len(s.CriticalServices) >= MaxCriticalServices {
			return refuse(model.Quota, ReasonQuota)
		}
		s.CriticalServices = append(s.CriticalServices, v.ID)
		slices.SortFunc(s.CriticalServices, func(a, b model.ID) int { return bytes.Compare(a[:], b[:]) })
		r.newCritical = true
	}
	return nil
}

// newEpisode closes the current episode so the next urgent evidence opens a
// new one. Impact revisions never go backwards.
func (r *run) newEpisode() {
	s := &r.s
	s.EpisodeOpen = false
	s.PeakSeverity = SeverityNone
	s.CriticalServices = nil
	s.Reminders = Reminders{}
	s.Pending = false
	s.Worse = 0
	s.Recoveries = 0
}

func (r *run) sourceFrom(state SourceState, fresh Freshness) {
	s := &r.s
	s.SourceFresh = fresh
	switch state {
	case SourceFiring:
		s.Source = SourceFiring
	case SourceRecovered:
		// Only fresh data can recover; stale or unknown never does.
		if fresh == FreshnessFresh {
			s.Source = SourceRecovered
		}
	default:
		if s.Source == "" {
			s.Source = SourceUnknown
		}
	}
}

func (e *ConditionEvidence) validate() error {
	ok := e.Seq > 0 && e.Episode != (model.ID{}) && e.Freshness.valid() && e.Severity.valid() &&
		(e.State == SourceFiring || e.State == SourceRecovered || e.State == SourceUnknown) &&
		(e.Service == nil || e.Service.ID != (model.ID{}))
	if !ok {
		return refuse(model.Invalid, ReasonInvalidEvent)
	}
	return nil
}

func (r *run) conditionEvidence() error {
	s, e := &r.s, r.ev.Condition
	if err := e.validate(); err != nil {
		return err
	}
	if r.mode() == ModeBackfill {
		r.late(ModeBackfill)
		return nil
	}
	if e.Seq == s.ConditionSeq {
		return nil // an exact replay
	}
	if e.Seq < s.ConditionSeq {
		r.late(r.mode())
		return nil
	}
	s.ConditionSeq = e.Seq
	if !r.driving {
		return nil
	}
	if s.EpisodeRef != nil && *s.EpisodeRef != e.Episode {
		r.newEpisode()
		s.Human = HumanOpen
		s.Source = SourceUnknown
	}
	ref := e.Episode
	s.EpisodeRef = &ref
	if e.Service != nil {
		if err := r.service(*e.Service); err != nil {
			return err
		}
	}
	r.sourceFrom(e.State, e.Freshness)
	if s.Source == SourceFiring {
		s.Severity = e.Severity
		s.Tier = TierQueue
		if e.Severity >= SeverityMajor {
			s.Tier = TierUrgent
		}
	} else if s.Source == SourceRecovered {
		s.Tier, s.Severity = TierNone, SeverityNone
	}
	s.Explanation = Explanation{Basis: BasisCondition, Rate: RateNotApplicable}
	return nil
}

func (e *IncidentEvidence) validate() error {
	ok := e.Version > 0 && e.ImpactRevision > 0 && e.Episode != (model.ID{}) && e.Freshness.valid() && e.Severity.valid() && e.Severity != SeverityNone &&
		(e.Status == HumanOpen || e.Status == HumanResolved) &&
		(e.Source == SourceFiring || e.Source == SourceRecovered || e.Source == SourceUnknown) &&
		(e.Service == nil || e.Service.ID != (model.ID{}))
	if !ok {
		return refuse(model.Invalid, ReasonInvalidEvent)
	}
	return nil
}

func (r *run) incidentEvidence() error {
	s, e := &r.s, r.ev.Incident
	if err := e.validate(); err != nil {
		return err
	}
	if r.mode() == ModeBackfill {
		r.late(ModeBackfill)
		return nil
	}
	if e.Version == s.IncidentVersion {
		return nil
	}
	if e.Version < s.IncidentVersion {
		r.late(r.mode())
		return nil
	}
	s.IncidentVersion = e.Version
	if !r.driving {
		return nil
	}
	adopting := s.Adopt && s.EpisodeOpen
	if !adopting && s.EpisodeRef != nil && *s.EpisodeRef != e.Episode {
		r.newEpisode()
	}
	ref := e.Episode
	s.EpisodeRef = &ref
	r.wantImpact = e.ImpactRevision
	if e.Service != nil {
		if err := r.service(*e.Service); err != nil {
			return err
		}
	}
	// A human resolution is final for an incident: a later snapshot cannot
	// reopen it (a new episode is a new, linked incident).
	if s.Human != HumanResolved {
		s.Human = e.Status
	}
	r.sourceFrom(e.Source, e.Freshness)
	s.Severity = e.Severity
	s.Tier = TierUrgent
	s.Explanation = Explanation{Basis: BasisIncident, Rate: RateNotApplicable}
	return nil
}

// ---- human actions ----

func (a *HumanAction) validate() error {
	ok := a.Actor != (model.ID{})
	switch a.Type {
	case ActionAck:
		ok = ok && a.ImpactRevision > 0
	case ActionResolve:
	case ActionSnooze, ActionMaintenance:
		ok = ok && safeReason(a.Reason) && a.Until > 0 && a.Scope.valid()
	case ActionUnsnooze, ActionMaintenanceEnd:
		ok = ok && a.Version > 0
	default:
		ok = false
	}
	if a.Type == ActionSnooze || a.Type == ActionMaintenance {
		ok = ok && a.Version > 0
	}
	if !ok {
		return refuse(model.Invalid, ReasonInvalidEvent)
	}
	return nil
}

func (sc Scope) valid() bool {
	switch sc.Kind {
	case ScopeEntity, ScopeProject:
		return sc.Service == nil
	case ScopeService:
		return sc.Service != nil && *sc.Service != (model.ID{})
	}
	return false
}

func (s *PolicyState) applies(sc Scope) bool {
	if sc.Kind != ScopeService {
		return true
	}
	if s.Service != nil && s.Service.ID == *sc.Service {
		return true
	}
	return slices.Contains(s.CriticalServices, *sc.Service)
}

func (r *run) humanAction() error {
	s, a := &r.s, r.ev.Action
	if err := a.validate(); err != nil {
		return err
	}
	switch a.Type {
	case ActionAck:
		// ACK and resolution belong to the canonical owner: the same action on
		// a linked, non-owning entity is recorded by that entity, not here.
		if r.driving && (s.Ack == nil || a.ImpactRevision > s.Ack.ImpactRevision) {
			s.Ack = &Ack{Actor: a.Actor, At: r.at, ImpactRevision: a.ImpactRevision}
		}
	case ActionResolve:
		if r.driving {
			s.Human = HumanResolved
		}
	case ActionSnooze:
		return r.window(&s.Snooze, &s.SnoozeEnded, a)
	case ActionMaintenance:
		return r.window(&s.Maintenance, &s.MaintenanceEnded, a)
	case ActionUnsnooze:
		r.endWindow(&s.Snooze, &s.SnoozeEnded, a.Version)
	case ActionMaintenanceEnd:
		r.endWindow(&s.Maintenance, &s.MaintenanceEnded, a.Version)
	}
	return nil
}

// window starts a snooze or maintenance window. A window that does not apply
// to this state, that already expired, that an equal or newer version
// replaced, or that a newer end already cancelled is a no-op, so replays and
// reordering are harmless.
func (r *run) window(slot **Window, ended *model.Revision, a *HumanAction) error {
	s := &r.s
	if !s.applies(a.Scope) || (a.Scope.Kind == ScopeEntity && !r.driving) {
		return nil
	}
	if a.Until <= r.at {
		return nil
	}
	if a.Until-r.at > s.Config.MaxSuppression {
		return refuse(model.Invalid, ReasonInvalidEvent)
	}
	if a.Version <= *ended || (*slot != nil && a.Version <= (*slot).Version) {
		return nil
	}
	sc := a.Scope
	if sc.Service != nil {
		v := *sc.Service
		sc.Service = &v
	}
	*slot = &Window{Scope: sc, Actor: a.Actor, Reason: a.Reason, From: r.at, Until: a.Until, Version: a.Version}
	return nil
}

func (r *run) endWindow(slot **Window, ended *model.Revision, version model.Revision) {
	if *slot != nil && (*slot).Scope.Kind == ScopeEntity && !r.driving {
		return
	}
	if *slot != nil && version > (*slot).Version {
		*slot = nil
	}
	if version > *ended && *slot == nil {
		*ended = version
	}
}

// ---- timer, destinations, cutover ----

func (r *run) timer() error {
	s := &r.s
	// Reminders: at most one per timer, for the latest slot that is due, then
	// the schedule moves past the decision time.
	if s.EpisodeOpen && s.Human == HumanOpen && s.Source != SourceRecovered && s.Reminders.Next > 0 && r.at >= s.Reminders.Next {
		switch {
		case s.Mode == ModeShadow || s.Maintenance != nil || s.Snooze != nil:
			s.Pending = true
		case s.Pending:
			// The suppression ended on this very timer: the single current-state
			// update that settle emits stands in for the reminder.
		case s.acked():
		default:
			skipped := (r.at - s.Reminders.Next) / s.Config.ReminderEvery
			step, ok := mulNano(skipped+1, s.Config.ReminderEvery)
			if !ok {
				return refuse(model.Invalid, ReasonTimeRange)
			}
			next, ok := addNano(s.Reminders.Next, step)
			if !ok {
				return refuse(model.Invalid, ReasonTimeRange)
			}
			s.Reminders.Sent++
			s.Reminders.Next = next
			t := r.template()
			t.Reminder = s.Reminders.Sent
			r.emit(KindReminder, s.ImpactRevision, uint64(s.Reminders.Sent), classReminder, t)
		}
	}
	// Digests: one per recipient per local date per policy revision.
	for i := range s.Recipients {
		rec := &s.Recipients[i]
		if !rec.Enabled || rec.DigestNext <= 0 || r.at < rec.DigestNext {
			continue
		}
		zone := s.effectiveZone(*rec)
		date, err := LocalDate(rec.DigestNext, zone)
		if err != nil {
			return err
		}
		next, err := NextDigest(r.at, zone)
		if err != nil {
			return err
		}
		rec.DigestNext = next
		if r.suppression(classRoutine) != CodeNone || s.Human != HumanOpen || s.Tier != TierQueue || s.EpisodeOpen || s.QueueRevision <= rec.DigestSeen {
			continue
		}
		rec.DigestSeen = s.QueueRevision
		t := r.template()
		t.Digest = &DigestFact{ID: DigestID(s.Org, s.Policy, rec.ID, date, s.PolicyRevision), LocalDate: date, Revision: s.PolicyRevision}
		id := rec.ID
		r.emitTo(KindDigest, s.ImpactRevision, uint64(date), classRoutine, t, &id)
	}
	return nil
}

func (r *run) destination() error {
	s, d := &r.s, r.ev.Destination
	if d.Recipient == (model.ID{}) {
		return refuse(model.Invalid, ReasonInvalidEvent)
	}
	if d.Remove {
		s.Recipients = slices.DeleteFunc(s.Recipients, func(x Recipient) bool { return x.ID == d.Recipient })
		return nil
	}
	if _, err := location(d.Zone); err != nil {
		return err
	}
	i := slices.IndexFunc(s.Recipients, func(x Recipient) bool { return x.ID == d.Recipient })
	if i < 0 {
		if len(s.Recipients) >= MaxRecipients {
			return refuse(model.Quota, ReasonQuota)
		}
		s.Recipients = append(s.Recipients, Recipient{ID: d.Recipient})
		slices.SortFunc(s.Recipients, func(a, b Recipient) int { return bytes.Compare(a.ID[:], b.ID[:]) })
		i = slices.IndexFunc(s.Recipients, func(x Recipient) bool { return x.ID == d.Recipient })
	}
	rec := &s.Recipients[i]
	reschedule := !rec.Enabled && d.Enabled || rec.Zone != d.Zone || rec.DigestNext == 0
	rec.Enabled, rec.Zone = d.Enabled, d.Zone
	switch {
	case !rec.Enabled:
		rec.DigestNext = 0
	case reschedule:
		next, err := NextDigest(r.at, s.effectiveZone(*rec))
		if err != nil {
			return err
		}
		rec.DigestNext = next
	}
	return nil
}

func (r *run) cutover() error {
	s, c := &r.s, r.ev.Cutover
	if c.Command == (model.ID{}) || !c.To.valid() || (c.Mode != "" && c.Mode != ModeActive && c.Mode != ModeShadow) {
		return refuse(model.Invalid, ReasonInvalidEvent)
	}
	if c.To != s.Owner {
		if !slices.Contains(s.Linked, c.To) {
			if len(s.Linked) >= MaxLinked {
				return refuse(model.Quota, ReasonQuota)
			}
			s.Linked = append(s.Linked, c.To)
		}
		// Sequence and version spaces belong to the entity that owns them.
		s.Owner = c.To
		s.ConditionSeq, s.IncidentVersion, s.SourceImpact = 0, 0, 0
		s.Adopt = c.To.Kind == EntityIncident && s.EpisodeOpen
	}
	if c.Mode != "" {
		s.Mode = c.Mode
	}
	s.OwnerRevision++
	cmd := c.Command
	s.LastCutover = &cmd
	r.driving = true
	if c.To.Kind == EntityIssue {
		r.assessWindows()
	}
	return nil
}

// ---- settle ----

type class int

const (
	// classOpening is an opening or worse-impact notice: only maintenance and
	// shadow mode suppress it. ACK and snooze never do.
	classOpening class = iota
	// classRoutine is recovery, resolution, current-state and digest: snooze
	// also suppresses it.
	classRoutine
	// classReminder is a reminder.
	classReminder
)

// suppression is the closed reason that currently suppresses a class, if any.
func (r *run) suppression(c class) Code {
	s := &r.s
	switch {
	case s.Mode == ModeShadow:
		return CodeShadow
	case s.Maintenance != nil:
		return CodeMaintenance
	case s.Snooze != nil && c != classOpening:
		return CodeSnoozed
	}
	return CodeNone
}

func (s *PolicyState) ackSpace() uint64 {
	if s.Owner.Kind == EntityIncident {
		return s.SourceImpact
	}
	return s.ImpactRevision
}

// acked reports whether an ACK covers the current impact revision. A worse
// impact has a new revision, so it is never acknowledged in advance.
func (s *PolicyState) acked() bool {
	return s.Ack != nil && s.Ack.ImpactRevision == s.ackSpace() && s.ackSpace() > 0
}

func (s *PolicyState) queueKey() queueKey {
	return queueKey{Tier: s.Tier, Severity: s.Severity, Source: s.Source, Human: s.Human, Owner: s.Owner}
}

func (r *run) nextImpact() uint64 {
	n := r.s.ImpactRevision + 1
	if r.wantImpact > n {
		n = r.wantImpact
	}
	return n
}

// settle turns the state change into intents: resolution, source recovery,
// the one opening per episode, worse impact, the queue update, and at most
// one current-state update when a suppression ended.
func (r *run) settle(before snapshot) error {
	s := &r.s
	incident := s.Owner.Kind == EntityIncident
	r.prevSource, r.adopted = s.SourceImpact, s.Adopt
	if incident && r.driving && r.wantImpact > 0 {
		s.SourceImpact = r.wantImpact
		s.Adopt = false
	}
	if s.Human == HumanResolved && before.human != HumanResolved {
		s.Reminders.Next = 0
		if s.EpisodeOpen {
			r.emit(KindResolution, s.ImpactRevision, s.Episode, classRoutine, r.template())
		}
		s.EpisodeOpen = false
		s.CriticalServices = nil
	}
	if s.Human == HumanOpen {
		switch {
		case s.Source == SourceRecovered && before.source != SourceRecovered && s.EpisodeOpen:
			s.Recoveries++
			s.Reminders.Next = 0
			r.emit(KindRecovery, s.ImpactRevision, s.Recoveries, classRoutine, r.template())
		case s.Tier == TierUrgent:
			if err := r.urgent(before, incident); err != nil {
				return err
			}
		}
	}
	if key := s.queueKey(); key != s.QueueKey {
		s.QueueKey = key
		s.QueueRevision++
		r.emitTo(KindQueue, s.ImpactRevision, s.QueueRevision, classOpening, r.template(), nil)
	}
	return r.flush()
}

func (r *run) urgent(before snapshot, incident bool) error {
	s := &r.s
	if !s.EpisodeOpen {
		s.Episode++
		s.EpisodeOpen = true
		s.ImpactRevision = r.nextImpact()
		s.PeakSeverity = s.Severity
		s.Worse = 0
		s.Recoveries = 0
		s.Adopt = false
		next, ok := addNano(r.at, s.Config.FirstReminder)
		if !ok {
			return refuse(model.Invalid, ReasonTimeRange)
		}
		s.Reminders = Reminders{Next: next}
		r.emit(KindOpen, s.ImpactRevision, s.Episode, classOpening, r.template())
		return nil
	}
	material := s.Severity > s.PeakSeverity || r.newCritical
	if incident && r.driving && r.wantImpact > r.prevSource && !r.adopted {
		material = true
	}
	if s.Severity > s.PeakSeverity {
		s.PeakSeverity = s.Severity
	}
	if material {
		s.ImpactRevision = r.nextImpact()
		s.Worse++
		next, ok := addNano(r.at, s.Config.FirstReminder)
		if !ok {
			return refuse(model.Invalid, ReasonTimeRange)
		}
		s.Reminders.Next = next
		r.emit(KindWorseImpact, s.ImpactRevision, s.Worse, classOpening, r.template())
		return nil
	}
	if before.source == SourceRecovered && s.Source == SourceFiring {
		// The source fired again inside the episode: reminders resume, there is
		// no second opening.
		next, ok := addNano(r.at, s.Config.FirstReminder)
		if !ok {
			return refuse(model.Invalid, ReasonTimeRange)
		}
		s.Reminders.Next = next
	}
	return nil
}

// flush is the exact-expiry reevaluation: when a suppression that held back
// an intent has ended, one current-state update describes the present state.
func (r *run) flush() error {
	s := &r.s
	if !s.Pending || r.suppression(classRoutine) != CodeNone {
		return nil
	}
	s.Pending = false
	s.Updates++
	if s.EpisodeOpen && s.Human == HumanOpen && s.Source != SourceRecovered {
		next, ok := addNano(r.at, s.Config.ReminderEvery)
		if !ok {
			return refuse(model.Invalid, ReasonTimeRange)
		}
		s.Reminders.Next = next
	}
	r.emit(KindCurrent, s.ImpactRevision, s.Updates, classRoutine, r.template())
	return nil
}

// ---- intents ----

func (r *run) template() Template {
	s := &r.s
	t := Template{
		Entity: s.Owner, Tier: s.Tier, Severity: s.Severity, Source: s.Source, Freshness: s.SourceFresh,
		Human: s.Human, Acknowledged: s.acked(), Explanation: s.Explanation, Queue: s.QueueRevision,
	}
	if g := s.Explanation.Regression; g != nil {
		c := *g
		t.Explanation.Regression = &c
	}
	if s.Service != nil {
		c := *s.Service
		t.Service = &c
	}
	return t
}

func (s *PolicyState) enabled() []Recipient {
	var out []Recipient
	for _, rec := range s.Recipients {
		if rec.Enabled {
			out = append(out, rec)
		}
	}
	return out
}

// emit sends one decision to every enabled recipient, or records the missing
// destination as a visible failed intent.
func (r *run) emit(kind Kind, impact, ordinal uint64, c class, t Template) {
	if r.seen(kind, impact, ordinal) {
		return
	}
	recs := r.s.enabled()
	if len(recs) == 0 {
		r.emitTo(kind, impact, ordinal, c, t, nil)
		return
	}
	for _, rec := range recs {
		id := rec.ID
		r.emitTo(kind, impact, ordinal, c, t, &id)
	}
}

// emitTo appends one intent to one recipient (nil: the shared queue, or the
// missing-destination failure).
func (r *run) emitTo(kind Kind, impact, ordinal uint64, c class, t Template, to *model.ID) {
	s := &r.s
	i := Intent{
		Route: routeOf(kind), Disposition: DispositionDeliver, At: r.at, Cause: r.ev.Command, Template: t,
		Key: IntentKey{Org: s.Org, Policy: s.Policy, Entity: s.Owner, ImpactRevision: impact, Kind: kind, Recipient: to, Ordinal: ordinal},
	}
	if kind != KindQueue {
		switch code := r.suppression(c); {
		case code != CodeNone:
			i.Disposition, i.Code = DispositionSuppressed, code
			if kind != KindDigest && kind != KindReminder {
				s.Pending = true
			}
		case to == nil:
			i.Disposition, i.Code = DispositionFailed, CodeNoDestination
		}
	}
	i.ID = KeyID(i.Key)
	if kind != KindDigest {
		s.mark(KindMark{Kind: kind, ImpactRevision: impact, Ordinal: ordinal, Disposition: i.Disposition, Code: i.Code, At: r.at})
	}
	r.out = append(r.out, i)
}

func (r *run) seen(kind Kind, impact, ordinal uint64) bool {
	return slices.ContainsFunc(r.s.Sent, func(m KindMark) bool {
		return m.Kind == kind && m.ImpactRevision == impact && m.Ordinal == ordinal
	})
}

func (s *PolicyState) mark(m KindMark) {
	if slices.ContainsFunc(s.Sent, func(x KindMark) bool {
		return x.Kind == m.Kind && x.ImpactRevision == m.ImpactRevision && x.Ordinal == m.Ordinal
	}) {
		return
	}
	s.Sent = append(s.Sent, m)
	if len(s.Sent) > MaxSentMarks {
		s.Sent = s.Sent[len(s.Sent)-MaxSentMarks:]
	}
}

func kindRank(k Kind) int {
	for i, v := range [...]Kind{KindOpen, KindWorseImpact, KindRecovery, KindResolution, KindCurrent, KindReminder, KindQueue, KindDigest} {
		if k == v {
			return i
		}
	}
	return len(k)
}

func (r *run) finish() []Intent {
	if len(r.out) == 0 {
		return nil
	}
	slices.SortStableFunc(r.out, func(a, b Intent) int {
		if c := kindRank(a.Key.Kind) - kindRank(b.Key.Kind); c != 0 {
			return c
		}
		if c := bytes.Compare(recipientBytes(a.Key.Recipient), recipientBytes(b.Key.Recipient)); c != 0 {
			return c
		}
		return bytes.Compare(a.ID[:], b.ID[:])
	})
	return slices.CompactFunc(r.out, func(a, b Intent) bool { return a.ID == b.ID })
}

func recipientBytes(id *model.ID) []byte {
	if id == nil {
		return nil
	}
	return id[:]
}

// KeyID is the stable intent identity: a hash of the C08 key, so the same
// decision always has the same ID and a replay is idempotent.
func KeyID(k IntentKey) model.ID {
	h := sha256.New()
	h.Write([]byte("soundpost.notify.intent.v1\x00"))
	h.Write(k.Org[:])
	h.Write(k.Policy[:])
	h.Write([]byte(k.Entity.Kind))
	h.Write([]byte{0})
	h.Write(k.Entity.ID[:])
	var n [16]byte
	binary.BigEndian.PutUint64(n[:8], k.ImpactRevision)
	binary.BigEndian.PutUint64(n[8:], k.Ordinal)
	h.Write(n[:])
	h.Write([]byte(k.Kind))
	h.Write([]byte{0})
	if k.Recipient == nil {
		h.Write([]byte{0})
	} else {
		h.Write([]byte{1})
		h.Write(k.Recipient[:])
	}
	return idFrom(h.Sum(nil))
}

// NextDue is the earliest instant at which a Timer event can change this
// state: a due reminder, a snooze or maintenance expiry or a digest. ok is
// false when nothing is scheduled.
func (s PolicyState) NextDue() (model.UnixNano, bool) {
	var due model.UnixNano
	consider := func(t model.UnixNano) {
		if t > 0 && (due == 0 || t < due) {
			due = t
		}
	}
	if s.EpisodeOpen && s.Human == HumanOpen && s.Source != SourceRecovered && !s.acked() {
		consider(s.Reminders.Next)
	}
	if s.Snooze != nil {
		consider(s.Snooze.Until)
	}
	if s.Maintenance != nil {
		consider(s.Maintenance.Until)
	}
	for _, rec := range s.Recipients {
		if rec.Enabled {
			consider(rec.DigestNext)
		}
	}
	return due, due > 0
}

// clone deep-copies the state so Decide never aliases its argument.
func (s PolicyState) clone() PolicyState {
	s.Linked = slices.Clone(s.Linked)
	s.Recipients = slices.Clone(s.Recipients)
	s.Cursors = slices.Clone(s.Cursors)
	s.CriticalServices = slices.Clone(s.CriticalServices)
	s.Sent = slices.Clone(s.Sent)
	s.Config = s.Config.clone()
	s.LastCutover = cloneID(s.LastCutover)
	s.EpisodeRef = cloneID(s.EpisodeRef)
	if s.Service != nil {
		c := *s.Service
		s.Service = &c
	}
	if g := s.Explanation.Regression; g != nil {
		c := *g
		s.Explanation.Regression = &c
	}
	if s.Ack != nil {
		c := *s.Ack
		s.Ack = &c
	}
	s.Snooze = cloneWindow(s.Snooze)
	s.Maintenance = cloneWindow(s.Maintenance)
	ws := make([]WindowState, len(s.Windows))
	for i, w := range s.Windows {
		w.Occurrences = slices.Clone(w.Occurrences)
		if w.Denominator != nil {
			c := *w.Denominator
			w.Denominator = &c
		}
		if w.Regression != nil {
			c := *w.Regression
			w.Regression = &c
		}
		ws[i] = w
	}
	s.Windows = ws
	if len(ws) == 0 {
		s.Windows = nil
	}
	return s
}

func cloneID(id *model.ID) *model.ID {
	if id == nil {
		return nil
	}
	c := *id
	return &c
}

func cloneWindow(w *Window) *Window {
	if w == nil {
		return nil
	}
	c := *w
	if w.Scope.Service != nil {
		v := *w.Scope.Service
		c.Scope.Service = &v
	}
	return &c
}
