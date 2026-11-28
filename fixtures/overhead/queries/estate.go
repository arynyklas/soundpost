// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

const (
	logTemplateID    = "app.event"
	metricUnit       = "1"
	policyCredential = 48 * time.Hour // the SDK sources' credentials outlive the 24 h run and its preload
	ctlMetric        = "ctl_flag"
	ctlSeries        = 4 // the control series the source policy admits beyond the application's
)

func scalar(s string) model.Scalar {
	var v model.Scalar
	if err := json.Unmarshal([]byte(fmt.Sprintf("%q", s)), &v); err != nil {
		panic(err)
	}
	return v
}

// Check says whether the estate can be generated.
func (c Config) Check() error {
	switch {
	case c.Orgs < 1 || c.Projects < c.Orgs || c.Projects%c.Orgs != 0:
		return fmt.Errorf("projects %d must be a positive multiple of orgs %d", c.Projects, c.Orgs)
	case c.RoutesPerProject < 1 || c.RoutesPerProject > 50:
		return fmt.Errorf("routes per project %d out of range", c.RoutesPerProject)
	case c.Projects < 100:
		return fmt.Errorf("the rule classes need at least 100 projects")
	}
	return nil
}

// Project is one source of the estate: identity, signed-policy input and the generator state (ingest role: workload.go).
type Project struct {
	Index    int
	OrgIndex int
	Org      model.ID
	Project  model.ID
	Source   model.ID
	Producer model.ID
	Reader   model.ID // the org's read-only user (same for the org's projects)
	Resource model.Resource
	Policy   model.SourcePolicy

	cfg    Config
	domain model.ClockDomain
	series []seriesDef
	perm   []int
	vals   []float64
	rng    *rand.Rand
	// generator state owned by workload.go
	recSeq, runSeq, traceSeq uint64
	cursor                   int
	carry                    [5]int64
	gen                      genState // preload and trace-continuation state (workload.go)
}

type seriesDef struct {
	name    string
	labels  model.Labels
	counter bool
	slot    uint16
}

// NewProject builds project index p of the estate.
func NewProject(cfg Config, p int) *Project {
	perOrg := cfg.Projects / cfg.Orgs
	pj := &Project{Index: p, OrgIndex: p / perOrg, cfg: cfg}
	pj.Org = ident(cfg.Seed, "org", pj.OrgIndex)
	pj.Project = ident(cfg.Seed, "project", p)
	pj.Source = ident(cfg.Seed, "source", p)
	pj.Producer = ident(cfg.Seed, "producer", p)
	pj.Reader = ident(cfg.Seed, "reader", pj.OrgIndex)
	pj.Resource = model.Resource{Service: ident(cfg.Seed, "service", p), Environment: ident(cfg.Seed, "environment", p), Build: ident(cfg.Seed, "build", p), Instance: "inst-1", Labels: model.Labels{}}
	pj.domain = model.ClockDomain{Host: ident(cfg.Seed, "host", p), Boot: ident(cfg.Seed, "boot", p), Runtime: ident(cfg.Seed, "runtime", p)}
	pj.rng = rand.New(rand.NewPCG(cfg.Seed, uint64(p)+1))
	pj.recSeq, pj.traceSeq, pj.runSeq = cfg.Epoch<<32, cfg.Epoch<<32, cfg.Epoch<<32

	routes := cfg.RoutesPerProject
	labels := map[string][]string{"route": nil}
	for r := 0; r < routes; r++ {
		labels["route"] = append(labels["route"], fmt.Sprintf("r%d", r))
	}
	codes := []model.Scalar{scalar("started"), scalar("retried"), scalar("completed"), scalar("skipped")}
	units := []model.Scalar{scalar("api"), scalar("worker"), scalar("cron")}
	pj.Policy = model.SourcePolicy{
		Revision: 1, Enabled: true, Class: "structured",
		Kinds: []model.Kind{model.Metric, model.Log, model.SpanKind, model.ErrorKind, model.JobAttempt},
		Templates: []model.LogTemplate{{ID: logTemplateID, Revision: 1, Line: "event {code} on {unit}", Severity: "info", Fields: []model.TemplateField{
			{Name: "code", Type: "string", MaxBytes: 64, Sensitivity: "metadata", Values: codes},
			{Name: "unit", Type: "string", MaxBytes: 64, Sensitivity: "metadata", Values: units}}}},
		Resources:  model.ResourceRegistry{Services: []model.ID{pj.Resource.Service}, Environments: []model.ID{pj.Resource.Environment}, Builds: []model.ID{pj.Resource.Build}, Instances: []string{"inst-1"}},
		Labels:     labels,
		Operations: []string{"request", "http.call", "db.execute", "job.run"}, Dependencies: []string{"api", "postgres"}, Codes: []string{"app.timeout", "app.db_error", "app.bad_input"},
		RetentionDays: map[model.Kind]uint32{model.Metric: 14, model.Log: 14, model.SpanKind: 14, model.ErrorKind: 90, model.JobAttempt: 90},
		MaxBytes:      1 << 30, MaxSeries: model.Uint64(cfg.SeriesPerProject() + cfg.SeriesPerProject()/10 + ctlSeries),
	}

	n := cfg.SeriesPerProject()
	pj.series = make([]seriesDef, n)
	pj.vals = make([]float64, n)
	for i := range pj.series {
		name, route := i%MetricNames, i/MetricNames
		def := seriesDef{name: fmt.Sprintf("app_m%d", name), counter: name < MetricNames/2,
			labels: model.Labels{{Name: "route", Value: fmt.Sprintf("r%d", route)}}}
		rec := model.Record{Kind: model.Metric, Payload: model.Payload{Metric: &model.MetricPoint{Name: def.name, Labels: def.labels}}}
		slot, err := model.OwnerSlot(pj.Org, pj.Project, pj.Source, pj.Producer, rec)
		if err != nil {
			panic(err)
		}
		def.slot = slot
		pj.series[i] = def
	}
	pj.perm = pj.rng.Perm(n)
	return pj
}
