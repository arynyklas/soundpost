// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"math/bits"
	"sync"
	"time"

	"soundpost/internal/model"
)

// PressureLevel is the disk-pressure admission level (design section 12).
type PressureLevel uint8

const (
	PressureNormal PressureLevel = iota
	PressureWarn
	PressureDenyLow
	PressureDenyAll
)

// pressureHysteresis is how many percentage points below its threshold usage
// must fall before a level is left, so a boundary does not flap.
const pressureHysteresis = 2

// pressureRingSize bounds the retained warning history.
const pressureRingSize = 64

// DiskUsage is the volume usage; UsedBytes includes everything on the volume.
type DiskUsage struct{ TotalBytes, UsedBytes uint64 }

// DiskMeter measures the volume that holds dir.
type DiskMeter interface {
	Usage(dir string) (DiskUsage, error)
}

// PressureConfig holds the thresholds and the space kept for consensus/audit.
type PressureConfig struct {
	WarnPercent, LowPercent, DenyPercent       uint8
	ReservedConsensusBytes, ReservedAuditBytes uint64
	Now                                        func() time.Time
	Interval                                   time.Duration // minimum age of a cached sample used by admission; 0 samples every admission
}

// DefaultPressureConfig returns the approved 80/90/95 thresholds.
func DefaultPressureConfig() PressureConfig {
	return PressureConfig{WarnPercent: 80, LowPercent: 90, DenyPercent: 95, ReservedConsensusBytes: 64 << 20, ReservedAuditBytes: 16 << 20, Now: time.Now, Interval: time.Second}
}

// PressureWarning records one level change. It carries no tenant data.
type PressureWarning struct {
	At          model.UnixNano
	From, To    PressureLevel
	UsedPercent uint8
	Code        string
	Seq         uint64
}

// PressureStatus is the operator-visible state.
type PressureStatus struct {
	Level                PressureLevel
	UsedPercent          uint8
	Warnings             []PressureWarning
	DeniedLow, DeniedAll uint64
}

// AdmissionClass separates low-priority batches from everything else.
type AdmissionClass uint8

const (
	ClassLow AdmissionClass = iota
	ClassNormal
)

type pressureState struct {
	mu        sync.Mutex
	bound     bool
	dir       string
	meter     DiskMeter
	cfg       PressureConfig
	level     PressureLevel
	percent   uint8
	free      uint64
	sampled   time.Time
	have      bool
	warnings  []PressureWarning
	seq       uint64
	deniedLow uint64
	deniedAll uint64
}

// BindPressure installs the meter once.
func (e *Engine) BindPressure(dir string, m DiskMeter, cfg PressureConfig) error {
	if m == nil || dir == "" || !(0 < cfg.WarnPercent && cfg.WarnPercent < cfg.LowPercent && cfg.LowPercent < cfg.DenyPercent && cfg.DenyPercent <= 100) {
		return model.Fail(model.Invalid)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	p := &e.pressure
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.bound {
		return model.Fail(model.Conflict)
	}
	p.bound, p.dir, p.meter, p.cfg = true, dir, m, cfg
	return nil
}

// PressureStatus returns the last observed state without sampling.
func (e *Engine) PressureStatus() PressureStatus {
	p := &e.pressure
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.status()
}

func (p *pressureState) status() PressureStatus {
	return PressureStatus{Level: p.level, UsedPercent: p.percent, Warnings: append([]PressureWarning(nil), p.warnings...), DeniedLow: p.deniedLow, DeniedAll: p.deniedAll}
}

// ObservePressure samples the meter now and records a warning on a level change.
func (e *Engine) ObservePressure(_ context.Context) (PressureStatus, error) {
	p := &e.pressure
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.bound {
		return PressureStatus{}, model.Fail(model.Unsupported)
	}
	if err := p.sample(); err != nil {
		return p.status(), err
	}
	return p.status(), nil
}

func atLeast(used, total uint64, percent uint8) bool {
	if total == 0 {
		return true
	}
	hi, lo := bits.Mul64(used, 100)
	thi, tlo := bits.Mul64(total, uint64(percent))
	return hi > thi || hi == thi && lo >= tlo
}

func (p *pressureState) threshold(l PressureLevel) uint8 {
	switch l {
	case PressureWarn:
		return p.cfg.WarnPercent
	case PressureDenyLow:
		return p.cfg.LowPercent
	}
	return p.cfg.DenyPercent
}

// sample requires p.mu. It fails closed: a meter error leaves the level as is.
func (p *pressureState) sample() error {
	u, err := p.meter.Usage(p.dir)
	if err != nil {
		return model.Fail(model.Unavailable)
	}
	now := p.cfg.Now()
	raw := PressureNormal
	for l := PressureWarn; l <= PressureDenyAll; l++ {
		if atLeast(u.UsedBytes, u.TotalBytes, p.threshold(l)) {
			raw = l
		}
	}
	next := raw
	if raw < p.level {
		next = p.level
		for next > PressureNormal && !atLeast(u.UsedBytes, u.TotalBytes, satSub(p.threshold(next), pressureHysteresis)) {
			next--
		}
		if next < raw {
			next = raw
		}
	}
	pct := uint8(100)
	if u.TotalBytes != 0 && u.UsedBytes < u.TotalBytes {
		hi, lo := bits.Mul64(u.UsedBytes, 100)
		q, _ := bits.Div64(hi, lo, u.TotalBytes)
		pct = uint8(q)
	}
	p.percent, p.sampled, p.have = pct, now, true
	p.free = 0
	if u.UsedBytes < u.TotalBytes {
		p.free = u.TotalBytes - u.UsedBytes
	}
	if next != p.level {
		p.seq++
		w := PressureWarning{At: model.UnixNano(now.UnixNano()), From: p.level, To: next, UsedPercent: pct, Seq: p.seq}
		switch next {
		case PressureNormal:
			w.Code = "disk_recovered"
		case PressureWarn:
			w.Code = "disk_warn"
		case PressureDenyLow:
			w.Code = "disk_deny_low"
		default:
			w.Code = "disk_deny_all"
		}
		if len(p.warnings) == pressureRingSize {
			copy(p.warnings, p.warnings[1:])
			p.warnings = p.warnings[:pressureRingSize-1]
		}
		p.warnings = append(p.warnings, w)
		p.level = next
	}
	return nil
}

func satSub(a, b uint8) uint8 {
	if a < b {
		return 0
	}
	return a - b
}

func capacityFault() *model.Fault {
	f := model.Fail(model.Unavailable)
	f.Retryable, f.SafeDetail = true, "capacity"
	return f
}

// admitPressure is the telemetry admission gate for Append and WriteBlob. It
// never changes or removes stored data. Without a bound meter it admits.
func (e *Engine) admitPressure(class AdmissionClass, bytes uint64) error {
	p := &e.pressure
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.bound {
		return nil
	}
	if !p.have || p.cfg.Interval <= 0 || p.cfg.Now().Sub(p.sampled) >= p.cfg.Interval {
		if err := p.sample(); err != nil {
			return capacityFault()
		}
	}
	if p.level >= PressureDenyAll {
		p.deniedAll++
		return capacityFault()
	}
	if p.level >= PressureDenyLow && class == ClassLow {
		p.deniedLow++
		return capacityFault()
	}
	need, carry := bits.Add64(bytes, p.cfg.ReservedConsensusBytes, 0)
	need2, carry2 := bits.Add64(need, p.cfg.ReservedAuditBytes, 0)
	if carry != 0 || carry2 != 0 || p.free < need2 {
		p.deniedAll++
		return capacityFault()
	}
	return nil
}

// batchClass is ClassLow only when every record is a span, replay or profile.
func batchClass(records []model.Record) AdmissionClass {
	for _, r := range records {
		if r.Kind != model.SpanKind && r.Kind != model.Replay && r.Kind != model.Profile {
			return ClassNormal
		}
	}
	return ClassLow
}
