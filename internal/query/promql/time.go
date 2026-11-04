// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"math"
	"soundpost/internal/model"
	"soundpost/internal/query/value"
	"strconv"
)

const maxEvaluationPoints = 5000000

func checkedAdd(a, b int64) (int64, error) {
	if b > 0 && a > math.MaxInt64-b || b < 0 && a < math.MinInt64-b {
		return 0, timeError()
	}
	return a + b, nil
}
func checkedSub(a, b int64) (int64, error) {
	if b == math.MinInt64 {
		if a >= 0 {
			return 0, timeError()
		}
		return a - b, nil
	}
	return checkedAdd(a, -b)
}
func gridCount(e value.Evaluation) (int64, error) {
	if e.Instant {
		return 1, nil
	}
	if e.Step <= 0 || e.End < e.Start {
		return 0, timeError()
	}
	delta := uint64(e.End) - uint64(e.Start)
	count := delta / uint64(e.Step)
	if count >= maxEvaluationPoints {
		return 0, timeError()
	}
	return int64(count) + 1, nil
}

// EvaluationGrid includes the end only when it lies exactly on the grid.
func EvaluationGrid(e value.Evaluation) ([]model.UnixNano, error) {
	n, err := gridCount(e)
	if err != nil {
		return nil, err
	}
	if e.Instant {
		return []model.UnixNano{e.Time}, nil
	}
	out := make([]model.UnixNano, int(n))
	at := int64(e.Start)
	for i := range out {
		out[i] = model.UnixNano(at)
		if i+1 < len(out) {
			at, err = checkedAdd(at, e.Step)
			if err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}
func secondsNS(f float64) (int64, error) {
	if math.IsNaN(f) || math.IsInf(f, 0) || f >= float64(math.MaxInt64)/1e9 || f < float64(math.MinInt64)/1e9 {
		return 0, timeError()
	}
	return int64(f * 1e9), nil
}

// Explicit @ numeric literals use each pinned profile's binary64-seconds to
// nearest-millisecond conversion (ties away from zero), unlike duration math.
func atNS(text string, e value.Evaluation) (int64, error) {
	switch text {
	case "start()":
		if e.Instant {
			return int64(e.Time), nil
		}
		return int64(e.Start), nil
	case "end()":
		if e.Instant {
			return int64(e.Time), nil
		}
		return int64(e.End), nil
	}
	seconds, err := strconv.ParseFloat(text, 64)
	if err != nil || math.IsNaN(seconds) || math.IsInf(seconds, 0) {
		return 0, timeError()
	}
	milliseconds := math.Round(seconds * 1000)
	if milliseconds > float64(math.MaxInt64/1000000) || milliseconds < float64(math.MinInt64/1000000) {
		return 0, timeError()
	}
	return int64(milliseconds) * 1000000, nil
}
func durationValue(e Expr, ev value.Evaluation) (float64, error) {
	if e == nil {
		return 0, nil
	}
	n := e.(*Node)
	switch n.Kind {
	case "number":
		return math.Float64frombits(n.FloatBits), nil
	case "paren":
		return durationValue(n.Children[0], ev)
	case "unary":
		v, err := durationValue(n.Children[0], ev)
		if n.Text == "-" {
			v = -v
		}
		return v, err
	case "binary":
		a, err := durationValue(n.Children[0], ev)
		if err != nil {
			return 0, err
		}
		b, err := durationValue(n.Children[1], ev)
		if err != nil {
			return 0, err
		}
		v, _, ok := floatOperator(n.Text, a, b)
		if !ok {
			return 0, timeError()
		}
		return v, nil
	case "duration_call":
		switch n.Text {
		case "step":
			return float64(ev.Step) / 1e9, nil
		case "range":
			if ev.Instant {
				return 0, nil
			}
			width, err := checkedSub(int64(ev.End), int64(ev.Start))
			if err != nil {
				return 0, err
			}
			return float64(width) / 1e9, nil
		case "min_of", "max_of":
			if len(n.Children) != 2 {
				return 0, timeError()
			}
			a, err := durationValue(n.Children[0], ev)
			if err != nil {
				return 0, err
			}
			b, err := durationValue(n.Children[1], ev)
			if err != nil {
				return 0, err
			}
			if n.Text == "min_of" {
				return math.Min(a, b), nil
			}
			return math.Max(a, b), nil
		}
	}
	return 0, timeError()
}
func durationNS(e Expr, text string, ev value.Evaluation) (int64, error) {
	var f float64
	var err error
	if e != nil {
		f, err = durationValue(e, ev)
	} else if text != "" {
		var ok bool
		f, ok = durationSeconds(text)
		if !ok {
			f, err = strconv.ParseFloat(text, 64)
		}
	}
	if err != nil {
		return 0, err
	}
	if _, err = secondsNS(f); err != nil {
		return 0, err
	}
	// Pinned duration expressions compute binary64 seconds, then truncate to
	// milliseconds. Literal durations first round into the nanosecond domain.
	if e != nil {
		if _, literal := constantNumber(e.(*Node)); literal {
			return int64(math.Round(f*1e9)) / 1000000 * 1000000, nil
		}
	}
	milliseconds := math.Trunc(f * 1000)
	if milliseconds > float64(math.MaxInt64/1000000) || milliseconds < float64(math.MinInt64/1000000) {
		return 0, timeError()
	}
	return int64(milliseconds) * 1000000, nil
}
func selectorTime(n *Node, at model.UnixNano, p Plan) (int64, error) {
	t := int64(at)
	var err error
	if n.At != "" {
		t, err = atNS(n.At, p.Evaluation)
		if err != nil {
			return 0, err
		}
	}
	offset, err := durationNS(n.OffsetExpr, n.Offset, p.Evaluation)
	if err != nil {
		return 0, err
	}
	return checkedSub(t, offset)
}
func firstSubqueryPoint(left, step int64) (int64, error) {
	if step <= 0 {
		return 0, timeError()
	}
	rem := left % step
	if rem < 0 {
		rem += step
	}
	return checkedAdd(left, step-rem)
}
