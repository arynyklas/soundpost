// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package value

import (
	"encoding/binary"
	"github.com/arynyklas/soundpost/internal/model"
	"sort"
	"strings"
)

func Label(ls model.Labels, name string) string {
	for _, l := range ls {
		if l.Name == name {
			return l.Value
		}
	}
	return ""
}
func CloneLabels(ls model.Labels) model.Labels {
	out := make(model.Labels, len(ls))
	for i, l := range ls {
		out[i] = model.Label{Name: strings.Clone(l.Name), Value: strings.Clone(l.Value)}
	}
	return out
}
func WithoutName(ls model.Labels) model.Labels {
	out := make(model.Labels, 0, len(ls))
	for _, l := range ls {
		if l.Name != "__name__" {
			out = append(out, l)
		}
	}
	return out
}
func SetLabel(ls model.Labels, name, v string) model.Labels {
	out := make(model.Labels, 0, len(ls)+1)
	for _, l := range ls {
		if l.Name != name {
			out = append(out, l)
		}
	}
	if v != "" {
		out = append(out, model.Label{Name: name, Value: v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// LabelKey is length delimited: labels containing separators cannot collide.
func LabelKey(ls model.Labels) string {
	var b strings.Builder
	var n [8]byte
	for _, l := range ls {
		binary.BigEndian.PutUint64(n[:], uint64(len(l.Name)))
		b.Write(n[:])
		b.WriteString(l.Name)
		binary.BigEndian.PutUint64(n[:], uint64(len(l.Value)))
		b.Write(n[:])
		b.WriteString(l.Value)
	}
	return b.String()
}

// CompareLabels is lexical ordering, deliberately distinct from LabelKey's
// length-delimited collision-free identity encoding.
func CompareLabels(a, b model.Labels) int {
	n := min(len(a), len(b))
	for i := range n {
		if c := strings.Compare(a[i].Name, b[i].Name); c != 0 {
			return c
		}
		if c := strings.Compare(a[i].Value, b[i].Value); c != 0 {
			return c
		}
	}
	if len(a) < len(b) {
		return -1
	}
	if len(a) > len(b) {
		return 1
	}
	return 0
}
func CloneSeries(s Series) Series {
	s.Labels = CloneLabels(s.Labels)
	out := make([]Sample, len(s.Samples))
	for i, p := range s.Samples {
		out[i] = CloneSample(p)
	}
	s.Samples = out
	return s
}
func CloneSample(s Sample) Sample {
	if s.StartTimestamp != nil {
		start := *s.StartTimestamp
		s.StartTimestamp = &start
	}
	if s.Histogram != nil {
		h := CloneHistogram(*s.Histogram)
		s.Histogram = &h
	}
	return s
}
