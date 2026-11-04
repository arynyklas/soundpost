// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package profiles

import (
	"math"
	"soundpost/internal/model"
)

func sameNativeDomain(a, b *model.ProfileNativeDomain) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}
func appendChunk(v *ProfileView, c model.ProfileChunk, skip, max uint32) error {
	if c.Profile == (model.ID{}) || len(c.Frames) > 4096 || len(c.Stacks) > 4096 || len(c.Samples) > 8192 || len(c.Intervals) > 8192 {
		return model.Fail(model.Corrupt)
	}
	if v.Profile == (model.ID{}) {
		v.Profile = c.Profile
		v.Process = c.Process
		v.Method = c.Method
		v.Units = c.Units
		v.Clock = c.Clock
		v.NativeDomain = c.NativeDomain
	} else if v.Profile != c.Profile || v.Process != c.Process || v.Method != c.Method || v.Units != c.Units || v.Clock != c.Clock || !sameNativeDomain(v.NativeDomain, c.NativeDomain) {
		return model.Fail(model.Corrupt)
	}
	if len(c.NativeLoss) > 256 || len(c.NativeLoss) > 256-len(v.NativeLoss) {
		return model.Fail(model.TooLarge)
	}
	v.NativeLoss = append(v.NativeLoss, c.NativeLoss...)
	if c.Loss > math.MaxUint64-v.LossCount {
		return model.Fail(model.Corrupt)
	}
	v.LossCount += c.Loss
	v.Truncated = v.Truncated || c.Truncated
	frameMap := map[uint32]uint32{}
	stackMap := map[uint32]uint32{}
	stack := func(old uint32) (uint32, error) {
		if n, ok := stackMap[old]; ok {
			return n, nil
		}
		if int(old) >= len(c.Stacks) || len(c.Stacks[old].Frames) > 128 {
			return 0, model.Fail(model.Corrupt)
		}
		refs := make([]uint32, 0, len(c.Stacks[old].Frames))
		for _, f := range c.Stacks[old].Frames {
			if int(f) >= len(c.Frames) {
				return 0, model.Fail(model.Corrupt)
			}
			n, ok := frameMap[f]
			if !ok {
				if len(v.Frames) >= 8192 {
					return 0, model.Fail(model.TooLarge)
				}
				n = uint32(len(v.Frames))
				v.Frames = append(v.Frames, c.Frames[f])
				frameMap[f] = n
			}
			refs = append(refs, n)
		}
		if len(v.Stacks) >= 8192 {
			return 0, model.Fail(model.TooLarge)
		}
		n := uint32(len(v.Stacks))
		v.Stacks = append(v.Stacks, model.ProfileStack{Frames: refs})
		stackMap[old] = n
		return n, nil
	}
	var at uint32
	for _, s := range c.Samples {
		if s.Count == 0 || int(s.Stack) >= len(c.Stacks) {
			return model.Fail(model.Corrupt)
		}
		if at < skip {
			at++
			continue
		}
		if uint32(len(v.Samples)+len(v.Intervals)) >= max {
			at++
			continue
		}
		n, err := stack(s.Stack)
		if err != nil {
			return err
		}
		s.Stack = n
		if s.Native != nil {
			owned := *s.Native
			s.Native = &owned
		}
		v.Samples = append(v.Samples, s)
		at++
	}
	for _, i := range c.Intervals {
		if i.End < i.Start || i.Correction || int(i.Stack) >= len(c.Stacks) {
			return model.Fail(model.Corrupt)
		}
		if at < skip {
			at++
			continue
		}
		if uint32(len(v.Samples)+len(v.Intervals)) >= max {
			at++
			continue
		}
		n, err := stack(i.Stack)
		if err != nil {
			return err
		}
		i.Stack = n
		if i.NativeTask != nil {
			owned := *i.NativeTask
			i.NativeTask = &owned
		}
		duration := uint64(i.End - i.Start)
		var total **model.Uint64
		switch i.Kind {
		case "blocked":
			total = &v.BlockedNano
		case "runnable":
			total = &v.RunnableNano
		case "unknown_offcpu":
			total = &v.UnknownNano
		default:
			return model.Fail(model.Corrupt)
		}
		if i.Unit != "" && i.Unit != "nanoseconds" {
			return model.Fail(model.Corrupt)
		}
		if *total == nil {
			*total = new(model.Uint64)
		}
		value := uint64(**total)
		if value > math.MaxUint64-duration {
			return model.Fail(model.Corrupt)
		}
		**total = model.Uint64(value + duration)
		v.Intervals = append(v.Intervals, i)
		at++
	}
	return nil
}
func capabilitiesComplete(p ProfilePage) bool {
	found := map[model.ID]model.Capability{}
	for _, record := range p.Capabilities {
		if _, exists := found[record.ID]; exists {
			return false
		}
		found[record.ID] = record.Value
	}
	for _, chunk := range p.Chunks {
		primary, ok := found[chunk.Capability]
		if !ok || primary.Signal != model.Profile || primary.Clock != chunk.Clock.Domain {
			return false
		}
		methods := map[string]bool{}
		for _, id := range chunk.NativeCapabilities {
			value, ok := found[id]
			if !ok || value.Signal != model.Profile || value.Clock != chunk.Clock.Domain {
				return false
			}
			if chunk.NativeDomain != nil {
				if value.Runtime != "native_linux" || methods[value.Method] {
					return false
				}
				methods[value.Method] = true
			}
		}
		if chunk.NativeDomain != nil && (len(methods) != 3 || !methods["native_cpu"] || !methods["native_offcpu"] || !methods["native_runqueue_split"] || primary.Method != "native_cpu") {
			return false
		}
	}
	return true
}

// monoWall uses the chunk's explicit mapping, never a receipt time or timer.
func monoWall(c model.TraceClock, at model.MonoNano) (model.UnixNano, bool) {
	if at >= c.Mono {
		delta := uint64(at - c.Mono)
		if delta > math.MaxInt64 || int64(c.Wall) > math.MaxInt64-int64(delta) {
			return 0, false
		}
		return c.Wall + model.UnixNano(delta), true
	}
	delta := uint64(c.Mono - at)
	if delta > math.MaxInt64 || int64(c.Wall) < math.MinInt64+int64(delta) {
		return 0, false
	}
	return c.Wall - model.UnixNano(delta), true
}
func clipChunk(c model.ProfileChunk, w Window) (model.ProfileChunk, error) {
	out := c
	out.Samples = nil
	out.Intervals = nil
	out.NativeLoss = nil
	for _, s := range c.Samples {
		at, ok := monoWall(c.Clock, s.At)
		if !ok {
			return model.ProfileChunk{}, model.Fail(model.Corrupt)
		}
		if at >= w.Start && at < w.End {
			out.Samples = append(out.Samples, s)
		}
	}
	for _, i := range c.Intervals {
		start, ok := monoWall(c.Clock, i.Start)
		if !ok {
			return model.ProfileChunk{}, model.Fail(model.Corrupt)
		}
		end, ok := monoWall(c.Clock, i.End)
		if !ok {
			return model.ProfileChunk{}, model.Fail(model.Corrupt)
		}
		if end <= w.Start || start >= w.End {
			continue
		}
		if start < w.Start {
			delta := uint64(w.Start - start)
			if uint64(i.Start) > math.MaxUint64-delta {
				return model.ProfileChunk{}, model.Fail(model.Corrupt)
			}
			i.Start += model.MonoNano(delta)
		}
		if end > w.End {
			i.End -= model.MonoNano(end - w.End)
		}
		out.Intervals = append(out.Intervals, i)
	}
	for _, loss := range c.NativeLoss {
		at, ok := monoWall(c.Clock, loss.At)
		if !ok {
			return model.ProfileChunk{}, model.Fail(model.Corrupt)
		}
		if at >= w.Start && at < w.End {
			out.NativeLoss = append(out.NativeLoss, loss)
		}
	}
	return out, nil
}
