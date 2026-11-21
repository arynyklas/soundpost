//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package qual

import (
	"fmt"
	"slices"
)

// nsJudge decides whether one namespace case's record shows the required behaviour. It returns the failures; none means the
// case passed. Cases are judged from what the real captures delivered and refused, never from what the fixture intended.
type nsJudge func(spec NSSpec, rec NSRecord) []string

func isIdentityCode(code string) bool {
	return code == "generation_changed" || code == "thread_coverage_changed" || code == "topology_changed"
}

func (s NSSession) taskKeysOK(t NSTarget) []string {
	var out []string
	for _, task := range s.Tasks {
		k := task.Key
		if k.TGID != t.PID || k.PIDNamespace != nsUint(t.PIDNS) || k.TID != t.PID {
			out = append(out, fmt.Sprintf("%s: events under TaskKey tgid=%d tid=%d ns=%d, the target is tgid=%d in ns=%d", s.Label, k.TGID, k.TID, uint64(k.PIDNamespace), t.PID, t.PIDNS))
		}
	}
	return out
}

func session(rec NSRecord, label string) (NSSession, bool) {
	for _, s := range rec.Sessions {
		if s.Label == label {
			return s, true
		}
	}
	return NSSession{}, false
}

// judgeNS is the production judge.
func judgeNS(spec NSSpec, rec NSRecord) []string {
	var f []string
	add := func(format string, args ...any) { f = append(f, fmt.Sprintf(format, args...)) }
	if rec.Error != "" {
		return []string{"case did not run: " + rec.Error}
	}
	for _, s := range rec.Sessions {
		if s.Leaks != 0 {
			add("%s: the private path canary reached the acquisition socket %d time(s)", s.Label, s.Leaks)
		}
	}
	main, ok := session(rec, "capture")
	if !ok {
		return append(f, "no capture session was recorded")
	}
	t := rec.Target
	needCapture := func() {
		switch {
		case !main.Ready:
			add("capture refused (%s%s), expected genuine samples", main.ErrorCode, main.ReadError)
		case main.CPU < 8:
			add("capture delivered %d CPU samples, expected at least 8", main.CPU)
		}
		f = append(f, main.taskKeysOK(t)...)
		if main.Resolved == 0 {
			add("capture: no frame resolved to an approved module (unresolved %v)", main.Unresolved)
		}
		for _, b := range main.Builds {
			if b != t.BuildID {
				add("capture: frames resolved to build %s, the target runs %s", b, t.BuildID)
			}
		}
	}
	endsWithIdentityError := func(s NSSession) {
		switch {
		case !isIdentityCode(s.ErrorCode):
			add("%s: the transition was not noticed (end code %q, %d CPU samples, %d events after the slack)", s.Label, s.ErrorCode, s.CPU, s.LateOld)
		case s.ProvenThrough != 0 && s.TransitionNs != 0 && s.ProvenThrough > s.TransitionNs:
			add("%s: identity last proven at %d, after the transition at %d", s.Label, s.ProvenThrough, s.TransitionNs)
		}
		if s.LateOld != 0 {
			add("%s: %d events under the old identity were delivered more than the identity cadence after the transition", s.Label, s.LateOld)
		}
		if !s.GuardRetired {
			add("%s: the old mapping guard stayed valid after the transition", s.Label)
		}
	}
	refused := func(s NSSession, code string) {
		if s.Ready || s.ErrorCode != code || s.CPU != 0 || s.Switch != 0 {
			add("%s: expected a refusal %q with no events, got ready=%v code=%q cpu=%d switch=%d", s.Label, code, s.Ready, s.ErrorCode, s.CPU, s.Switch)
		}
	}
	nested := len(t.NSpid) >= 2
	switch spec.Name {
	case "nested_target_host_helper":
		needCapture()
		if !nested || t.NSpid[0] != t.PID || t.NSpid[len(t.NSpid)-1] != 1 {
			add("target NSpid %v, expected the helper-view PID %d first and PID 1 of its own namespace last", t.NSpid, t.PID)
		}
		if t.PIDNS == rec.HelperPIDNS {
			add("target and helper share PID namespace %d, the case needs a nested one", t.PIDNS)
		}
		for _, task := range main.Tasks {
			if task.Key.TID == 1 || task.Key.TGID == 1 {
				add("an event carries the target's PID inside its own namespace (1) as its identity")
			}
		}
		sched, ok := session(rec, "scheduler")
		switch {
		case !ok:
			add("no scheduler session")
		case rec.HelperInit:
			if !sched.Ready || sched.TargetSwitch < 3 {
				add("scheduler: helper in the initial PID namespace, nested target: ready=%v target switches=%d (code %q), expected attributed switches", sched.Ready, sched.TargetSwitch, sched.ErrorCode)
			}
			f = append(f, sched.taskKeysOK(t)...)
		default:
			refused(sched, "event_unavailable")
		}
		if rec.ProbeCPU != "supported" {
			add("probe: CPU %q across the PID namespace boundary", rec.ProbeCPU)
		}
		if rec.HelperInit && rec.ProbeOffCPU != "supported" {
			add("probe: off-CPU %q in the initial PID namespace", rec.ProbeOffCPU)
		}
	case "helper_in_target_ns":
		needCapture()
		if rec.HelperInit {
			add("the helper runs in the initial PID namespace, the case needs a nested one")
		}
		if t.PIDNS != rec.HelperPIDNS {
			add("target PID namespace %d is not the helper's %d", t.PIDNS, rec.HelperPIDNS)
		}
		if len(t.NSpid) != 1 || t.NSpid[0] != t.PID {
			add("NSpid %v seen from inside the namespace, expected only the target's own PID %d (the kernel hides outer PIDs)", t.NSpid, t.PID)
		}
		if sched, ok := session(rec, "scheduler"); !ok {
			add("no scheduler session")
		} else {
			refused(sched, "event_unavailable")
		}
		if rec.ProbeCPU != "supported" {
			add("probe: CPU %q in the target's own PID namespace", rec.ProbeCPU)
		}
		if rec.ProbeOffCPU == "supported" || !slices.Contains(rec.ProbeReasons, "event_unavailable") {
			add("probe: off-CPU %q reasons %v, expected unsupported with event_unavailable", rec.ProbeOffCPU, rec.ProbeReasons)
		}
	case "nested_exec":
		f = append(f, main.taskKeysOK(t)...)
		if !main.Ready || main.CPU < 8 {
			add("capture before the exec delivered %d samples (ready=%v)", main.CPU, main.Ready)
		}
		endsWithIdentityError(main)
	case "cgroup_move":
		if !main.Ready || main.CPU < 8 {
			add("capture before the move delivered %d samples (ready=%v)", main.CPU, main.Ready)
		}
		endsWithIdentityError(main)
		if after, ok := session(rec, "after_transition_old_identity"); !ok {
			add("no capture after the move")
		} else {
			refused(after, "generation_changed")
		}
	case "layer_overlay":
		needCapture()
		if rec.Facts["host_path_build_id"] == t.BuildID || rec.Facts["host_path_build_id"] == "" {
			add("the layer did not change what runs at the path: host build %q, target build %s", rec.Facts["host_path_build_id"], t.BuildID)
		}
		if slices.Contains(main.Builds, rec.Facts["host_path_build_id"]) {
			add("frames resolved to the build found at the path in the helper's mount namespace, not the one the target runs")
		}
	case "deleted_replaced", "mount_ns_swap", "mount_unshare":
		if !main.Ready || main.CPU < 8 {
			add("capture before the change delivered %d samples (ready=%v)", main.CPU, main.Ready)
		}
		if main.ErrorCode != "" && !isIdentityCode(main.ErrorCode) {
			add("capture ended with %q", main.ErrorCode)
		}
		for _, s := range rec.Sessions {
			if slices.Contains(s.Builds, rec.Facts["variant_build_id"]) {
				add("%s: frames resolved to the replacement build %s the running process never mapped", s.Label, rec.Facts["variant_build_id"])
			}
		}
		after, ok := session(rec, "after_transition_old_identity")
		if !ok {
			add("no capture after the change")
			break
		}
		safe := map[string]bool{"deleted_executable": true, "invalid_elf_artifact": true, "artifact_unavailable": true, "build_not_approved": true}
		switch {
		case !after.Ready && isIdentityCode(after.ErrorCode):
			// refusing is safe
		case !after.Ready:
			add("after the change the capture was refused with %q, not an identity code", after.ErrorCode+after.ReadError)
		default:
			if after.CPU == 0 {
				add("after the change the capture delivered no samples")
			}
			for reason := range after.Unresolved {
				if !safe[reason] && reason != "frame_unresolved" && reason != "missing_frame_pointer_or_callchain" && reason != "callchain_truncated" {
					add("after the change frames carry reason %q", reason)
				}
			}
			if spec.Transition == "deleted_replaced" && after.Resolved != 0 {
				add("after the change %d frames still resolved to a module although its file is deleted", after.Resolved)
			}
		}
	case "pid_reuse_cross_ns":
		if !main.Ready || main.CPU < 6 {
			add("capture of the first process delivered %d samples", main.CPU)
		}
		endsWithIdentityError(main)
		if after, ok := session(rec, "after_transition_old_identity"); !ok {
			add("no capture with the old identity")
		} else {
			refused(after, "generation_changed")
		}
		reuser, ok := session(rec, "reuser")
		switch {
		case !ok:
			add("no capture of the process that reused the PID")
		case !reuser.Ready || reuser.CPU == 0:
			add("capture of the reusing process delivered %d samples (ready=%v code=%q)", reuser.CPU, reuser.Ready, reuser.ErrorCode)
		default:
			for _, old := range main.Tasks {
				for _, now := range reuser.Tasks {
					if old.Key == now.Key {
						add("old and new process share TaskKey %+v", old.Key)
					}
					// Generation is the capture's own epoch (1 for every fresh capture); what separates two processes across
					// captures is the PID namespace and the process start in the key, which differ here.
					if old.Key.ProcessStart == now.Key.ProcessStart {
						add("old and new process share the process start %d", uint64(old.Key.ProcessStart))
					}
					if old.Key.PIDNamespace == now.Key.PIDNamespace {
						add("old and new process share PID namespace %d", uint64(old.Key.PIDNamespace))
					}
					if old.Key.TGID != now.Key.TGID {
						add("the PID was not reused: %d then %d", old.Key.TGID, now.Key.TGID)
					}
				}
			}
		}
	case "proc_view_mismatch":
		if rec.Facts["views_differ"] != "true" {
			add("the case did not set up two different processes under one number")
		}
		refused(main, "generation_changed")
	case "attach":
		// a target that already runs in the /proc this helper sees (Compose pid: container:<workload>, DaemonSet hostPID)
		// record-only rows: genuine CPU samples under the right TaskKey are required; frames may stay unresolved with a safe
		// reason (a PERFMON-only helper cannot always read another container's executable through /proc/<pid>/root)
		if !main.Ready || main.CPU < 8 {
			add("capture refused (%s%s) or delivered %d samples, expected at least 8", main.ErrorCode, main.ReadError, main.CPU)
		}
		f = append(f, main.taskKeysOK(t)...)
		if len(t.NSpid) == 0 || t.NSpid[0] != t.PID {
			add("target NSpid %v does not start with the PID %d the helper uses", t.NSpid, t.PID)
		}
		if t.PIDNS == rec.HelperPIDNS && len(t.NSpid) != 1 || t.PIDNS != rec.HelperPIDNS && len(t.NSpid) < 2 {
			add("target PID namespace %d (helper's %d) does not match its NSpid chain %v", t.PIDNS, rec.HelperPIDNS, t.NSpid)
		}
		if sched, ok := session(rec, "scheduler"); !ok {
			add("no scheduler session")
		} else if rec.HelperInit && rec.Facts["tracefs"] == "unreadable" {
			// the helper has the initial PID namespace but this container has no tracefs: the refusal must be explicit
			refused(sched, "event_unavailable")
		} else if rec.HelperInit {
			if sched.Ready && sched.TargetSwitch < 3 {
				add("scheduler: ready but %d attributed switches", sched.TargetSwitch)
			}
			if !sched.Ready {
				refused(sched, "event_unavailable") // an explicit refusal (no tracefs / seccomp) is recorded, not a pass of off-CPU
			}
			f = append(f, sched.taskKeysOK(t)...)
		} else {
			refused(sched, "event_unavailable")
		}
	default:
		add("no judge for case %q", spec.Name)
	}
	return f
}

// JudgeNS judges one case record with the production judge.
func JudgeNS(spec NSSpec, rec NSRecord) []string { return judgeNS(spec, rec) }
