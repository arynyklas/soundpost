# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
"""Optional, explicit CPython profile supplements (internal adapter, not public C09 API).

Two methods, kept distinct and never relabelled as OS CPU time:

* ``python_monitoring``: deterministic ``sys.monitoring`` event counts per code object (units ``events``).
* ``python_wall_samples``: ``sys._current_frames()`` sampling of every other thread (units ``samples``, offsets in
  wall microseconds of ``time.perf_counter_ns``).

Only code identities are read (``co_filename``/``co_qualname``/``co_firstlineno`` through the intrinsic
``types.CodeType`` descriptors): never arguments, locals, globals, return values, exception values, source text,
thread names or absolute paths. Profiling is off until ``start_profile`` is called; expected failures return a
report with a refusal capability instead of raising. One lease may own the profiler per process, held in a registry
stored under a well-known key on ``sys`` so duplicate module copies still conflict.
"""
import copy
import math
import os
import platform
import re
import secrets
import sys
import sysconfig
import threading
import time
import types
from dataclasses import dataclass
from .frames import normalize_root

REGISTRY_KEY = "__soundpost_profile_registry_v1__"
METHODS = ("python_monitoring", "python_wall_samples")
REASONS = {
    "supported": ("ok",),
    "denied": ("profiler_owned", "isolate_scope_mismatch", "monitoring_tool_ids_occupied", "document_policy_missing", "permission_denied", "invalid_options", "client_unavailable"),
    "unsupported": ("inspector_unavailable", "profiler_api_unavailable", "sys_monitoring_unavailable", "js_self_profiling_unavailable", "free_threaded_unqualified", "runtime_unsupported"),
    "error": ("inspector_timeout", "inspector_error", "profiler_state_lost", "stop_timeout", "sampler_failed"),
}
MAX_DURATION_S = 60
MAX_STACK_DEPTH = 128
MAX_FRAMES = 4096
MAX_SAMPLES = 8192
MAX_EVENT_ROWS = 4 * MAX_FRAMES
UNCERTAINTY_NS = "18446744073709551615"
CAPABILITY_TTL_NS = 3600 * 10**9
PLACEHOLDER = {"module_id": "external", "function": "", "artifact_id": "", "offset": "0", "reason": "not_captured"}
_KINDS = ("PY_START", "PY_RESUME", "PY_RETURN", "PY_UNWIND")
_COVERAGE_NONE = {"frames": "none", "threads": "none", "workers": "none", "tasks": "none"}
_SAFE_SYMBOL = re.compile(r"(?:[A-Za-z_][A-Za-z0-9_]*|<[a-z]{1,16}>)(?:\.(?:[A-Za-z_][A-Za-z0-9_]*|<[a-z]{1,16}>))*")
_SAFE_PATH = re.compile(r"[A-Za-z0-9_./-]{1,256}")
_CACHE_LIMIT = 16384
_THREAD_LIMIT = 4096
_EXTERNAL, _FULL = -1, -2
_ACK_TIMEOUT_S = 2.0

@dataclass(frozen=True)
class ProfileOptions:
    method: str
    duration_s: float
    interval_ms: int = 10
    project_root: str | None = None
    max_samples: int = MAX_SAMPLES
    max_events: int = MAX_EVENT_ROWS
    max_code_objects: int = MAX_FRAMES

# ------------------------------------------------------------------ helpers

def _registry():
    # setdefault on the module dict is atomic under the GIL: the first copy of this module to arrive wins.
    return vars(sys).setdefault(REGISTRY_KEY, {"lock": threading.Lock(), "owner": None})

def _safe_code(value, limit):
    return re.sub(r"[^A-Za-z0-9_.:/<>+ $-]", "_", value)[:limit] or "unknown"

def _runtime_identity():
    machine = platform.machine() or "unknown"
    date = platform.python_build()[1]
    return {
        "runtime": "cpython",
        "version": _safe_code(platform.python_version(), 128),
        "build": _safe_code(f"{platform.python_implementation()} {date} {platform.python_compiler()}", 256),
        "os": _safe_code(sys.platform, 64),
        "arch": _safe_code(machine.lower(), 64),
    }

def _is_int(value, low, high):
    return type(value) is int and low <= value <= high

def _validate(options):
    """Return a dict of the echoed, validated options or None; never echoes invalid values."""
    if type(options) is not ProfileOptions:
        return None
    duration = options.duration_s
    if type(duration) not in (int, float) or not math.isfinite(duration) or not 0 < duration <= MAX_DURATION_S:
        return None
    if options.method not in METHODS or not _is_int(options.interval_ms, 1, 1000):
        return None
    if not _is_int(options.max_samples, 1, MAX_SAMPLES) or not _is_int(options.max_events, 1, MAX_EVENT_ROWS) or not _is_int(options.max_code_objects, 1, MAX_FRAMES):
        return None
    try:
        root = normalize_root(options.project_root)
    except ValueError:
        return None
    return {"duration_s": duration, "interval_ms": options.interval_ms, "max_samples": options.max_samples, "max_events": options.max_events, "max_code_objects": options.max_code_objects, "root": root}

def _identity(code, root):
    """Project-safe code identity or None for anything outside the explicit project root."""
    filename = types.CodeType.co_filename.__get__(code)
    function = types.CodeType.co_qualname.__get__(code)
    first = types.CodeType.co_firstlineno.__get__(code)
    if type(filename) is not str or type(function) is not str or type(first) is not int:
        return None
    try:
        filename = os.path.normpath(filename)
        if os.path.commonpath((root, filename)) != root:
            return None
        relative = os.path.relpath(filename, root).replace("\\", "/")
    except ValueError:
        return None
    if _SAFE_PATH.fullmatch(relative) is None or any(part in ("", ".", "..") for part in relative.split("/")):
        return None
    safe = len(function) <= 256 and _SAFE_SYMBOL.fullmatch(function) is not None
    return {"module_id": relative, "function": function if safe else "", "artifact_id": relative, "line": max(first, 0), "column": None, "offset": "0", "reason": "" if safe else "not_captured"}

class _Frames:
    """Bounded code-identity table. Cached entries hold the code object so ``id`` cannot be reused."""
    def __init__(self, root, cap):
        self.root, self.cap = root, cap
        self.frames = []
        self._by_code = {}
        self._placeholder = None
        self.full_codes = 0
        self.uncached_full = 0
    def lookup(self, code):
        entry = self._by_code.get(id(code))
        if entry is not None:
            return entry[0]
        identity = _identity(code, self.root) if self.root is not None else None
        if identity is None:
            result = _EXTERNAL
        elif len(self.frames) >= self.cap:
            result = _FULL
        else:
            result = len(self.frames)
            self.frames.append(identity)
        if result == _FULL:
            self.full_codes += 1
        if len(self._by_code) < _CACHE_LIMIT or result >= 0:
            self._by_code[id(code)] = (result, code)
        elif result == _FULL:
            self.uncached_full += 1
        return result
    def external(self):
        if self._placeholder is None:
            if len(self.frames) >= self.cap:
                return _FULL
            self._placeholder = len(self.frames)
            self.frames.append(dict(PLACEHOLDER))
        return self._placeholder

# ------------------------------------------------------------------ engines

class _MonitoringEngine:
    method = "python_monitoring"
    units = "events"
    time_delta_unit = None
    coverage = {"frames": "partial", "threads": "complete", "workers": "none", "tasks": "none"}
    def __init__(self, params):
        self.params = params
        self.tool = None
        self.name = "soundpost-profile-" + secrets.token_hex(4)
        self._lock = threading.RLock()
        self._frames = _Frames(params["root"], params["max_code_objects"])
        self._counts = {}
        self._dropped_rows = set()
        self._errors = 0
        self._closed = False
        self._used_disable = False
        self._events = None
        self._disable = None
    def acquire(self):
        monitoring = getattr(sys, "monitoring", None)
        if monitoring is None:
            return "sys_monitoring_unavailable"
        for tool in (monitoring.PROFILER_ID, 3, 4):
            try:
                monitoring.use_tool_id(tool, self.name)
            except ValueError:
                continue
            self.tool = tool
            return None
        return "monitoring_tool_ids_occupied"
    def start(self):
        monitoring = sys.monitoring
        self._disable = monitoring.DISABLE
        events = monitoring.events
        self._events = (events.PY_START, events.PY_RESUME, events.PY_RETURN, events.PY_UNWIND)
        callbacks = (self._start, self._resume, self._return, self._unwind)
        for event, callback in zip(self._events, callbacks):
            monitoring.register_callback(self.tool, event, callback)
        monitoring.set_events(self.tool, self._events[0] | self._events[1] | self._events[2] | self._events[3])
    def _hit(self, code, kind):
        # Only the code object is inspected. Return/exception arguments are never touched.
        try:
            with self._lock:
                if self._closed:
                    return None
                index = self._frames.lookup(code)
                if index >= 0:
                    key = index * 4 + kind
                    count = self._counts.get(key)
                    if count is not None:
                        self._counts[key] = count + 1
                        return None
                    if len(self._counts) < self.params["max_events"]:
                        self._counts[key] = 1
                        return None
                    if len(self._dropped_rows) < _CACHE_LIMIT:
                        self._dropped_rows.add(key)
                if kind < 3:
                    self._used_disable = True
                    return self._disable
                return None
        except Exception:
            self._errors += 1
            return None
    def _start(self, code, offset):
        return self._hit(code, 0)
    def _resume(self, code, offset):
        return self._hit(code, 1)
    def _return(self, code, offset, retval):
        return self._hit(code, 2)
    def _unwind(self, code, offset, exception):
        return self._hit(code, 3)
    def halt(self):
        monitoring = getattr(sys, "monitoring", None)
        state = monitoring.get_tool(self.tool) if monitoring is not None and self.tool is not None else None
        owned = state == self.name
        orphan = self.tool is not None and monitoring is not None and state is None
        health = None
        if self.tool is not None and monitoring is not None:
            if owned:
                health = None if monitoring.get_events(self.tool) == sum(self._events or ()) else "profiler_state_lost"
                for step in (lambda: monitoring.set_events(self.tool, 0), *(lambda event=event: monitoring.register_callback(self.tool, event, None) for event in self._events or ())):
                    try:
                        step()
                    except Exception:
                        health = health or "profiler_state_lost"
            else:
                health = "profiler_state_lost"
        with self._lock:
            self._closed = True
            counts, frames, errors = dict(self._counts), list(self._frames.frames), self._errors
            dropped_rows, full, uncached = len(self._dropped_rows), self._frames.full_codes, self._frames.uncached_full
        try:
            clear = getattr(monitoring, "clear_tool_id", None)  # CPython 3.14+ only; 3.12/3.13 rely on the callback reset above
            if (owned or orphan) and clear is not None:
                # An orphaned (externally freed, still unclaimed) ID may carry our leftover callbacks; a claimed one is never touched.
                clear(self.tool)
            if owned:
                monitoring.free_tool_id(self.tool)
        except Exception:
            health = health or "profiler_state_lost"
        if self._used_disable and monitoring is not None:
            # DISABLE is remembered per code location even after the tool ID is freed; restore it so later
            # profiles (or other tools reusing this ID) are not silently blind. Other tools just re-fire once.
            try:
                monitoring.restart_events()
            except Exception:
                health = health or "profiler_state_lost"
        rows = [{"frame": key // 4, "kind": _KINDS[key % 4], "count": str(value)} for key, value in sorted(counts.items())]
        dropped = full + dropped_rows
        losses = [("truncated", dropped)] if dropped else []
        if health == "profiler_state_lost":
            losses.append(("foreign_state", 1))
        return {
            "health": health, "frames": frames, "stacks": [], "samples": [], "events": rows, "losses": losses,
            "truncated": bool(dropped), "interval": {"requested_us": None, "achieved_us": None},
            "scope": {"tool_id": self.tool, "events": list(_KINDS), "callback_errors": errors, "line_semantics": "function_first_line",
                      "dropped": {"code_objects": full, "event_rows": dropped_rows, "exact": uncached == 0}},
        }

class _WallEngine:
    method = "python_wall_samples"
    units = "samples"
    time_delta_unit = "wall_microseconds"
    coverage = {"frames": "partial", "threads": "partial", "workers": "none", "tasks": "none"}
    def __init__(self, params):
        self.params = params
        self.interval_ns = params["interval_ms"] * 1_000_000
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._frames = _Frames(params["root"], MAX_FRAMES)
        self._stack_index = {}
        self._stacks = []
        self._samples = []
        self._threads = {}
        self._exclude = frozenset()
        self._dropped = 0
        self._stacks_truncated = 0
        self._ticks = 0
        self._missed = 0
        self._gap_total = 0
        self._gap_max = 0
        self._previous = None
        self._failed = False
        self._sealed = False
        self._thread = None
        self._origin = 0
        self._clock = time.perf_counter_ns
    def acquire(self):
        return None
    def start(self):
        self._origin = self._clock()
        self._thread = threading.Thread(target=self._run, name="soundpost-profile-sampler", daemon=True)
        self._thread.start()
    def exclude(self, idents):
        self._exclude = frozenset(idents)
    def _run(self):
        interval = self.interval_ns
        try:
            due = self._clock()
            while not self._stop.is_set():
                self._tick()
                due += interval
                delay = due - self._clock()
                if delay <= 0:
                    due = self._clock()
                elif self._sleep_until(due):
                    break
        except BaseException:
            self._failed = True
    def _sleep_until(self, due):
        # time.sleep has ~1 ms resolution on Windows where Event.wait(timeout) rounds to the ~15.6 ms clock tick;
        # short slices keep the stop flag responsive. Returns True when stop was requested.
        while not self._stop.is_set():
            remaining = due - self._clock()
            if remaining <= 0:
                return False
            time.sleep(min(remaining / 1e9, 0.02))
        return True
    def _tick(self):
        with self._lock:
            if self._sealed:
                return
            now = self._clock()
            if self._previous is not None:
                gap = now - self._previous
                self._gap_total += gap
                self._gap_max = max(self._gap_max, gap)
                if gap > 2 * self.interval_ns:
                    self._missed += gap // self.interval_ns - 1
            self._previous = now
            self._ticks += 1
            current = sys._current_frames()
            top = None
            skip = {threading.get_ident()} | self._exclude
            at = str((now - self._origin) // 1000)
            for ident, top in current.items():
                if ident in skip:
                    continue
                if len(self._samples) >= self.params["max_samples"]:
                    self._dropped += 1
                    continue
                thread = self._threads.get(ident)
                if thread is None:
                    if len(self._threads) >= _THREAD_LIMIT:
                        self._dropped += 1
                        continue
                    thread = self._threads[ident] = str(len(self._threads) + 1)
                stack = self._walk(top)
                if stack is None:
                    self._dropped += 1
                    continue
                self._samples.append({"at_us": at, "stack": stack, "count": "1", "thread": thread})
            del current, top
    def _walk(self, frame):
        indexes = []
        depth = 0
        table = self._frames
        while frame is not None and depth < MAX_STACK_DEPTH:
            index = table.lookup(types.FrameType.f_code.__get__(frame))
            if index == _EXTERNAL:
                index = table.external()
                if indexes and indexes[-1] == index:
                    frame = types.FrameType.f_back.__get__(frame)
                    depth += 1
                    continue
            if index == _FULL:
                return None
            indexes.append(index)
            frame = types.FrameType.f_back.__get__(frame)
            depth += 1
        if frame is not None:
            self._stacks_truncated += 1
        key = tuple(indexes)
        stack = self._stack_index.get(key)
        if stack is None:
            if len(self._stacks) >= MAX_FRAMES:
                return None
            stack = self._stack_index[key] = len(self._stacks)
            self._stacks.append({"frames": list(key)})
        return stack
    def halt(self):
        self._stop.set()
        thread = self._thread
        timed_out = False
        if thread is not None and thread is not threading.current_thread():
            thread.join(max(1.0, 5 * self.interval_ns / 1e9))
            timed_out = thread.is_alive()
        acquired = self._lock.acquire(timeout=1.0)
        try:
            self._sealed = True
            if not acquired:
                return self._unreadable()
            samples, stacks, frames = list(self._samples), list(self._stacks), list(self._frames.frames)
            dropped, truncated_stacks, missed = self._dropped, self._stacks_truncated, self._missed
            ticks, gap_total, gap_max = self._ticks, self._gap_total, self._gap_max
        finally:
            if acquired:
                self._lock.release()
        health = "stop_timeout" if timed_out else "sampler_failed" if self._failed else None
        losses = []
        if dropped:
            losses.append(("truncated", dropped))
        if missed:
            losses.append(("sample_gap", int(missed)))
        if timed_out:
            losses.append(("timeout_cleanup", 1))
        gaps = max(ticks - 1, 0)
        achieved = gap_total // gaps // 1000 if gaps else None
        return {
            "health": health, "frames": frames, "stacks": stacks, "samples": samples, "events": [], "losses": losses,
            "truncated": bool(dropped or truncated_stacks), "timed_out": timed_out,
            "interval": {"requested_us": self.params["interval_ms"] * 1000, "achieved_us": achieved},
            "scope": {"sampler": {"ticks": ticks, "mean_gap_us": achieved, "max_gap_us": gap_max // 1000 if gaps else None, "thread_excluded": True},
                      "stack_depth_limit": MAX_STACK_DEPTH, "stacks_truncated": truncated_stacks, "line_semantics": "function_first_line",
                      "thread_ids": "ordinal", "bias": {"gil_acquisition": True, "native_time_attributed_to_python_caller": True, "suspended_tasks_unobserved": True}},
        }
    def _unreadable(self):
        return {"health": "stop_timeout", "frames": [], "stacks": [], "samples": [], "events": [], "losses": [("timeout_cleanup", 1)], "truncated": False, "timed_out": True,
                "interval": {"requested_us": self.params["interval_ms"] * 1000, "achieved_us": None},
                "scope": {"sampler": {"ticks": 0, "mean_gap_us": None, "max_gap_us": None, "thread_excluded": True}, "stack_depth_limit": MAX_STACK_DEPTH, "stacks_truncated": 0,
                          "line_semantics": "function_first_line", "thread_ids": "ordinal", "bias": {"gil_acquisition": True, "native_time_attributed_to_python_caller": True, "suspended_tasks_unobserved": True}}}

# ------------------------------------------------------------------ lease

def _empty_result(requested_us=None):
    return {"health": None, "frames": [], "stacks": [], "samples": [], "events": [], "losses": [], "truncated": False,
            "interval": {"requested_us": requested_us, "achieved_us": None}, "scope": {}}

class ProfileLease:
    """One bounded profile run. ``stop``/``close`` are idempotent and always release every runtime facility."""
    def __init__(self, client, method, requested, units, time_delta_unit):
        self._client = client
        self._method = method
        self._requested = requested
        self._units = units
        self._time_delta_unit = time_delta_unit
        self._lock = threading.Lock()
        self._halted = threading.Event()
        self._started = threading.Event()
        self._client_finished = threading.Event()
        self._state = "new"
        self._engine = None
        self._timer = None
        self._report = None
        self._capability = None
        self._identity = _runtime_identity()
        self._id = secrets.token_hex(16)
        self._domain = {key: secrets.token_hex(16) for key in ("host", "boot", "runtime")}
        self._wall_start = time.time_ns()
        self._client_done = False
        self._loss_attempted = False
        self._loss_admitted = False
        self._ack_done = False
    @property
    def capability(self):
        return copy.deepcopy(self._capability)
    @property
    def active(self):
        return self._state in ("running", "halting")
    def stop(self):
        """Stop (if running) and return the report. Safe to call repeatedly and from any thread."""
        self._halt("caller")
        self._finish_client_side(wait=True)
        self._acknowledge()
        return copy.deepcopy(self._report)
    def close(self):
        """Stop and release without a report. ``Client.close`` calls this while holding the client lock, so it never waits on it."""
        self._halt("client_close" if getattr(self._client, "_closed", False) is True else "caller")
        self._finish_client_side(wait=False)
        return None
    # -- report construction
    def _capability_for(self, status, reason, coverage):
        return {"id": self._id, "runtime": self._identity["runtime"], "version": self._identity["version"], "build": self._identity["build"],
                "os": self._identity["os"], "arch": self._identity["arch"], "signal": "profile_chunk", "method": self._method, "status": status, "reason": reason,
                "coverage": dict(coverage), "clock_domain": dict(self._domain), "expires_ns": str(self._wall_start + CAPABILITY_TTL_NS)}
    def _build_report(self, result, stopped_by, wall_end, status, reason, coverage):
        self._capability = self._capability_for(status, reason, coverage)
        scope = {"runtime": {"name": "cpython", "version": self._identity["version"]}, "process": "current"}
        scope.update(result["scope"])
        self._report = {
            "version": 1, "method": self._method, "profile": True, "units": self._units, "time_delta_unit": self._time_delta_unit,
            "capability": copy.deepcopy(self._capability), "interval": result["interval"],
            "clock": {"domain": dict(self._domain), "uncertainty_ns": UNCERTAINTY_NS, "source": "perf_counter_ns", "wall_start_ns": str(self._wall_start), "wall_end_ns": str(wall_end)},
            "scope": scope, "frames": result["frames"], "stacks": result["stacks"], "stack_order": "leaf_first", "samples": result["samples"], "events": result["events"],
            "sample_count": len(result["samples"]), "truncated": result["truncated"], "losses": [{"reason": name, "count": str(count)} for name, count in result["losses"]],
            "non_profile": [], "ack": {"status": "not_available", "reason": "not_requested"}, "stopped_by": stopped_by, "requested": dict(self._requested),
        }
    def _refuse(self, status, reason):
        interval = self._requested.get("interval_ms")
        self._build_report(_empty_result(interval * 1000 if interval else None), "not_started", self._wall_start, status, reason, _COVERAGE_NONE)
        self._state = "halted"
        self._started.set()
        self._halted.set()
    # -- teardown
    def _halt(self, stopped_by):
        self._started.wait(10.0)
        with self._lock:
            winner = self._state == "running"
            if winner:
                self._state = "halting"
        if not winner:
            if self._state == "halting":
                self._halted.wait(10.0)
            return
        timer = self._timer
        try:
            if timer is not None:
                timer.cancel()
            result = self._engine.halt()
            if result.get("timed_out") and stopped_by != "client_close":
                stopped_by = "timeout_cleanup"
            status, reason = ("supported", "ok") if result["health"] is None else ("error", result["health"])
            self._build_report(result, stopped_by, time.time_ns(), status, reason, self._engine.coverage)
        except BaseException:
            self._build_report(_empty_result(), stopped_by, time.time_ns(), "error", "sampler_failed", _COVERAGE_NONE)
        finally:
            registry = _registry()
            with registry["lock"]:
                if registry["owner"] is self:
                    registry["owner"] = None
            with self._lock:
                self._state = "halted"
            self._halted.set()
        if timer is not None and timer is not threading.current_thread():
            timer.join(1.0)
    def _auto_stop(self):
        self._halt("duration")
        self._finish_client_side(wait=False)
    def _finish_client_side(self, wait):
        """Release the client's hook-lease slot and report reportable losses, exactly once."""
        with self._lock:
            if self._state != "halted":
                return
            first = not self._client_done
            self._client_done = True
        if not first:
            if wait:
                self._client_finished.wait(10.0)
            return
        try:
            release = getattr(self._client, "_release_hook_lease", None)
            if release is not None:
                release(self)
            losses = self._reportable_losses()
            if losses:
                self._loss_attempted = True
                record = getattr(self._client, "_record_signal_loss", None)
                admitted = True
                for reason, count in losses:
                    try:
                        admitted = bool(record("profile_chunk", reason, count)) and admitted
                    except Exception:
                        admitted = False
                self._loss_admitted = admitted
        except Exception:
            pass
        finally:
            self._client_finished.set()
    def _reportable_losses(self):
        losses = [(loss["reason"], int(loss["count"])) for loss in self._report["losses"] if loss["reason"] == "truncated"]
        if self._report["capability"]["status"] == "unsupported":
            losses.append(("unsupported", 1))
        return losses
    def _acknowledge(self):
        with self._lock:
            if self._ack_done or not self._client_finished.is_set():
                return
            self._ack_done = True
        if not self._loss_attempted:
            ack = {"status": "not_available", "reason": "no_loss_recorded"}
        elif not self._loss_admitted:
            ack = {"status": "not_available", "reason": "loss_not_admitted"}
        else:
            try:
                flushed = self._client.flush(_ACK_TIMEOUT_S)
                cursors = [cursor for cursor in flushed.acknowledged_cursors if type(cursor) is str]
                if cursors:
                    ack = {"status": "obtained", "cursors": cursors}
                else:
                    ack = {"status": "failed", "reason": "flush_deadline_exceeded" if flushed.deadline_exceeded else "no_acknowledged_cursor"}
            except Exception:
                ack = {"status": "failed", "reason": "flush_error"}
        self._report["ack"] = ack

class _Refusal(Exception):
    def __init__(self, status, reason):
        super().__init__(reason)
        self.status, self.reason = status, reason

def _refused(client, method, requested, status, reason):
    lease = ProfileLease(client, method, requested, "events" if method == "python_monitoring" else "samples", "wall_microseconds" if method == "python_wall_samples" else None)
    lease._refuse(status, reason)
    lease._finish_client_side(wait=True)
    return lease

def _requested(params, method):
    echo = {"duration_s": params["duration_s"]}
    if method == "python_wall_samples":
        echo.update(interval_ms=params["interval_ms"], max_samples=params["max_samples"])
    else:
        echo.update(max_events=params["max_events"], max_code_objects=params["max_code_objects"])
    return echo

def start_profile(options, client):
    """Start an explicit bounded profile. Expected failures return a refused lease and never raise."""
    try:
        return _start(options, client)
    except Exception:
        method = getattr(options, "method", None)
        return _refused(None, method if method in METHODS else "unknown", {}, "error", "sampler_failed")

def _start(options, client):
    params = _validate(options)
    method = options.method if type(options) is ProfileOptions and options.method in METHODS else "unknown"
    if params is None:
        return _refused(client, method, {}, "denied", "invalid_options")
    requested = _requested(params, method)
    if params["root"] is None:
        params["root"] = getattr(client, "_project_root", None)
    if sysconfig.get_config_var("Py_GIL_DISABLED") or getattr(sys, "_is_gil_enabled", lambda: True)() is False:
        return _refused(client, method, requested, "unsupported", "free_threaded_unqualified")
    if method == "python_monitoring" and getattr(sys, "monitoring", None) is None:
        return _refused(client, method, requested, "unsupported", "sys_monitoring_unavailable")
    if method == "python_monitoring" and params["root"] is None:
        return _refused(client, method, {}, "denied", "invalid_options")
    own = getattr(client, "_own_hook_lease", None)
    if not callable(own):
        return _refused(client, method, requested, "denied", "client_unavailable")
    engine = _MonitoringEngine(params) if method == "python_monitoring" else _WallEngine(params)
    lease = ProfileLease(client, method, requested, engine.units, engine.time_delta_unit)
    registry = _registry()
    with registry["lock"]:
        claimed = registry["owner"] is None
        if claimed:
            registry["owner"] = lease
    if not claimed:
        return _refused(client, method, requested, "denied", "profiler_owned")
    registered = False
    try:
        problem = engine.acquire()
        if problem is not None:
            raise _Refusal("denied", problem)
        try:
            own(lease)
        except Exception:
            raise _Refusal("denied", "client_unavailable") from None
        registered = True
        lease._engine = engine
        # The timer starts first so its ident can be excluded from wall samples; _halt waits on `_started`.
        timer = threading.Timer(params["duration_s"], lease._auto_stop)
        timer.name = "soundpost-profile-timer"
        timer.daemon = True
        lease._timer = timer
        timer.start()
        if method == "python_wall_samples":
            engine.exclude((timer.ident,))
        engine.start()
        lease._capability = lease._capability_for("supported", "ok", engine.coverage)
        lease._state = "running"
        lease._started.set()
        return lease
    except _Refusal as refusal:
        status, reason = refusal.status, refusal.reason
    except Exception:
        status, reason = "error", "sampler_failed"
    # Startup failed: undo every partial effect, then report the refusal through a refused lease.
    if lease._timer is not None:
        lease._timer.cancel()
    try:
        engine.halt()
    except Exception:
        pass
    with registry["lock"]:
        if registry["owner"] is lease:
            registry["owner"] = None
    lease._started.set()
    if registered:
        try:
            client._release_hook_lease(lease)
        except Exception:
            pass
    return _refused(client, method, requested, status, reason)
