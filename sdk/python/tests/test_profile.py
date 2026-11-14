# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
"""Runtime profile supplements: real sys.monitoring / sys._current_frames behavior, ownership, cleanup and honest states.

Fakes used here: a hand-written `Ledger` receipt transport (shared with test_delivery.py) for the ACK cases and
foreign sys.monitoring tools registered by the tests themselves. Everything else is the real client and real runtime.
"""
import ast
import asyncio
import base64
import importlib.util
import json
import platform
import re
import socket
import sys
import sysconfig
import threading
import time
import types
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
import pytest
from test_policy import KEY, b64, config
from test_delivery import Ledger
from soundpost import SignedPolicy, init
from soundpost import profile as P
from soundpost.profile import ProfileOptions, start_profile
from soundpost.transport import Outcome
from soundpost.wire import parse_safe_record

MON = getattr(sys, "monitoring", None)
needs_monitoring = pytest.mark.skipif(MON is None or bool(sysconfig.get_config_var("Py_GIL_DISABLED")), reason="sys.monitoring/GIL build required")
TOP_KEYS = {"version", "method", "profile", "units", "time_delta_unit", "capability", "interval", "clock", "scope", "frames", "stacks", "stack_order", "samples", "events", "sample_count", "truncated", "losses", "non_profile", "ack", "stopped_by", "requested"}
CAPABILITY_KEYS = {"id", "runtime", "version", "build", "os", "arch", "signal", "method", "status", "reason", "coverage", "clock_domain", "expires_ns"}
PLACEHOLDER = {"module_id": "external", "function": "", "artifact_id": "", "offset": "0", "reason": "not_captured"}
SAFE_CODE = re.compile(r"[A-Za-z0-9_.:/<>+ $-]+")
LOSS_REASONS = {"truncated", "sample_gap", "foreign_state", "timeout_cleanup"}
WALL = "python_wall_samples"
MONITORING = "python_monitoring"

APP = '''
import time
def busy(n):
    total = 0
    for i in range(n):
        total += i * i
    return total
def sleepy(seconds):
    time.sleep(seconds)
def read_blocking(sock):
    return sock.recv(1)
def boom(message):
    raise ValueError(message)
def gen3():
    yield 1
    yield 2
    yield 3
def uses_external(seconds):
    return EXT.ext_outer(seconds)
def recurse(depth, seconds):
    if depth == 0:
        time.sleep(seconds)
        return None
    return recurse(depth - 1, seconds)
def returns_value(value):
    return value
def raises_value(error):
    raise error
def with_locals(secret_arg, *, secret_kw="CANARY_KW"):
    secret_local = "CANARY_LOCAL"
    time.sleep(0.2)
    return len(secret_local) + len(secret_arg) + len(secret_kw)
def f1(): return 1
def f2(): return 2
def f3(): return 3
def f4(): return 4
def f5(): return 5
'''
EXTERNAL = '''
import time
def ext_inner(seconds):
    end = time.perf_counter() + seconds
    while time.perf_counter() < end:
        pass
def ext_middle(seconds):
    ext_inner(seconds)
def ext_outer(seconds):
    ext_middle(seconds)
'''
UNSAFE = '''
def \u043a\u043b\u044e\u0447_symbol():
    import time
    time.sleep(0.2)
'''
ASYNC = '''
import asyncio
async def waiter_co(seconds):
    await asyncio.sleep(seconds)
async def main_co(seconds):
    task = asyncio.ensure_future(waiter_co(seconds))
    await asyncio.sleep(seconds)
    await task
def runner(seconds):
    asyncio.run(main_co(seconds))
'''

def _registry():
    return vars(sys).get(P.REGISTRY_KEY)

@pytest.fixture(autouse=True)
def isolation():
    """Every test must leave no lease, no tool ID and no profile thread behind."""
    before = [MON.get_tool(i) for i in (2, 3, 4)] if MON else []
    yield
    registry = _registry()
    leaked = registry["owner"] if registry else None
    if leaked is not None:
        leaked.close()
    assert leaked is None, "test leaked a running profile lease"
    if MON:
        assert [MON.get_tool(i) for i in (2, 3, 4)] == before
    deadline = time.time() + 2
    while time.time() < deadline and [t for t in threading.enumerate() if t.name.startswith("soundpost-profile")]:
        time.sleep(0.01)
    assert not [t for t in threading.enumerate() if t.name.startswith("soundpost-profile")]

@pytest.fixture
def client():
    instance = init(config())
    yield instance
    instance.close()

class Workspace:
    def __init__(self, tmp_path):
        self.root = str(tmp_path / "project")
        self.other = str(tmp_path / "elsewhere")
        self.ext = self.load(self.other, "ext_lib.py", EXTERNAL)
        self.app = self.load(self.root, "app.py", APP, EXT=self.ext)
    @staticmethod
    def load(base, name, source, **extra):
        namespace = dict(extra)
        exec(compile(source, str(Path(base) / name), "exec"), namespace)
        return types.SimpleNamespace(**namespace)

@pytest.fixture
def work(tmp_path):
    return Workspace(tmp_path)

def options(work, **changes):
    values = dict(method=WALL, duration_s=30, interval_ms=2, project_root=work.root)
    values.update(changes)
    return ProfileOptions(**values)

def spin(app, seconds):
    end = time.perf_counter() + seconds
    while time.perf_counter() < end:
        app.busy(2000)

def functions(report, sample):
    return [report["frames"][index]["function"] for index in report["stacks"][sample["stack"]]["frames"]]

def rows(report):
    return {(report["frames"][row["frame"]]["function"], row["kind"]): int(row["count"]) for row in report["events"]}

def assert_report_shape(report):
    assert set(report) == TOP_KEYS
    assert report["version"] == 1 and report["profile"] is True and report["stack_order"] == "leaf_first"
    capability = report["capability"]
    assert set(capability) == CAPABILITY_KEYS and capability["method"] == report["method"]
    assert capability["signal"] == "profile_chunk" and capability["reason"] and capability["status"] in ("supported", "denied", "unsupported", "error")
    assert report["clock"]["domain"] == capability["clock_domain"] and report["clock"]["uncertainty_ns"] == "18446744073709551615"
    start, end = report["clock"]["wall_start_ns"], report["clock"]["wall_end_ns"]
    assert start.isdigit() and end.isdigit() and int(end) >= int(start) and capability["expires_ns"] == str(int(start) + 3600 * 10**9)
    assert report["sample_count"] == len(report["samples"])
    for frame in report["frames"]:
        assert frame == PLACEHOLDER or set(frame) == {"module_id", "function", "artifact_id", "line", "column", "offset", "reason"} and frame["offset"] == "0"
    for stack in report["stacks"]:
        assert 0 < len(stack["frames"]) <= 128 and all(type(i) is int and 0 <= i < len(report["frames"]) for i in stack["frames"])
    last = -1
    for sample in report["samples"]:
        assert set(sample) == {"at_us", "stack", "count", "thread"} and sample["count"] == "1" and sample["at_us"].isdigit() and sample["thread"].isdigit()
        assert 0 <= sample["stack"] < len(report["stacks"]) and int(sample["at_us"]) >= last
        last = int(sample["at_us"])
    for row in report["events"]:
        assert set(row) == {"frame", "kind", "count"} and row["kind"] in ("PY_START", "PY_RESUME", "PY_RETURN", "PY_UNWIND") and int(row["count"]) > 0
    for loss in report["losses"]:
        assert set(loss) == {"reason", "count"} and loss["reason"] in LOSS_REASONS and loss["count"].isdigit() and int(loss["count"]) > 0
    assert report["ack"]["status"] in ("not_available", "obtained", "failed")
    assert report["stopped_by"] in ("caller", "duration", "client_close", "timeout_cleanup", "not_started")
    json.dumps(report)

def assert_refused(report, status, reason, method):
    assert_report_shape(report)
    assert report["method"] == method and report["capability"]["status"] == status and report["capability"]["reason"] == reason
    assert report["frames"] == [] and report["stacks"] == [] and report["samples"] == [] and report["events"] == []
    assert report["sample_count"] == 0 and report["stopped_by"] == "not_started" and report["losses"] == []
    assert report["capability"]["coverage"] == {"frames": "none", "threads": "none", "workers": "none", "tasks": "none"}

# ---------------------------------------------------------------- wall samples

def test_wall_samples_attribute_busy_sleep_and_socket_wait_to_python_callers(work, client):
    left, right = socket.socketpair()
    lease = start_profile(options(work), client)
    try:
        assert lease.active and lease.capability["status"] == "supported" and lease.capability["reason"] == "ok"
        sleeper = threading.Thread(target=work.app.sleepy, args=(0.5,))
        reader = threading.Thread(target=work.app.read_blocking, args=(left,))
        sleeper.start(); reader.start()
        alive = len(threading.enumerate())
        spin(work.app, 0.5)
        right.send(b"x"); sleeper.join(); reader.join()
    finally:
        report = lease.stop(); left.close(); right.close()
    assert_report_shape(report)
    assert report["units"] == "samples" and report["time_delta_unit"] == "wall_microseconds" and report["stopped_by"] == "caller"
    assert report["capability"]["status"] == "supported" and report["events"] == [] and report["sample_count"] > 20
    leaf = [functions(report, sample)[0] for sample in report["samples"]]
    assert leaf.count("busy") > 5 and leaf.count("sleepy") > 5 and leaf.count("read_blocking") > 5
    # Blocking native calls are attributed to the calling Python frame; there is no native/off-CPU frame.
    assert all(frame["function"] != "recv" and frame["function"] != "sleep" for frame in report["frames"])
    # main + sleeper + reader are sampled; the sampler and the lease's own timer thread never are.
    assert 3 <= len({sample["thread"] for sample in report["samples"]}) <= alive - 2
    assert report["interval"]["requested_us"] == 2000 and 0 < report["interval"]["achieved_us"] < 1_000_000
    assert report["scope"]["sampler"]["max_gap_us"] >= report["interval"]["achieved_us"]
    # at_us is wall microseconds since report start: first sample near the start, last near the measured elapsed time.
    elapsed_us = (int(report["clock"]["wall_end_ns"]) - int(report["clock"]["wall_start_ns"])) // 1000
    first, last = int(report["samples"][0]["at_us"]), int(report["samples"][-1]["at_us"])
    assert 0 <= first < 250_000 and 300_000 < last <= elapsed_us + 100_000

def test_wall_coverage_and_bias_are_truthful_and_machine_readable(work, client):
    lease = start_profile(options(work), client)
    spin(work.app, 0.05)
    report = lease.stop()
    assert report["capability"]["coverage"] == {"frames": "partial", "threads": "partial", "workers": "none", "tasks": "none"}
    assert report["scope"]["bias"] == {"gil_acquisition": True, "native_time_attributed_to_python_caller": True, "suspended_tasks_unobserved": True}
    assert report["scope"]["runtime"] == {"name": "cpython", "version": platform.python_version()} and "tool_id" not in report["scope"]
    assert report["scope"]["sampler"]["thread_excluded"] is True and report["scope"]["stack_depth_limit"] == 128
    assert report["requested"] == {"duration_s": 30, "interval_ms": 2, "max_samples": 8192}

def test_wall_sampler_excludes_itself_and_reports_gil_held_gaps(work, client):
    previous = sys.getswitchinterval()
    sys.setswitchinterval(0.05)
    lease = start_profile(options(work, interval_ms=2, project_root=str(Path(P.__file__).parent)), client)
    try:
        spin(work.app, 0.6)
    finally:
        report = lease.stop(); sys.setswitchinterval(previous)
    gaps = [loss for loss in report["losses"] if loss["reason"] == "sample_gap"]
    assert len(gaps) == 1 and int(gaps[0]["count"]) >= 1
    assert int(gaps[0]["count"]) <= 300
    assert report["scope"]["sampler"]["max_gap_us"] >= 4000 and report["interval"]["achieved_us"] > 2000
    sampled = {name for s in report["samples"] for name in functions(report, s)}
    assert sampled and not {name for name in sampled if name.startswith("_WallEngine._run") or name.startswith("_WallEngine._tick")}

def test_wall_stacks_are_leaf_first_collapse_external_frames_and_have_no_task_ancestry(work, client):
    lease = start_profile(options(work), client)
    work.app.uses_external(0.3)
    report = lease.stop()
    assert PLACEHOLDER in report["frames"]
    external_leaf = [s for s in report["samples"] if report["frames"][report["stacks"][s["stack"]]["frames"][0]] == PLACEHOLDER]
    assert len(external_leaf) > 5
    for sample in external_leaf:
        frames = report["stacks"][sample["stack"]]["frames"]
        # ext_inner/ext_middle/ext_outer are all outside the project: collapsed to one adjacent placeholder.
        assert all(not (a == b and report["frames"][a] == PLACEHOLDER) for a, b in zip(frames, frames[1:]))
    assert all(frame["function"] not in ("ext_inner", "ext_middle", "ext_outer") for frame in report["frames"])
    assert any("uses_external" in functions(report, s) for s in external_leaf)
    assert all(frame["module_id"] == "external" or not frame["module_id"].startswith(("/", "C:")) for frame in report["frames"])

def test_wall_deep_recursion_is_stack_bounded_and_marks_truncation(work, client):
    worker = threading.Thread(target=work.app.recurse, args=(300, 0.4))
    lease = start_profile(options(work), client)
    worker.start(); worker.join()
    report = lease.stop()
    assert max(len(s["frames"]) for s in report["stacks"]) == 128
    assert report["scope"]["stacks_truncated"] > 0 and report["truncated"] is True
    assert report["scope"]["stack_depth_limit"] == 128

def test_wall_sample_cap_reports_derived_dropped_count(work, client):
    lease = start_profile(options(work, max_samples=5), client)
    spin(work.app, 0.4)
    report = lease.stop()
    assert report["sample_count"] == 5 and report["truncated"] is True
    dropped = [loss for loss in report["losses"] if loss["reason"] == "truncated"]
    assert len(dropped) == 1 and int(dropped[0]["count"]) > 5
    assert report["requested"]["max_samples"] == 5

def synthetic_engine(work, interval_ms, ticks):
    params = P._validate(options(work, interval_ms=interval_ms))
    engine = P._WallEngine(params)
    clock = iter(ticks)
    engine._clock = lambda: next(clock)
    return engine

def test_wall_gap_accounting_is_derived_from_the_requested_interval(work):
    ms = 1_000_000
    # Gaps (ms): 10, 10.5, 20 (exactly 2x: not a gap), 20.5 (1 missed), 59 (4 missed).
    times = [0, 10 * ms, int(20.5 * ms), int(40.5 * ms), 61 * ms, 120 * ms]
    engine = synthetic_engine(work, 10, times)
    engine._origin = 0
    for _ in times:
        engine._tick()
    result = engine.halt()
    assert result["losses"] == [("sample_gap", 5)]
    assert result["interval"] == {"requested_us": 10_000, "achieved_us": 24_000}
    assert result["scope"]["sampler"] == {"ticks": 6, "mean_gap_us": 24_000, "max_gap_us": 59_000, "thread_excluded": True}

def test_monitoring_callbacks_disable_only_foreign_locations_and_never_unwind(work):
    engine = P._MonitoringEngine(P._validate(options(work, method=MONITORING)))
    engine._disable = object()
    assert engine._hit(work.ext.ext_inner.__code__, 0) is engine._disable and engine._hit(work.ext.ext_inner.__code__, 2) is engine._disable
    assert engine._hit(work.ext.ext_inner.__code__, 3) is None
    assert engine._hit(work.app.busy.__code__, 0) is None and engine._hit(work.app.busy.__code__, 3) is None

def test_monitoring_sibling_directory_sharing_a_prefix_is_not_project_code(tmp_path, client):
    root = str(tmp_path / "project")
    sibling = Workspace.load(str(tmp_path / "project2"), "lib.py", "import time\ndef sneaky():\n    time.sleep(0.2)\n")
    mine = Workspace.load(root, "mine.py", "def inside():\n    return 1\n")
    assert mine.inside() == 1
    lease = start_profile(ProfileOptions(method=MONITORING, duration_s=10, project_root=root), client)
    sibling.sneaky(); mine.inside()
    report = lease.stop()
    assert {frame["function"] for frame in report["frames"]} == {"inside"}

def test_wall_sampler_that_cannot_stop_is_reported_without_blocking_forever(work, client, monkeypatch):
    monkeypatch.setattr(P._WallEngine, "_tick", lambda self: time.sleep(1.5))
    lease = start_profile(options(work), client)
    time.sleep(0.05)
    started = time.perf_counter()
    result = []
    stopper = threading.Thread(target=lambda: result.append(lease.stop()))
    stopper.start()
    time.sleep(0.3)
    # Teardown is pending: the lease still owns the runtime, so nothing else may start a profiler yet.
    assert lease.active and _registry()["owner"] is lease
    assert_refused(start_profile(options(work), client).stop(), "denied", "profiler_owned", WALL)
    stopper.join()
    report = result[0]
    assert time.perf_counter() - started < 1.4
    assert report["stopped_by"] == "timeout_cleanup" and report["capability"]["status"] == "error" and report["capability"]["reason"] == "stop_timeout"
    assert {"reason": "timeout_cleanup", "count": "1"} in report["losses"]
    assert _registry()["owner"] is None and lease not in client._hook_leases

def test_wall_sampler_failure_is_a_typed_error_not_an_exception(work, client, monkeypatch):
    def broken(self):
        raise RuntimeError("CANARY_SAMPLER")
    monkeypatch.setattr(P._WallEngine, "_tick", broken)
    lease = start_profile(options(work), client)
    time.sleep(0.05)
    report = lease.stop()
    assert report["capability"]["status"] == "error" and report["capability"]["reason"] == "sampler_failed" and "CANARY_SAMPLER" not in json.dumps(report)
    assert report["sample_count"] == 0

def test_wall_suspended_asyncio_tasks_are_never_invented(tmp_path, work, client):
    asyncio_app = work.load(work.root, "aio.py", ASYNC)
    lease = start_profile(options(work), client)
    asyncio_app.runner(0.7)
    report = lease.stop()
    settled = [s for s in report["samples"] if 100_000 <= int(s["at_us"]) <= 500_000]
    seen = [functions(report, s) for s in settled]
    assert sum("runner" in names for names in seen) > 5
    assert all("waiter_co" not in names and "main_co" not in names for names in seen)
    assert report["capability"]["coverage"]["tasks"] == "none"

def test_wall_never_reads_locals_or_leaks_paths(tmp_path, work, client):
    unsafe = work.load(work.root, "unsafe_symbol.py", UNSAFE)
    hidden = work.load(work.root, "bad name.py", "def spaced():\n    import time\n    time.sleep(0.2)\n")
    lease = start_profile(options(work), client)
    thread = threading.Thread(target=work.app.with_locals, args=("CANARY_ARG",), kwargs={"secret_kw": "CANARY_KW"}, name="CANARY_THREAD_NAME")
    thread.start()
    getattr(unsafe, "\u043a\u043b\u044e\u0447_symbol")()
    hidden.spaced()
    thread.join()
    report = lease.stop()
    text = json.dumps(report)
    for needle in ("CANARY", str(tmp_path), tmp_path.as_posix(), work.root, json.dumps(work.root)[1:-1], "elsewhere"):
        assert needle not in text
    assert {"module_id": "unsafe_symbol.py", "function": "", "artifact_id": "unsafe_symbol.py", "line": 2, "column": None, "offset": "0", "reason": "not_captured"} in report["frames"]
    assert not any(frame["module_id"] == "bad name.py" for frame in report["frames"])
    assert any(frame["function"] == "with_locals" and frame["module_id"] == "app.py" for frame in report["frames"])

# ---------------------------------------------------------------- monitoring

@needs_monitoring
def test_monitoring_counts_exact_deterministic_events_across_threads(work, client):
    left, right = socket.socketpair()
    lease = start_profile(options(work, method=MONITORING), client)
    assert lease.active
    for _ in range(7):
        work.app.busy(1000)
    for _ in range(3):
        with pytest.raises(ValueError):
            work.app.boom("CANARY_EXC")
    assert list(work.app.gen3()) == [1, 2, 3]
    work.app.sleepy(0.05)
    reader = threading.Thread(target=work.app.read_blocking, args=(left,))
    reader.start(); right.send(b"x"); reader.join()
    worker = threading.Thread(target=work.app.busy, args=(10,)); worker.start(); worker.join()
    work.app.uses_external(0.01)
    report = lease.stop()
    left.close(); right.close()
    assert_report_shape(report)
    counts = rows(report)
    assert counts[("busy", "PY_START")] == 8 and counts[("busy", "PY_RETURN")] == 8
    assert counts[("boom", "PY_START")] == 3 and counts[("boom", "PY_UNWIND")] == 3 and ("boom", "PY_RETURN") not in counts
    assert counts[("gen3", "PY_START")] == 1 and counts[("gen3", "PY_RESUME")] == 3 and counts[("gen3", "PY_RETURN")] == 1
    assert counts[("sleepy", "PY_START")] == 1 and counts[("read_blocking", "PY_RETURN")] == 1
    assert counts[("uses_external", "PY_START")] == 1
    assert report["units"] == "events" and report["time_delta_unit"] is None and report["method"] == MONITORING
    assert report["samples"] == [] and report["stacks"] == [] and report["sample_count"] == 0
    assert report["interval"] == {"requested_us": None, "achieved_us": None}
    assert report["requested"] == {"duration_s": 30, "max_events": 16384, "max_code_objects": 4096}
    assert not any(frame["module_id"] == "external" or frame["function"].startswith("ext_") for frame in report["frames"])
    assert report["capability"]["coverage"] == {"frames": "partial", "threads": "complete", "workers": "none", "tasks": "none"}
    assert report["losses"] == [] and report["truncated"] is False

@needs_monitoring
def test_monitoring_callbacks_never_touch_returned_or_raised_values(work, client):
    calls = []
    def trap(name):
        def method(self, *args, **kwargs):
            calls.append(name)
            raise AssertionError(name)
        return method
    namespace = {name: trap(name) for name in ("__repr__", "__str__", "__eq__", "__ne__", "__hash__", "__bool__", "__len__", "__iter__", "__getattr__", "__getitem__", "__format__", "__lt__", "__contains__", "__int__", "__index__", "__del__")}
    del namespace["__del__"]
    Hostile = type("Hostile", (), namespace)
    HostileError = type("HostileError", (Exception,), {name: trap(name) for name in ("__repr__", "__str__", "__eq__", "__hash__", "__getattr__", "__bool__")})
    value = Hostile()
    error = HostileError()
    lease = start_profile(options(work, method=MONITORING), client)
    try:
        for _ in range(3):
            work.app.returns_value(value)
            try:
                work.app.raises_value(error)
            except HostileError:
                pass
    finally:
        report = lease.stop()
    assert calls == []
    counts = rows(report)
    assert counts[("returns_value", "PY_RETURN")] == 3 and counts[("raises_value", "PY_UNWIND")] == 3
    assert report["scope"]["callback_errors"] == 0

@needs_monitoring
def test_monitoring_callback_failure_never_reaches_the_application(work, client, monkeypatch):
    def broken(code, root):
        raise RuntimeError("CANARY_INTERNAL")
    monkeypatch.setattr(P, "_identity", broken)
    lease = start_profile(options(work, method=MONITORING), client)
    try:
        assert work.app.busy(10) == 285
    finally:
        report = lease.stop()
    assert report["scope"]["callback_errors"] >= 1 and "CANARY_INTERNAL" not in json.dumps(report)
    assert report["capability"]["status"] == "supported" and report["events"] == []

@needs_monitoring
def test_monitoring_coexists_with_occupied_tool_ids_and_leaves_their_state_intact(work, client):
    seen, kept = [], []
    MON.use_tool_id(2, "foreign-profiler")
    try:
        MON.register_callback(2, MON.events.PY_START, lambda code, offset: seen.append(code.co_name))
        MON.set_events(2, MON.events.PY_START)
        lease = start_profile(options(work, method=MONITORING), client)
        assert lease.active and lease.capability["status"] == "supported"
        assert MON.get_tool(2) == "foreign-profiler" and MON.get_tool(3) is not None
        work.app.busy(5); work.app.uses_external(0.01)
        report = lease.stop()
        assert rows(report)[("busy", "PY_START")] == 1
        # The foreign tool kept firing for project AND external code while we ran (our DISABLE is per tool).
        assert "busy" in seen and "ext_inner" in seen
        assert MON.get_tool(3) is None and MON.get_events(2) == MON.events.PY_START
        before = len(seen)
        work.app.busy(5)
        assert len(seen) > before
    finally:
        MON.set_events(2, 0); MON.register_callback(2, MON.events.PY_START, None); MON.free_tool_id(2)

@needs_monitoring
def test_monitoring_frees_its_tool_id_on_interpreters_without_clear_tool_id(work, client, monkeypatch):
    # sys.monitoring.clear_tool_id exists only from CPython 3.14; on 3.12/3.13 the stop path must still free the ID.
    monkeypatch.delattr(MON, "clear_tool_id", raising=False)
    lease = start_profile(options(work, method=MONITORING), client)
    assert lease.active
    work.app.busy(5)
    report = lease.stop()
    assert rows(report)[("busy", "PY_START")] == 1 and "foreign_state" not in {loss["reason"] for loss in report["losses"]}
    assert [MON.get_tool(tool) for tool in (2, 3, 4)] == [None, None, None]

@needs_monitoring
def test_monitoring_refuses_when_every_allowed_tool_id_is_occupied(work, client):
    fired = []
    for tool in (2, 3, 4):
        MON.use_tool_id(tool, f"foreign-{tool}")
    try:
        MON.register_callback(3, MON.events.PY_START, lambda code, offset: fired.append(1))
        MON.set_events(3, MON.events.PY_START)
        lease = start_profile(options(work, method=MONITORING), client)
        assert not lease.active
        report = lease.stop()
        assert_refused(report, "denied", "monitoring_tool_ids_occupied", MONITORING)
        work.app.busy(1)
        assert fired and [MON.get_tool(t) for t in (2, 3, 4)] == ["foreign-2", "foreign-3", "foreign-4"]
        assert MON.get_events(3) == MON.events.PY_START
        assert _registry()["owner"] is None
    finally:
        MON.set_events(3, 0); MON.register_callback(3, MON.events.PY_START, None)
        for tool in (2, 3, 4):
            MON.free_tool_id(tool)
    again = start_profile(options(work), client)
    assert again.active
    again.stop()

@needs_monitoring
def test_monitoring_takes_first_free_id_in_profiler_order(work, client):
    MON.use_tool_id(2, "foreign")
    try:
        lease = start_profile(options(work, method=MONITORING), client)
        assert lease.capability["status"] == "supported" and lease.stop()["scope"]["tool_id"] == 3
    finally:
        MON.free_tool_id(2)
    lease = start_profile(options(work, method=MONITORING), client)
    assert lease.stop()["scope"]["tool_id"] == 2

@needs_monitoring
def test_monitoring_restores_disabled_locations_so_next_profile_sees_them(work, client):
    other = Workspace.load(work.other, "second_app.py", "def later():\n    return 1\n")
    first = start_profile(options(work, method=MONITORING), client)
    other.later(); work.app.busy(1)
    first.stop()
    second = start_profile(options(work, method=MONITORING, project_root=work.other), client)
    other.later()
    report = second.stop()
    assert rows(report) == {("later", "PY_START"): 1, ("later", "PY_RETURN"): 1}

@needs_monitoring
def test_monitoring_code_object_cap_counts_dropped_objects_once(work, client):
    lease = start_profile(options(work, method=MONITORING, max_code_objects=2), client)
    for _ in range(4):
        for function in (work.app.f1, work.app.f2, work.app.f3, work.app.f4, work.app.f5):
            function()
    report = lease.stop()
    assert len(report["frames"]) == 2 and report["truncated"] is True
    names = {frame["function"] for frame in report["frames"]}
    assert names == {"f1", "f2"} and {report["frames"][r["frame"]]["function"] for r in report["events"]} == names
    assert report["losses"] == [{"reason": "truncated", "count": "3"}]
    assert rows(report)[("f1", "PY_START")] == 4

@needs_monitoring
def test_monitoring_event_row_cap_is_reported(work, client):
    lease = start_profile(options(work, method=MONITORING, max_events=3), client)
    for function in (work.app.f1, work.app.f2):
        function()
    report = lease.stop()
    assert len(report["events"]) == 3 and report["truncated"] is True
    assert report["losses"] == [{"reason": "truncated", "count": "1"}]

@needs_monitoring
def test_monitoring_privacy_paths_locals_and_names(tmp_path, work, client):
    unsafe = work.load(work.root, "unsafe_symbol.py", UNSAFE)
    lease = start_profile(options(work, method=MONITORING), client)
    work.app.with_locals("CANARY_ARG", secret_kw="CANARY_KW")
    with pytest.raises(ValueError):
        work.app.boom("CANARY_EXC https://example.invalid/?token=CANARY_URL")
    getattr(unsafe, "\u043a\u043b\u044e\u0447_symbol")()
    report = lease.stop()
    text = json.dumps(report)
    for needle in ("CANARY", str(tmp_path), tmp_path.as_posix(), work.root, "elsewhere", "token"):
        assert needle not in text
    assert {"module_id": "unsafe_symbol.py", "function": "", "artifact_id": "unsafe_symbol.py", "line": 2, "column": None, "offset": "0", "reason": "not_captured"} in report["frames"]
    safe = [frame for frame in report["frames"] if frame["function"] == "with_locals"]
    assert safe == [{"module_id": "app.py", "function": "with_locals", "artifact_id": "app.py", "line": safe[0]["line"], "column": None, "offset": "0", "reason": ""}]

@needs_monitoring
def test_monitoring_reports_foreign_takeover_without_touching_the_new_owner(work, client):
    lease = start_profile(options(work, method=MONITORING), client)
    tool = [t for t in (2, 3, 4) if (MON.get_tool(t) or "").startswith("soundpost-profile")][0]
    MON.free_tool_id(tool)
    MON.use_tool_id(tool, "new-owner")
    fired = []
    MON.register_callback(tool, MON.events.PY_START, lambda code, offset: fired.append(1))
    MON.set_events(tool, MON.events.PY_START)
    try:
        report = lease.stop()
        assert report["capability"]["status"] == "error" and report["capability"]["reason"] == "profiler_state_lost"
        assert {"reason": "foreign_state", "count": "1"} in report["losses"]
        assert MON.get_tool(tool) == "new-owner" and MON.get_events(tool) == MON.events.PY_START
        work.app.busy(1)
        assert fired
    finally:
        MON.set_events(tool, 0); MON.register_callback(tool, MON.events.PY_START, None); MON.free_tool_id(tool)

# ---------------------------------------------------------------- lifecycle

@pytest.mark.parametrize("method", [WALL, MONITORING])
def test_stop_releases_everything_and_is_idempotent(work, client, method):
    lease = start_profile(options(work, method=method, duration_s=40), client)
    names = {t.name for t in threading.enumerate() if t.name.startswith("soundpost-profile")}
    assert names and lease.active and _registry()["owner"] is lease and lease in client._hook_leases
    started = time.perf_counter()
    first = lease.stop()
    assert time.perf_counter() - started < 3
    assert not lease.active and _registry()["owner"] is None and lease not in client._hook_leases
    assert not [t for t in threading.enumerate() if t.name.startswith("soundpost-profile")]
    if MON and method == MONITORING:
        assert not [t for t in (2, 3, 4) if (MON.get_tool(t) or "").startswith("soundpost-profile")] and MON.get_events(first["scope"]["tool_id"]) == 0
    assert lease.stop() == first and lease.close() is None and lease.close() is None
    assert first["stopped_by"] == "caller"

@pytest.mark.parametrize("method", [WALL, MONITORING])
def test_duration_auto_stops_and_releases_without_caller(work, client, method):
    lease = start_profile(options(work, method=method, duration_s=0.2), client)
    deadline = time.time() + 5
    while lease.active and time.time() < deadline:
        time.sleep(0.01)
    assert not lease.active and _registry()["owner"] is None
    assert not [t for t in threading.enumerate() if t.name.startswith("soundpost-profile")]
    report = lease.stop()
    assert report["stopped_by"] == "duration" and 0.15 <= (int(report["clock"]["wall_end_ns"]) - int(report["clock"]["wall_start_ns"])) / 1e9 < 3
    assert lease not in client._hook_leases
    assert start_profile(options(work, method=method), client).stop()["capability"]["status"] == "supported"

@pytest.mark.parametrize("method", [WALL, MONITORING])
def test_client_close_stops_the_lease(work, method):
    client = init(config())
    lease = start_profile(options(work, method=method), client)
    spin(work.app, 0.05)
    client.close()
    assert not lease.active and _registry()["owner"] is None and client._hook_leases == []
    assert not [t for t in threading.enumerate() if t.name.startswith("soundpost-profile")]
    report = lease.stop()
    assert report["stopped_by"] == "client_close" and report["capability"]["status"] == "supported"
    assert report["ack"]["status"] == "not_available"

def test_closed_client_or_client_without_leases_is_refused_not_raised(work):
    client = init(config())
    client.close()
    assert_refused(start_profile(options(work), client).stop(), "denied", "client_unavailable", WALL)
    assert _registry()["owner"] is None
    assert_refused(start_profile(options(work), object()).stop(), "denied", "client_unavailable", WALL)

def test_client_hook_lease_limit_is_refused_and_does_not_leak_ownership(work, client):
    fillers = [types.SimpleNamespace(close=lambda: None) for _ in range(8)]
    for filler in fillers:
        client._own_hook_lease(filler)
    try:
        assert_refused(start_profile(options(work), client).stop(), "denied", "client_unavailable", WALL)
        assert _registry()["owner"] is None
        if MON:
            assert all(MON.get_tool(t) is None for t in (2, 3, 4))
    finally:
        for filler in fillers:
            client._release_hook_lease(filler)

@pytest.mark.parametrize("first,second", [(WALL, WALL), (MONITORING, WALL), (WALL, MONITORING)])
def test_second_start_is_refused_while_a_lease_owns_the_runtime(work, client, first, second):
    owner = start_profile(options(work, method=first), client)
    try:
        refused = start_profile(options(work, method=second), client)
        assert not refused.active
        assert_refused(refused.stop(), "denied", "profiler_owned", second)
        assert owner.active and _registry()["owner"] is owner
        assert refused not in client._hook_leases
    finally:
        owner.stop()
    assert start_profile(options(work, method=second), client).stop()["capability"]["status"] == "supported"

def test_duplicate_module_copy_still_conflicts_through_the_global_registry(work, client):
    spec = importlib.util.spec_from_file_location("soundpost.profile_copy", P.__file__)
    copy = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(copy)
    assert copy is not P and copy.ProfileOptions is not ProfileOptions
    owner = start_profile(options(work), client)
    try:
        refused = copy.start_profile(copy.ProfileOptions(method=WALL, duration_s=5, project_root=work.root), client)
        assert_refused(refused.stop(), "denied", "profiler_owned", WALL)
    finally:
        owner.stop()
    assert copy.start_profile(copy.ProfileOptions(method=WALL, duration_s=5, project_root=work.root), client).stop()["capability"]["status"] == "supported"

# ---------------------------------------------------------------- options and support

BAD = [
    ("bad method", dict(method="cpu")),
    ("zero duration", dict(duration_s=0)),
    ("negative duration", dict(duration_s=-1)),
    ("over cap duration", dict(duration_s=60.5)),
    ("nan duration", dict(duration_s=float("nan"))),
    ("inf duration", dict(duration_s=float("inf"))),
    ("bool duration", dict(duration_s=True)),
    ("string duration", dict(duration_s="5")),
    ("zero interval", dict(interval_ms=0)),
    ("huge interval", dict(interval_ms=1001)),
    ("float interval", dict(interval_ms=2.5)),
    ("relative root", dict(project_root="relative/dir")),
    ("nul root", dict(project_root="/tmp/\x00x")),
    ("zero samples", dict(max_samples=0)),
    ("too many samples", dict(max_samples=8193)),
    ("too many code objects", dict(max_code_objects=4097)),
    ("zero events", dict(max_events=0)),
    ("too many events", dict(max_events=16385)),
]

@pytest.mark.parametrize("label,changes", BAD, ids=[label for label, _ in BAD])
def test_invalid_options_are_denied_without_raising(work, client, label, changes):
    lease = start_profile(options(work, **changes), client)
    assert not lease.active
    method = changes.get("method", WALL)
    report = lease.stop()
    assert_refused(report, "denied", "invalid_options", method if method in (WALL, MONITORING) else "unknown")
    assert "relative" not in json.dumps(report) and _registry()["owner"] is None and report["requested"] == {}

def test_documented_maximums_are_accepted(work, client):
    for method in (WALL, MONITORING):
        lease = start_profile(options(work, method=method, duration_s=60, interval_ms=1000, max_samples=8192, max_events=16384, max_code_objects=4096), client)
        assert lease.active and lease.capability["status"] == "supported"
        report = lease.stop()
        assert report["requested"]["duration_s"] == 60
    lease = start_profile(options(work, duration_s=0.001, interval_ms=1, max_samples=1), client)
    assert lease.stop()["capability"]["status"] == "supported"

def test_options_object_must_be_the_dataclass_and_is_immutable(work, client):
    assert_refused(start_profile({"method": WALL}, client).stop(), "denied", "invalid_options", "unknown")
    with pytest.raises(FrozenInstanceError):
        options(work).duration_s = 1
    # Deterministic monitoring without any project root (option or client) has nothing it may report.
    assert_refused(start_profile(ProfileOptions(method=MONITORING, duration_s=5), client).stop(), "denied", "invalid_options", MONITORING)

def test_project_root_defaults_to_the_clients_configured_root(work):
    client = init(config(project_root=work.root))
    try:
        lease = start_profile(ProfileOptions(method=WALL, duration_s=5, interval_ms=2), client)
        spin(work.app, 0.1)
        report = lease.stop()
        assert any(f["function"] == "busy" for f in report["frames"])
    finally:
        client.close()

def test_free_threaded_build_is_unsupported_for_both_methods(work, client, monkeypatch):
    real = sysconfig.get_config_var
    monkeypatch.setattr(sysconfig, "get_config_var", lambda name: 1 if name == "Py_GIL_DISABLED" else real(name))
    for method in (WALL, MONITORING):
        assert_refused(start_profile(options(work, method=method), client).stop(), "unsupported", "free_threaded_unqualified", method)
    assert _registry()["owner"] is None

def test_missing_sys_monitoring_is_unsupported_only_for_monitoring(work, client, monkeypatch):
    monkeypatch.delattr(sys, "monitoring")
    assert_refused(start_profile(options(work, method=MONITORING), client).stop(), "unsupported", "sys_monitoring_unavailable", MONITORING)
    lease = start_profile(options(work), client)
    assert lease.active
    lease.stop()

# ---------------------------------------------------------------- capability, units, wire

def capability_record(report):
    capability = dict(report["capability"])
    identity = capability.pop("id")
    return json.dumps({"id": identity, "kind": "capability", "observed_at_ns": report["clock"]["wall_start_ns"], "policy_revision": "1", "payload": capability})

def reports(work, client, monkeypatch):
    out = {}
    out["wall"] = start_profile(options(work), client).stop()
    out["monitoring"] = start_profile(options(work, method=MONITORING), client).stop()
    out["invalid"] = start_profile(options(work, duration_s=0), client).stop()
    owner = start_profile(options(work), client)
    out["owned"] = start_profile(options(work), client).stop()
    owner.stop()
    real = sysconfig.get_config_var
    monkeypatch.setattr(sysconfig, "get_config_var", lambda name: 1 if name == "Py_GIL_DISABLED" else real(name))
    out["unsupported"] = start_profile(options(work), client).stop()
    return out

def test_capability_payload_passes_closed_c04_validation_and_go_safe_codes(work, client, monkeypatch):
    produced = reports(work, client, monkeypatch)
    identities = set()
    for name, report in produced.items():
        assert_report_shape(report)
        capability = report["capability"]
        for key in ("runtime", "version", "build", "os", "arch", "method", "reason"):
            assert SAFE_CODE.fullmatch(capability[key]), (name, key)
        assert len(capability["build"]) <= 256 and len(capability["runtime"]) <= 128 and len(capability["version"]) <= 128 and len(capability["os"]) <= 64 and len(capability["arch"]) <= 64
        assert re.fullmatch(r"[0-9a-f]{32}", capability["id"]) and capability["id"] not in identities
        identities.add(capability["id"])
        assert len(set(capability["clock_domain"].values())) == 3 and all(re.fullmatch(r"[0-9a-f]{32}", v) for v in capability["clock_domain"].values())
        record = parse_safe_record(capability_record(report))
        assert record["payload"]["status"] == capability["status"] and record["id"] == capability["id"]
    assert {name: r["capability"]["status"] + "/" + r["capability"]["reason"] for name, r in produced.items()} == {
        "wall": "supported/ok", "monitoring": "supported/ok", "invalid": "denied/invalid_options", "owned": "denied/profiler_owned", "unsupported": "unsupported/free_threaded_unqualified"}
    broken = json.loads(capability_record(produced["wall"]))
    broken["payload"]["coverage"]["frames"] = "full"
    with pytest.raises(ValueError):
        parse_safe_record(json.dumps(broken))
    broken = json.loads(capability_record(produced["wall"]))
    broken["payload"]["extra"] = 1
    with pytest.raises(ValueError):
        parse_safe_record(json.dumps(broken))

def test_refused_and_unsupported_states_never_contain_samples_events_or_cpu_evidence(work, client, monkeypatch):
    produced = reports(work, client, monkeypatch)
    for name in ("invalid", "owned", "unsupported"):
        report = produced[name]
        assert report["frames"] == [] and report["stacks"] == [] and report["samples"] == [] and report["events"] == [] and report["sample_count"] == 0
        assert report["stopped_by"] == "not_started" and report["capability"]["coverage"] == {"frames": "none", "threads": "none", "workers": "none", "tasks": "none"}
    assert produced["wall"]["units"] == "samples" and produced["wall"]["time_delta_unit"] == "wall_microseconds"
    assert produced["monitoring"]["units"] == "events" and produced["monitoring"]["time_delta_unit"] is None
    for report in produced.values():
        text = json.dumps(report).lower()
        assert "cpu" not in text and "nanoseconds" not in re.sub(r'"(?:wall_start_ns|wall_end_ns|expires_ns|uncertainty_ns)"', "", text)
        assert report["units"] in ("samples", "events") and report["time_delta_unit"] in (None, "wall_microseconds")

def test_reports_have_independent_clock_domains_and_identities(work, client):
    one = start_profile(options(work), client).stop()
    two = start_profile(options(work), client).stop()
    assert one["capability"]["id"] != two["capability"]["id"] and one["clock"]["domain"] != two["clock"]["domain"]

def test_profile_module_uses_only_code_identity_and_never_frame_locals():
    tree = ast.parse(Path(P.__file__).read_text(encoding="utf-8"))
    forbidden = {"f_locals", "f_globals", "f_builtins", "co_consts", "co_varnames", "co_freevars", "co_cellvars", "gi_frame", "cr_frame", "getframe", "currentframe", "getsource", "getlines"}
    attributes = {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)} | {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
    assert not attributes & forbidden
    assert not any(isinstance(node, (ast.Import, ast.ImportFrom)) and any(a.name.split(".")[0] in ("inspect", "traceback", "linecache", "pdb") for a in getattr(node, "names", [])) for node in ast.walk(tree))

# ---------------------------------------------------------------- loss reporting and ACK

def signed_client(transport, **policy):
    original = config()
    payload = json.loads(base64.urlsafe_b64decode(original.policy.payload + "=" * (-len(original.policy.payload) % 4)))
    payload.update(policy)
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return init(replace(original, transport=transport, policy=SignedPolicy(1, "Ed25519", "test", b64(raw), b64(KEY.sign(raw)))))

def losses_sent(ledger):
    return [record["payload"] for body in ledger.sends for record in json.loads(body)["records"] if record["kind"] == "loss"]

def test_truncation_is_reported_as_profile_chunk_loss_and_ack_needs_a_real_cursor(work):
    ledger = Ledger(); ledger.lost = False
    client = signed_client(ledger, loss=True)
    try:
        lease = start_profile(options(work, max_samples=4), client)
        spin(work.app, 0.3)
        report = lease.stop()
        dropped = [loss for loss in report["losses"] if loss["reason"] == "truncated"]
        assert len(dropped) == 1
        assert report["ack"]["status"] == "obtained" and report["ack"]["cursors"] == ["99999999999999999999999999999999:9007199254740993"]
        sent = losses_sent(ledger)
        assert len(sent) == 1 and sent[0]["signal"] == "profile_chunk" and sent[0]["reason"] == "truncated" and sent[0]["count"] == dropped[0]["count"]
        assert lease.stop()["ack"] == report["ack"]
    finally:
        client.close()

def test_unsupported_capability_is_reported_as_loss_and_acknowledged(work, monkeypatch):
    ledger = Ledger(); ledger.lost = False
    client = signed_client(ledger, loss=True)
    real = sysconfig.get_config_var
    monkeypatch.setattr(sysconfig, "get_config_var", lambda name: 1 if name == "Py_GIL_DISABLED" else real(name))
    try:
        report = start_profile(options(work), client).stop()
        assert report["capability"]["status"] == "unsupported" and report["ack"]["status"] == "obtained" and report["ack"]["cursors"]
        sent = losses_sent(ledger)
        assert [(s["signal"], s["reason"], s["count"]) for s in sent] == [("profile_chunk", "unsupported", "1")]
    finally:
        client.close()

def test_ack_is_not_available_without_loss_permission_or_without_reportable_loss(work):
    ledger = Ledger(); ledger.lost = False
    denied = signed_client(ledger, loss=False)
    allowed = signed_client(ledger, loss=True)
    try:
        lease = start_profile(options(work, max_samples=3), denied)
        spin(work.app, 0.2)
        report = lease.stop()
        assert report["truncated"] is True and report["ack"] == {"status": "not_available", "reason": "loss_not_admitted"}
        clean = start_profile(options(work), allowed)
        spin(work.app, 0.05)
        report = clean.stop()
        assert [loss["reason"] for loss in report["losses"] if loss["reason"] == "truncated"] == []
        assert report["ack"] == {"status": "not_available", "reason": "no_loss_recorded"}
        assert not ledger.sends
    finally:
        denied.close(); allowed.close()

def test_ack_fails_honestly_when_the_backend_returns_no_cursor(work):
    ledger = Ledger(); ledger.restricted = True
    client = signed_client(ledger, loss=True)
    try:
        lease = start_profile(options(work, max_samples=3), client)
        spin(work.app, 0.2)
        report = lease.stop()
        assert report["ack"]["status"] == "failed" and report["ack"]["reason"] and "cursors" not in report["ack"]
        assert len(ledger.sends) >= 1
    finally:
        client.close()
