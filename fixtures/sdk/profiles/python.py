# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
"""Python runtime-supplement fixture: real sys.monitoring / sys._current_frames evidence, no network, no backend.

Run: ./.venv/Scripts/python.exe fixtures/sdk/profiles/python.py
Prints exactly one JSON line on stdout and exits 0 only when every assertion held; otherwise a short reason goes
to stderr and the exit code is 1. The JSON carries measured counts/reasons only, never raw telemetry.
"""
import base64
import json
import os
import platform
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path

SOURCE_ROOT = Path(__file__).resolve().parents[3] / "sdk" / "python" / "src"
if SOURCE_ROOT.is_dir() and str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from soundpost import Config, Resource, SignedPolicy, init
from soundpost.profile import ProfileOptions, start_profile
from soundpost.transport import Outcome

WORKLOAD = '''
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
def boom():
    raise ValueError("fixture")
def generator():
    yield 1
    yield 2
'''
LIBRARY = '''
import time
def library_spin(seconds):
    end = time.perf_counter() + seconds
    while time.perf_counter() < end:
        pass
'''
WALL, MONITORING = "python_wall_samples", "python_monitoring"

class FixtureFailure(Exception):
    pass

def check(condition, reason):
    if not condition:
        raise FixtureFailure(reason)

class OfflineTransport:
    """No network: the fixture never needs a receipt, so every export attempt is terminal."""
    def send(self, batch, deadline):
        return Outcome("terminal")
    def lookup(self, batch, deadline):
        return Outcome("not_found")
    def close(self):
        pass

def offline_client(root):
    key = Ed25519PrivateKey.generate()
    org, project, source, build = "1" * 32, "2" * 32, "3" * 32, "4" * 32
    def b64(value):
        return base64.urlsafe_b64encode(value).rstrip(b"=").decode()
    payload = json.dumps(dict(version=1, org=org, source=source, project=project, revision="1", expires_ns="9223372036854775807", errors=True, logs=True, replay=False, bodies=False, loss=True), sort_keys=True, separators=(",", ":")).encode()
    config = Config(org=org, project=project, source=source, endpoint="https://example.invalid/ingest/v1/batches", credential="offline", build=build,
                    policy=SignedPolicy(1, "Ed25519", "fixture", b64(payload), b64(key.sign(payload))),
                    trusted_keys={"fixture": key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)}, resource=Resource("6" * 32, "7" * 32, build, "fixture-worker"),
                    project_root=root, transport=OfflineTransport())
    return init(config)

def load(base, name, source, **extra):
    namespace = dict(extra)
    exec(compile(source, os.path.join(base, name), "exec"), namespace)
    return namespace

def spin(app, seconds):
    end = time.perf_counter() + seconds
    while time.perf_counter() < end:
        app["busy"](2000)

def functions(report, sample):
    return [report["frames"][i]["function"] for i in report["stacks"][sample["stack"]]["frames"]]

def event_rows(report):
    return {report["frames"][row["frame"]]["function"] + ":" + row["kind"]: int(row["count"]) for row in report["events"]}

def refusal(report, status, reason):
    check(report["capability"]["status"] == status and report["capability"]["reason"] == reason, f"expected {status}/{reason}, got {report['capability']['status']}/{report['capability']['reason']}")
    check(report["samples"] == [] and report["events"] == [] and report["frames"] == [] and report["sample_count"] == 0 and report["stopped_by"] == "not_started", f"{reason} report is not empty")
    return {"status": status, "reason": reason, "sample_count": 0, "event_rows": 0}

def wall_run(client, app, root):
    left, right = socket.socketpair()
    lease = start_profile(ProfileOptions(method=WALL, duration_s=30, interval_ms=2, project_root=root), client)
    check(lease.active and lease.capability["status"] == "supported", "wall profile did not start")
    sleeper = threading.Thread(target=app["sleepy"], args=(0.5,))
    reader = threading.Thread(target=app["read_blocking"], args=(left,))
    sleeper.start(); reader.start()
    spin(app, 0.5)
    right.send(b"x"); sleeper.join(); reader.join(); left.close(); right.close()
    report = lease.stop()
    check(report["units"] == "samples" and report["time_delta_unit"] == "wall_microseconds" and report["stack_order"] == "leaf_first", "wall units/time unit wrong")
    check(report["sample_count"] >= 20 and len(report["samples"]) == report["sample_count"], f"wall samples empty or too few: {report['sample_count']}")
    leaves = {}
    for sample in report["samples"]:
        leaf = functions(report, sample)[0]
        leaves[leaf] = leaves.get(leaf, 0) + 1
    for name in ("busy", "sleepy", "read_blocking"):
        check(leaves.get(name, 0) >= 3, f"no wall samples attributed to {name}")
    check(report["capability"]["coverage"] == {"frames": "partial", "threads": "partial", "workers": "none", "tasks": "none"}, "wall coverage not partial/none")
    bias = report["scope"]["bias"]
    check(bias == {"gil_acquisition": True, "native_time_attributed_to_python_caller": True, "suspended_tasks_unobserved": True}, "wall bias flags wrong")
    achieved = report["interval"]["achieved_us"]
    check(achieved is not None and achieved > 0, "no achieved interval")
    text = json.dumps(report).lower()
    check("cpu" not in text and root not in json.dumps(report) and json.dumps(root)[1:-1] not in json.dumps(report), "report leaks a CPU unit or the project root")
    gap = [int(loss["count"]) for loss in report["losses"] if loss["reason"] == "sample_gap"]
    return {"status": report["capability"]["status"], "reason": report["capability"]["reason"], "units": report["units"], "time_delta_unit": report["time_delta_unit"],
            "sample_count": report["sample_count"], "distinct_stacks": len(report["stacks"]), "frame_count": len(report["frames"]), "threads_sampled": len({s["thread"] for s in report["samples"]}),
            "leaf_samples": {key: leaves[key] for key in sorted(leaves)}, "interval": {"requested_us": report["interval"]["requested_us"], "achieved_mean_us": achieved, "achieved_max_us": report["scope"]["sampler"]["max_gap_us"]},
            "sample_gap_estimated_missed": gap[0] if gap else 0, "losses": report["losses"], "truncated": report["truncated"], "coverage": report["capability"]["coverage"], "bias": bias, "ack": report["ack"]["status"]}

def monitoring_run(client, app, root, library):
    lease = start_profile(ProfileOptions(method=MONITORING, duration_s=30, project_root=root), client)
    check(lease.active and lease.capability["status"] == "supported", "monitoring profile did not start")
    for _ in range(7):
        app["busy"](1000)
    for _ in range(3):
        try:
            app["boom"]()
        except ValueError:
            pass
    check(list(app["generator"]()) == [1, 2], "generator behavior changed under monitoring")
    app["sleepy"](0.02)
    library["library_spin"](0.01)
    report = lease.stop()
    rows = event_rows(report)
    check(report["units"] == "events" and report["time_delta_unit"] is None and report["samples"] == [] and report["stacks"] == [], "monitoring units wrong")
    expected = {"busy:PY_START": 7, "busy:PY_RETURN": 7, "boom:PY_START": 3, "boom:PY_UNWIND": 3, "generator:PY_START": 1, "generator:PY_RESUME": 2, "generator:PY_RETURN": 1, "sleepy:PY_START": 1}
    for key, value in expected.items():
        check(rows.get(key) == value, f"event count {key} expected {value}, got {rows.get(key)}")
    check(not any(frame["function"].startswith("library") or frame["module_id"] == "external" for frame in report["frames"]), "external code was recorded")
    check(report["capability"]["coverage"] == {"frames": "partial", "threads": "complete", "workers": "none", "tasks": "none"}, "monitoring coverage wrong")
    return {"status": report["capability"]["status"], "reason": report["capability"]["reason"], "units": report["units"], "time_delta_unit": report["time_delta_unit"],
            "event_rows": len(report["events"]), "events": rows, "frame_count": len(report["frames"]), "tool_id": report["scope"]["tool_id"], "losses": report["losses"], "coverage": report["capability"]["coverage"]}

def coexistence_run(client, app, root, library):
    monitoring = sys.monitoring
    seen = []
    monitoring.use_tool_id(monitoring.PROFILER_ID, "fixture-foreign-profiler")
    try:
        monitoring.register_callback(monitoring.PROFILER_ID, monitoring.events.PY_START, lambda code, offset: seen.append(code.co_name))
        monitoring.set_events(monitoring.PROFILER_ID, monitoring.events.PY_START)
        lease = start_profile(ProfileOptions(method=MONITORING, duration_s=30, project_root=root), client)
        check(lease.active, "monitoring refused next to an occupied PROFILER_ID")
        app["busy"](10); library["library_spin"](0.001)
        report = lease.stop()
        check(report["scope"]["tool_id"] == 3, "did not take the next free tool ID")
        check("busy" in seen and "library_spin" in seen, "foreign tool callback stopped firing while ours ran")
        check(monitoring.get_tool(monitoring.PROFILER_ID) == "fixture-foreign-profiler" and monitoring.get_events(monitoring.PROFILER_ID) == monitoring.events.PY_START and monitoring.get_tool(3) is None, "foreign tool state or our cleanup wrong")
        before = len(seen)
        app["busy"](10)
        check(len(seen) > before, "foreign callback no longer fires after our stop")
        return {"foreign_tool_id": monitoring.PROFILER_ID, "our_tool_id": report["scope"]["tool_id"], "foreign_saw_project_code": True, "foreign_saw_external_code": True, "our_tool_freed": True, "our_busy_starts": event_rows(report).get("busy:PY_START")}
    finally:
        monitoring.set_events(monitoring.PROFILER_ID, 0)
        monitoring.register_callback(monitoring.PROFILER_ID, monitoring.events.PY_START, None)
        monitoring.free_tool_id(monitoring.PROFILER_ID)

def refusal_runs(client, root):
    results = {}
    owner = start_profile(ProfileOptions(method=WALL, duration_s=30, project_root=root), client)
    try:
        results["profiler_owned"] = refusal(start_profile(ProfileOptions(method=MONITORING, duration_s=5, project_root=root), client).stop(), "denied", "profiler_owned")
    finally:
        owner.stop()
    results["invalid_options"] = refusal(start_profile(ProfileOptions(method=WALL, duration_s=0, project_root=root), client).stop(), "denied", "invalid_options")
    monitoring = sys.monitoring
    for tool in (2, 3, 4):
        monitoring.use_tool_id(tool, f"fixture-foreign-{tool}")
    try:
        results["monitoring_tool_ids_occupied"] = refusal(start_profile(ProfileOptions(method=MONITORING, duration_s=5, project_root=root), client).stop(), "denied", "monitoring_tool_ids_occupied")
    finally:
        for tool in (2, 3, 4):
            monitoring.free_tool_id(tool)
    closed = offline_client(root)
    closed.close()
    results["client_unavailable"] = refusal(start_profile(ProfileOptions(method=WALL, duration_s=5, project_root=root), closed).stop(), "denied", "client_unavailable")
    return results

def lifecycle_runs(root, app):
    results = {}
    client = offline_client(root)
    lease = start_profile(ProfileOptions(method=MONITORING, duration_s=0.2, project_root=root), client)
    deadline = time.time() + 5
    while lease.active and time.time() < deadline:
        time.sleep(0.01)
    report = lease.stop()
    check(not lease.active and report["stopped_by"] == "duration", "duration did not stop the profile")
    results["duration_auto_stop"] = {"stopped_by": report["stopped_by"], "elapsed_ms": (int(report["clock"]["wall_end_ns"]) - int(report["clock"]["wall_start_ns"])) // 10**6}
    lease = start_profile(ProfileOptions(method=WALL, duration_s=30, interval_ms=2, project_root=root), client)
    spin(app, 0.05)
    client.close()
    report = lease.stop()
    check(not lease.active and report["stopped_by"] == "client_close", "client.close did not stop the profile")
    results["client_close"] = {"stopped_by": report["stopped_by"], "active_after": lease.active}
    results["leftover_profile_threads"] = len([t for t in threading.enumerate() if t.name.startswith("soundpost-profile")])
    check(results["leftover_profile_threads"] == 0, "profile threads left running")
    return results

def truncation_run(client, app, root):
    lease = start_profile(ProfileOptions(method=WALL, duration_s=30, interval_ms=2, project_root=root, max_samples=4), client)
    spin(app, 0.2)
    report = lease.stop()
    dropped = [loss for loss in report["losses"] if loss["reason"] == "truncated"]
    check(report["sample_count"] == 4 and report["truncated"] is True and len(dropped) == 1, "sample cap not reported as truncated loss")
    return {"sample_count": report["sample_count"], "truncated": True, "loss": dropped[0], "ack": report["ack"]}

def main():
    check(not (sys.version_info < (3, 12)), "CPython 3.12+ required")
    from sysconfig import get_config_var
    root = os.path.join(tempfile.gettempdir(), "soundpost-profile-fixture", "project")
    other = os.path.join(tempfile.gettempdir(), "soundpost-profile-fixture", "library")
    client = offline_client(root)
    if get_config_var("Py_GIL_DISABLED"):
        # Free-threaded builds start unqualified: the honest result is a typed refusal with zero samples/events.
        try:
            results = {method: refusal(start_profile(ProfileOptions(method=method, duration_s=5, project_root=root), client).stop(), "unsupported", "free_threaded_unqualified") for method in (WALL, MONITORING)}
        finally:
            client.close()
        print(json.dumps({"fixture": "python", "python": platform.python_version(), "implementation": platform.python_implementation(), "platform": sys.platform, "machine": platform.machine(), "results": results}, sort_keys=True, separators=(",", ":")))
        return
    try:
        library = load(other, "library.py", LIBRARY)
        app = load(root, "app.py", WORKLOAD)
        results = {
            "wall_samples": wall_run(client, app, root),
            "monitoring": monitoring_run(client, app, root, library),
            "coexistence": coexistence_run(client, app, root, library),
            "refusals": refusal_runs(client, root),
            "truncation": truncation_run(client, app, root),
        }
    finally:
        client.close()
    results["lifecycle"] = lifecycle_runs(root, app)
    check(not [i for i in (2, 3, 4) if sys.monitoring.get_tool(i)], "a monitoring tool ID leaked")
    print(json.dumps({"fixture": "python", "python": platform.python_version(), "implementation": platform.python_implementation(), "platform": sys.platform, "machine": platform.machine(), "results": results}, sort_keys=True, separators=(",", ":")))

if __name__ == "__main__":
    try:
        main()
    except FixtureFailure as failure:
        print(f"fixture failed: {failure}", file=sys.stderr)
        sys.exit(1)
    except Exception as error:
        print(f"fixture crashed: {type(error).__name__}", file=sys.stderr)
        sys.exit(1)
