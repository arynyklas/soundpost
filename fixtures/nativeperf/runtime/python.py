# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
"""Task 04.09 CPython runtime column.

Run by fixtures/nativeperf/acceptance as: python3 python.py <seconds> [phases]
Protocol: prints "ready <pid>", waits for "go" on stdin, runs a CPU loop, an asyncio loopback-HTTP wait and (when
SOUNDPOST_FIXTURE_DB_ADDR names a PostgreSQL server) an asyncio database wait, one `select pg_sleep(0.2)` after the other
over the PostgreSQL wire protocol (pgwait.py), while the C09 supplement (sdk/python/src/soundpost/profile.py, method
python_wall_samples) profiles it, then prints ONE JSON line. The supplement's samples are runtime ENGINE samples (wall
microseconds of the interpreter's own threads): they are this runtime's separate comparison column and are never native
engine output, CPU time or OS scheduler data. The native CPU capture of this process is taken by the acceptance runner,
independently of this script. phases is a comma list of cpu, http, db (default cpu,http: the runner takes the database wait in a
capture of its own, so that neither capture holds more than the other's budget). The native-extension and
perf-trampoline comparison is its own scenario: python_trampolines.py.
"""
import asyncio
import base64
import json
import os
import platform
import re
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from pgwait import DB_DELAY_S, connect_pg, database_wait  # noqa: E402

SOURCE_ROOT = Path(__file__).resolve().parents[3] / "sdk" / "python" / "src"
if SOURCE_ROOT.is_dir() and str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from soundpost import Config, Resource, SignedPolicy, init
from soundpost.profile import ProfileOptions, start_profile
from soundpost.transport import Outcome


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

    payload = json.dumps(dict(version=1, org=org, source=source, project=project, revision="1", expires_ns="9223372036854775807",
                              errors=True, logs=True, replay=False, bodies=False, loss=True), sort_keys=True, separators=(",", ":")).encode()
    config = Config(org=org, project=project, source=source, endpoint="https://example.invalid/ingest/v1/batches", credential="offline", build=build,
                    policy=SignedPolicy(1, "Ed25519", "fixture", b64(payload), b64(key.sign(payload))),
                    trusted_keys={"fixture": key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)},
                    resource=Resource("6" * 32, "7" * 32, build, "fixture-worker"), project_root=root, transport=OfflineTransport())
    return init(config)


def cpu_loop(seconds):
    end = time.perf_counter() + seconds
    total = 0
    while time.perf_counter() < end:
        for i in range(20000):
            total += i * i
    return total


async def http_wait(requests, delay):
    async def handle(reader, writer):
        await reader.readuntil(b"\r\n\r\n")
        await asyncio.sleep(delay)  # the server side wait of a real HTTP exchange
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    waited = []
    for _ in range(requests):
        started = time.perf_counter()
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        await writer.drain()
        body = await reader.read()
        writer.close()
        if not body.endswith(b"ok"):
            raise RuntimeError("unexpected HTTP response")
        waited.append(time.perf_counter() - started)
    server.close()
    await server.wait_closed()
    return waited


DB_REQUESTS = 12
DB_ADDR = os.environ.get("SOUNDPOST_FIXTURE_DB_ADDR", "")


def scrub(error):
    """The text of a failure without the address of the database."""
    text = str(error)
    if DB_ADDR:
        text = text.replace(DB_ADDR, "<db>")
    return re.sub(r"\d+\.\d+\.\d+\.\d+(:\d+)?", "<ip>", text)


def db_options():
    return dict(user=os.environ.get("SOUNDPOST_FIXTURE_DB_USER") or "postgres", database=os.environ.get("SOUNDPOST_FIXTURE_DB_NAME") or "postgres",
                password=os.environ.get("SOUNDPOST_FIXTURE_DB_PASSWORD") or "")


async def database_probe():
    """Before the ready line: the database is reachable and speaks the protocol (the measured phase reconnects, because an
    asyncio connection belongs to the loop that made it)."""
    client = await connect_pg(DB_ADDR, **db_options())
    client.close()


async def database_phase(requests):
    client = await connect_pg(DB_ADDR, **db_options())
    try:
        start_ns = time.monotonic_ns()
        waits, reported = await database_wait(client, requests)
        end_ns = time.monotonic_ns()
        return client.params.get("server_version", ""), waits, reported, start_ns, end_ns
    finally:
        client.close()


def main():
    seconds = float(sys.argv[1])
    phases = {p.strip() for p in (sys.argv[2] if len(sys.argv) > 2 else "cpu,http").split(",") if p.strip()}
    root = str(Path(__file__).resolve().parents[3])
    client = offline_client(root)
    # Everything that creates threads (the client, the supplement's sampler and timer threads) happens BEFORE the
    # ready line: the native helper treats a thread creation or exit inside a live capture as a coverage change.
    lease = start_profile(ProfileOptions(method="python_wall_samples", duration_s=60, interval_ms=2, project_root=root), client)
    started = lease.active and lease.capability["status"] == "supported"
    asyncio.run(http_wait(1, 0.001))  # warm-up
    database = {"status": "not_run", "reason": "SOUNDPOST_FIXTURE_DB_ADDR is not set" if "db" in phases else "phase not requested"}
    if "db" in phases and DB_ADDR:
        database = None
        try:
            asyncio.run(database_probe())
        except Exception as error:  # an unreachable or unfriendly database is reported, never hidden
            database = {"status": "error", "reason": "database_unreachable: " + scrub(error)}
    print(f"ready {os.getpid()}", flush=True)
    if sys.stdin.readline().strip() != "go":
        return 2
    cpu_seconds = 0.0
    if "cpu" in phases:
        t0 = time.perf_counter()
        cpu_loop(seconds * 0.6)
        cpu_seconds = time.perf_counter() - t0
    announced = False

    def announce_wait():
        nonlocal announced
        if not announced:
            announced = True
            # CLOCK_MONOTONIC: the clock of the native scheduler events; the harness releases the loop thread's CPU-phase
            # intervals at the source from here on
            print(f"wait_begin {time.monotonic_ns()}", flush=True)

    http = {"status": "not_run", "reason": "phase not requested"}
    if "http" in phases:
        announce_wait()
        wait_start_ns = time.monotonic_ns()
        waited = asyncio.run(http_wait(max(4, int(seconds * 0.4 / 0.06)), 0.05))
        wait_end_ns = time.monotonic_ns()
        http = {"kind": "asyncio loopback HTTP", "requests": len(waited), "wait_seconds_total": sum(waited), "wait_seconds_min": min(waited), "server_delay_s": 0.05,
                "window_ns": [wait_start_ns, wait_end_ns]}
    if database is None:
        try:
            announce_wait()
            version, waits, reported, db_start_ns, db_end_ns = asyncio.run(database_phase(DB_REQUESTS))
            database = {"kind": "PostgreSQL v3 simple query (pg_sleep) over asyncio streams", "server_version": version, "requests": len(waits),
                        "wait_seconds_total": sum(waits), "wait_seconds_min": min(waits), "server_delay_s": DB_DELAY_S,
                        "server_reported_s_total": sum(reported), "window_ns": [db_start_ns, db_end_ns]}
        except Exception as error:
            database = {"status": "error", "reason": "database_failed: " + scrub(error)}
    # The supplement's sampler and timer threads exit when it stops, and the native helper ends a capture when a thread
    # of its target exits. So the report waits: this line tells the runner the measured phase is over, the runner closes
    # the native capture (its final proof needs a live, unchanged target) and then answers "exit".
    print("done", flush=True)
    if sys.stdin.readline().strip() != "exit":
        return 2
    report = lease.stop()
    leaves = {}
    for sample in report["samples"]:
        frames = report["stacks"][sample["stack"]]["frames"]
        name = (report["frames"][frames[0]]["function"] if frames else "") or "<external>"
        leaves[name] = leaves.get(name, 0) + 1
    out = {
        "runtime": "python",
        "version": platform.python_version(),
        "implementation": platform.python_implementation(),
        "executable": sys.executable,
        "free_threaded": bool(getattr(sys, "_is_gil_enabled", lambda: True)() is False),
        "engine": {
            "supplement": "sdk/python/src/soundpost/profile.py start_profile (C09, internal adapter)",
            "method": report["method"], "units": report["units"], "time_delta_unit": report["time_delta_unit"],
            "status": report["capability"]["status"], "reason": report["capability"]["reason"], "started": started,
            "sample_count": report["sample_count"], "leaf_samples": {k: leaves[k] for k in sorted(leaves)},
            "coverage": report["capability"]["coverage"], "bias": report["scope"].get("bias"),
            "achieved_interval_us": report["interval"].get("achieved_us"), "losses": report["losses"],
            "native_extension_work": "not_run: the python_trampolines host scenario runs the native-extension workload (python_trampolines.py)",
            "trampolines": "not_run: the python_trampolines host scenario compares perf trampolines on and off (python_trampolines.py)",
        },
        "cpu": {"loop_seconds": cpu_seconds, "function": "cpu_loop"},
        "wait": {"loop_tid": threading.get_native_id(), "http": http, "database": database},
    }
    print(json.dumps(out), flush=True)
    code = 0 if started and report["sample_count"] > 0 else 1
    return code


if __name__ == "__main__":
    sys.exit(main())
