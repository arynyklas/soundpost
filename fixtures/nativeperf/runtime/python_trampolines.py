# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
"""Task 04.09 CPython perf-trampoline comparison (host scenario python_trampolines).

Run by fixtures/nativeperf/acceptance as: python3 python_trampolines.py <seconds> <on|off> <extension-dir>
Protocol: activates (on) or leaves off (off) CPython's perf trampoline (sys.activate_stack_trampoline("perf"), which writes
/tmp/perf-<pid>.map and runs every Python call through a small machine-code trampoline in anonymous executable memory),
warms every phase up, prints "ready <pid>", waits for "go" on stdin and runs three phases: (a) a pure-Python CPU loop,
(b) the native-extension workload (spnative.burn, a real CPython extension module), (c) an asyncio wait on loopback
requests held 50 ms server-side. Then it prints "done", waits for "exit" and prints ONE JSON line with each phase's
monotonic window (CLOCK_MONOTONIC nanoseconds, the clock of the native events) and its own CPU time. The native capture of
this process is taken by the acceptance runner; no soundpost package is imported.
"""
import asyncio
import json
import os
import platform
import sys
import threading
import time

seconds = float(sys.argv[1])
mode = sys.argv[2]
sys.path.insert(0, sys.argv[3])
import spnative  # noqa: E402  (the extension the runner compiled for this interpreter)


def spy_cpu_loop(duration):
    end = time.perf_counter() + duration
    total = 0
    while time.perf_counter() < end:
        for i in range(20000):
            total += i * i
    return total


def spy_native_phase(duration):
    return spnative.burn(duration)


async def spy_http_wait(requests, delay):
    async def spy_handle(reader, writer):
        await reader.readuntil(b"\r\n\r\n")
        await asyncio.sleep(delay)  # the server side wait of a real HTTP exchange
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(spy_handle, "127.0.0.1", 0)
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


def phase(function, *args):
    """Runs one phase and returns (result, window_ns, cpu_seconds of this thread)."""
    cpu0, t0 = time.thread_time_ns(), time.monotonic_ns()
    result = function(*args)
    t1, cpu1 = time.monotonic_ns(), time.thread_time_ns()
    return result, [t0, t1], (cpu1 - cpu0) / 1e9


def main():
    trampoline = {"mode": mode, "available": hasattr(sys, "activate_stack_trampoline"), "active": False, "backend": "perf", "error": ""}
    if mode == "on":
        if not trampoline["available"]:
            trampoline["error"] = "sys.activate_stack_trampoline does not exist in CPython " + platform.python_version()
        else:
            try:
                sys.activate_stack_trampoline("perf")
            except Exception as error:  # the build has no perf trampoline support, or perf support was disabled
                trampoline["error"] = f"{type(error).__name__}: {error}"
        trampoline["active"] = bool(getattr(sys, "is_stack_trampoline_active", lambda: False)())
    # Everything that creates a thread, a map or a trampoline happens BEFORE the ready line: the native helper treats a
    # thread creation or exit inside a live capture as a coverage change.
    spy_cpu_loop(0.02)
    spy_native_phase(0.02)
    asyncio.run(spy_http_wait(1, 0.001))
    print(f"ready {os.getpid()}", flush=True)
    if sys.stdin.readline().strip() != "go":
        return 2
    _, cpu_window, cpu_seconds = phase(spy_cpu_loop, seconds * 0.4)
    checksum, native_window, native_seconds = phase(spy_native_phase, seconds * 0.4)
    print(f"wait_begin {time.monotonic_ns()}", flush=True)  # the harness releases the loop thread's CPU-phase intervals at the source
    waited, wait_window, _ = phase(lambda: asyncio.run(spy_http_wait(max(24, int(seconds * 0.2 / 0.06)), 0.05)))
    print("done", flush=True)
    if sys.stdin.readline().strip() != "exit":
        return 2
    print(json.dumps({
        "runtime": "python", "version": platform.python_version(), "executable": sys.executable, "pid": os.getpid(),
        "trampoline": trampoline, "perf_map_present": os.path.exists(f"/tmp/perf-{os.getpid()}.map"),
        "cpu_phase": {"function": "spy_cpu_loop", "window_ns": cpu_window, "cpu_seconds": cpu_seconds},
        "native_phase": {"function": "spy_native_phase", "extension": "spnative.burn", "window_ns": native_window, "cpu_seconds": native_seconds, "checksum": checksum & 0xFFFF},
        "wait": {"loop_tid": threading.get_native_id(),
                 "http": {"kind": "asyncio loopback HTTP", "requests": len(waited), "wait_seconds_total": sum(waited), "wait_seconds_min": min(waited), "server_delay_s": 0.05, "window_ns": wait_window},
                 "database": {"status": "not_run", "reason": "phase not requested"}},
    }), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
