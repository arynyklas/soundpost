# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
"""Fresh short-lived process end-to-end check against a real ingest server.

Each run starts a brand-new Python process that records one span, calls ``client.flush(5.0)`` and ``client.close()``.
The run passes only if the first flush already holds a durable receipt (receipts>=1, pending==0) and close dropped nothing.

    python fixtures/sdk/python/short_process.py --config private-config.json [--runs 10]

The JSON config uses the parent-written layout of ``examples/reference/api/telemetry.py`` (org, project, source, endpoint,
credential, build, resource, descriptor, policy, trusted_keys, ca_file). The source's signed policy must permit traces and its
registered operations must include ``request``. The server and its CA are real; nothing here bypasses TLS verification.
"""
import argparse
import base64
import json
import subprocess
import sys
import time
from pathlib import Path

OPERATION = "request"

def load_client(path):
    from soundpost import Config, Resource, RoutingDescriptor, SignedPolicy, init
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    res = data["resource"]
    keys = {name: base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)) for name, value in data["trusted_keys"].items()}
    config = Config(
        org=data["org"], project=data["project"], source=data["source"], endpoint=data["endpoint"],
        credential=data["credential"], build=data["build"],
        resource=Resource(res["service_id"], res["environment_id"], res["build_id"], res["instance_pseudonym"],
                          tuple((label["name"], label["value"]) for label in res.get("labels", []))),
        descriptor=RoutingDescriptor(**data["descriptor"]), policy=SignedPolicy(**data["policy"]),
        trusted_keys=keys, ca_file=data.get("ca_file"), operations=(OPERATION,),
    )
    return init(config)

def child(path):
    started = time.monotonic()
    client = load_client(path)
    with client.span(OPERATION, kind="server") as span:
        span.set_error()
    flushed = client.flush(5.0)
    closed = client.close()
    print(json.dumps({
        "receipts": len(flushed.receipts), "pending": flushed.pending, "lost": flushed.lost,
        "deadline_exceeded": flushed.deadline_exceeded, "dropped": closed.dropped,
        "elapsed_s": round(time.monotonic() - started, 3),
    }))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--runs", type=int, default=10)
    parser.add_argument("--child", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.child:
        child(args.config)
        return 0
    failures = 0
    for number in range(1, args.runs + 1):
        done = subprocess.run([sys.executable, __file__, "--child", "--config", args.config], capture_output=True, text=True, timeout=60)
        try:
            result = json.loads(done.stdout.strip().splitlines()[-1])
        except (IndexError, ValueError):
            result = {"error": "no result", "returncode": done.returncode}
        ok = done.returncode == 0 and result.get("receipts", 0) >= 1 and result.get("pending") == 0 and result.get("dropped") == 0
        failures += not ok
        print(f"run {number}/{args.runs}: {'ok' if ok else 'FAIL'} {json.dumps(result)}", flush=True)
    print(f"{args.runs - failures}/{args.runs} fresh short processes delivered their span")
    return 1 if failures else 0

if __name__ == "__main__":
    sys.exit(main())
