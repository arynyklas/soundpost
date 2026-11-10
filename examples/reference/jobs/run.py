# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
"""Scheduler + worker for job reference.catalog.refresh in one process.

The scheduler enqueues the deterministic run and retries after a deterministic
exponential backoff; the worker runs each attempt inside the SDK job-attempt
API. Exits 0 only when the run finally succeeded and the flush is clean.
"""
import argparse
import json
import os
import platform
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "api"))
import telemetry  # noqa: E402

JOB_ALIAS = "reference.catalog.refresh"
PROMPT = "Refresh catalog summaries for the reference journey."


class DependencyUnavailable(Exception):
    pass


def work(instruments, dsn, run_id, ordinal):
    import psycopg
    response = instruments.post_dependency(
        "/v1/complete", json={"prompt": PROMPT, "max_tokens": 32}, headers={"X-Reference-Run": run_id})
    if response.status_code != 200:
        raise DependencyUnavailable
    completion = response.json()["completion"]
    with psycopg.connect(dsn, autocommit=True) as connection:
        instruments.database(connection).execute(
            "INSERT INTO catalog_refresh(run_id, attempt, completion) VALUES (%s, %s, %s)",
            (run_id, ordinal, completion))


def run_attempt(client, instruments, dsn, run_id, ordinal):
    """One worker attempt. Failures propagate through the SDK scope first."""
    if client is None:
        return work(instruments, dsn, run_id, ordinal)
    with client.span("job.run"):
        with client.job_attempt(JOB_ALIAS, run_id, ordinal):
            work(instruments, dsn, run_id, ordinal)


def versions():
    import httpx
    import psycopg
    try:
        import cryptography
        crypto = cryptography.__version__
    except ImportError:
        crypto = None
    return {"python": platform.python_version(), "cryptography": crypto,
            "psycopg": psycopg.__version__, "httpx": httpx.__version__}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config")
    parser.add_argument("--dependency-url", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--max-attempts", type=int, default=3)
    parser.add_argument("--backoff-ms", type=int, default=250)
    parser.add_argument("--ca")
    args = parser.parse_args()
    dsn = os.environ["REFERENCE_DATABASE_URL"]

    client = data = None
    if args.config:
        client, data = telemetry.load_client(args.config)
    http = telemetry.http_client(args.ca or (data or {}).get("ca_file"))
    instruments = telemetry.Instruments(client, http, args.dependency_url)

    attempts, succeeded = [], False
    for ordinal in range(1, args.max_attempts + 1):  # scheduler: enqueue, then retry with backoff
        try:
            run_attempt(client, instruments, dsn, args.run_id, ordinal)
        except Exception as error:
            attempts.append({"ordinal": ordinal, "outcome": "failed", "error": type(error).__name__})
            if ordinal < args.max_attempts:
                time.sleep(args.backoff_ms * (2 ** (ordinal - 1)) / 1000.0)
            continue
        attempts.append({"ordinal": ordinal, "outcome": "succeeded"})
        succeeded = True
        break
    http.close()
    report, clean = telemetry.finish(client, 10.0)
    print(json.dumps({"run_id": args.run_id, "job_alias": JOB_ALIAS, "attempts": attempts,
                      "flush": report, "versions": versions()}), flush=True)
    sys.exit(0 if succeeded and clean else 1)


if __name__ == "__main__":
    main()
