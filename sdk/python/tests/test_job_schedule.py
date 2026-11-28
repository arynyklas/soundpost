# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
"""A scheduler-driven attempt carries jobs.OccurrenceKey, never manual.<run>."""
import json
import pathlib
import pytest
from soundpost import init
from soundpost.jobs import occurrence_key
from dataclasses import replace
from test_trace_policy import signed

JOB = 'a' * 32
RUN = 'b' * 32


def settings(**changes):
    return replace(signed(jobs=True, traces=True), **{'job_registry': (('fixture.task', JOB),), **changes})


def records(instance, kind='job_attempt'):
    return [json.loads(value) for value in instance.buffered_records() if json.loads(value)['kind'] == kind]


# Go: jobs.OccurrenceKey("UTC", 1699999200000000000, 0); the tag is pinned in internal/jobs TestOccurrenceKeyVectors.
VECTOR_TAG_UTC = '4bda1821'
GOLDEN = pathlib.Path(__file__).resolve().parents[3] / 'internal' / 'appcore' / 'testdata' / 'sdk-scheduled-retry-journey.json'
SCHEDULED_AT = 1699999200000000000


def test_scheduled_attempt_emits_the_occurrence_key_not_manual():
    clocks = iter(('1699999205000000000', '1699999220000000000'))
    instance = init(settings(clock_ns=lambda: next(clocks)))
    try:
        with instance.job_attempt('fixture.task', RUN, 1, ('UTC', SCHEDULED_AT, 0)):
            pass
        keys = {event['payload']['schedule_occurrence'] for event in records(instance)}
        assert keys == {occurrence_key('UTC', SCHEDULED_AT, 0)}
        assert next(iter(keys)).startswith('s.%d.f0.' % SCHEDULED_AT)
    finally: instance.close()


def test_unscheduled_attempt_stays_manual():
    instance = init(settings())
    try:
        with instance.job_attempt('fixture.task', RUN, 1): pass
        assert {e['payload']['schedule_occurrence'] for e in records(instance)} == {'manual.' + RUN}
    finally: instance.close()


def test_occurrence_key_matches_the_server_vectors_and_rejects_malformed_schedules():
    # The Go reducer parses exactly this shape; its tag for "UTC" is pinned in internal/jobs/reducer_test.go.
    assert occurrence_key('UTC', SCHEDULED_AT, 0) == 's.1699999200000000000.f0.' + VECTOR_TAG_UTC
    assert occurrence_key('UTC', SCHEDULED_AT, 1).endswith('.f1.' + VECTOR_TAG_UTC)
    assert occurrence_key('Europe/London', SCHEDULED_AT, 0) != occurrence_key('UTC', SCHEDULED_AT, 0)
    for bad in (('UTC', 0, 0), ('UTC', -1, 0), ('UTC', 1, 2), ('', 1, 0), (1, 1, 0), ('UTC', '1', 0), ('UTC', True, 0), ('UTC', 1, True), ('UTC',), ('UTC', 1, 0, 0), ['UTC', 1, 0]):
        instance = init(settings())
        try:
            with pytest.raises(ValueError):
                instance.job_attempt('fixture.task', RUN, 1, bad)
        finally: instance.close()


def run_journey():
    """A scheduled run whose first attempt fails and whose retry succeeds (the clock reads: start, error, end, start, end)."""
    times = iter(('1699999205000000000', '1699999210000000000', '1699999220000000000', '1699999260000000000', '1699999290000000000'))
    instance = init(settings(clock_ns=lambda: next(times)))
    try:
        with pytest.raises(RuntimeError):
            with instance.job_attempt('fixture.task', RUN, 1, ('UTC', SCHEDULED_AT, 0)): raise RuntimeError('boom')
        with instance.job_attempt('fixture.task', RUN, 2, ('UTC', SCHEDULED_AT, 0)): pass
        return [event['payload'] for event in records(instance)]
    finally: instance.close()


def test_scheduled_retry_journey_matches_the_committed_server_fixture():
    """The SDK's output for a scheduled run that fails then retries is the fixture the Go journey ingests."""
    attempts = run_journey()
    golden = json.loads(GOLDEN.read_text(encoding='utf8'))
    assert len(attempts) == len(golden) == 4
    ids = {}
    for got, want in zip(attempts, golden):
        for name in ('attempt_id', 'producer_epoch', 'cause_error'):
            if name in want:
                assert ids.setdefault((name, want[name]), got[name]) == got[name]  # same identity classes
                got[name] = want[name]
        assert got == want
    assert len({e['attempt_id'] for e in golden}) == 2
