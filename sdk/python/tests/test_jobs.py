# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
"""Job producers must preserve execution and admit only native, private-safe events."""
import asyncio
import json
import secrets
from dataclasses import replace
import pytest
from soundpost import init
from soundpost.context import TraceContext
from test_trace_policy import signed

JOB = 'a' * 32
RUN = 'b' * 32

def settings(**changes):
    values = {'job_registry': (('fixture.task', JOB),), **changes}
    return replace(signed(jobs=True, traces=True), **values)

def records(instance, kind='job_attempt'):
    return [json.loads(value) for value in instance.buffered_records() if json.loads(value)['kind'] == kind]

def test_sync_attempt_emits_exact_started_and_terminal_without_inventing_health():
    instance = init(settings())
    try:
        with instance.job_attempt('fixture.task', RUN, 18446744073709551615) as attempt:
            assert attempt.run_id == RUN
        events = records(instance)
        assert [event['payload']['state'] for event in events] == ['started', 'succeeded']
        started, terminal = [event['payload'] for event in events]
        assert started['job_id'] == terminal['job_id'] == JOB
        assert started['run_id'] == terminal['run_id'] == RUN
        assert started['attempt_id'] == terminal['attempt_id'] != '0' * 32
        assert started['producer_epoch'] == terminal['producer_epoch'] != '0' * 32
        assert started['ordinal'] == '18446744073709551615'
        assert [started['sequence'], terminal['sequence']] == ['1', '2']
        assert started['schedule_occurrence'] == 'manual.' + RUN
        assert started['observed_ns'] == terminal['observed_ns'] == '9007199254740993'
        assert started['terminal_ns'] is None
        assert terminal['terminal_ns'] == '9007199254740993'
        assert 'fixture.task' not in ''.join(instance.buffered_records())
        assert not any(key in terminal for key in ('health', 'cron', 'arguments', 'body'))
        with pytest.raises(RuntimeError):
            with attempt: pass
    finally: instance.close()

def test_failed_unsampled_attempt_links_sanitized_error_and_preserves_exception():
    class PrivateError(Exception):
        def __str__(self): raise AssertionError('message inspected')
        def __repr__(self): raise AssertionError('value inspected')
    original = PrivateError('CANARY_ARGUMENT')
    instance = init(settings())
    try:
        with instance._trace_context.bind(TraceContext('c' * 32, 'd' * 16, False, 0.0)):
            with pytest.raises(PrivateError) as raised:
                with instance.job_attempt('fixture.task', RUN, 1): raise original
        assert raised.value is original
        terminal = records(instance)[-1]['payload']
        errors = records(instance, 'error')
        assert terminal['state'] == 'failed'
        assert len(errors) == 1
        assert terminal['cause_error'] == errors[0]['id']
        assert terminal['cause_trace'] == 'c' * 32
        assert errors[0]['payload']['run_id'] == RUN
        assert not records(instance, 'span')
        assert 'CANARY' not in ''.join(instance.buffered_records())
        instance.capture_exception(ValueError('outside'))
        assert 'run_id' not in records(instance, 'error')[-1]['payload']
    finally: instance.close()

def test_async_concurrent_retry_and_cancellation_restore_context():
    async def exercise(instance):
        ready = asyncio.Event()
        async def task(index):
            run = f'{index + 1:032x}'
            async with instance.job_attempt('fixture.task', run, index + 1):
                await ready.wait()
                instance.capture_exception(ValueError('CANARY_BODY'))
                if index == 0: raise asyncio.CancelledError()
            return run
        children = [asyncio.create_task(task(index)) for index in range(20)]
        await asyncio.sleep(0)
        ready.set()
        outcomes = await asyncio.gather(*children, return_exceptions=True)
        assert isinstance(outcomes[0], asyncio.CancelledError)
        assert outcomes[1] == f'{2:032x}'
        instance.capture_exception(ValueError('outside'))
    instance = init(settings())
    try:
        asyncio.run(exercise(instance))
        events = records(instance)
        assert len(events) == 40
        assert sorted(int(event['payload']['sequence']) for event in events) == list(range(1, 41))
        terminals = [event['payload'] for event in events if event['payload']['terminal_ns'] is not None]
        assert sum(event['state'] == 'cancelled' for event in terminals) == 1
        assert sum(event['state'] == 'succeeded' for event in terminals) == 19
        errors = records(instance, 'error')
        assert {event['payload']['run_id'] for event in errors[:-1]} == {f'{index + 1:032x}' for index in range(20)}
        assert 'run_id' not in errors[-1]['payload']
    finally: instance.close()

@pytest.mark.parametrize('ordinal', [True, False, 0, -1, 1.0, '1', 18446744073709551616])
def test_ordinal_validation_never_enters_application(ordinal):
    instance = init(settings())
    try:
        with pytest.raises((ValueError, TypeError)):
            with instance.job_attempt('fixture.task', RUN, ordinal): pytest.fail('body entered')
        assert not instance.buffered_records()
    finally: instance.close()

@pytest.mark.parametrize('job,run', [('unknown', RUN), ('fixture.task', '0' * 32), ('fixture.task', 'B' * 32), ('fixture.task', 'display-run')])
def test_registered_jobs_and_canonical_run_ids_are_required(job, run):
    instance = init(settings())
    try:
        with pytest.raises(ValueError): instance.job_attempt(job, run, 1)
        assert not instance.buffered_records()
    finally: instance.close()

@pytest.mark.parametrize('registry', [(('task', '0' * 32),), (('task', JOB), ('task', RUN)), (('task/private', JOB),), {'task': JOB}])
def test_registry_rejects_ambiguous_or_unbounded_shapes(registry):
    with pytest.raises((ValueError, TypeError)): init(settings(job_registry=registry))
    with pytest.raises(ValueError): init(settings(job_registry=tuple((f'task{i}', JOB) for i in range(1025))))

def test_deployment_and_signed_jobs_denial_does_not_change_callback_behavior():
    for config in (replace(settings(), deployment_jobs=False), replace(settings(), policy=signed(jobs=False).policy)):
        instance = init(config)
        try:
            original = ValueError('CANARY')
            with pytest.raises(ValueError) as raised:
                with instance.job_attempt('fixture.task', RUN, 1): raise original
            assert raised.value is original
            assert not records(instance)
            assert len(records(instance, 'error')) == 1
        finally: instance.close()

def test_clock_failure_and_queue_overflow_never_replace_application_exception():
    for config in (settings(clock_ns=lambda: 'bad-clock'), settings(max_records=1)):
        instance = init(config)
        original = ValueError('CANARY')
        try:
            with pytest.raises(ValueError) as raised:
                with instance.job_attempt('fixture.task', RUN, 1): raise original
            assert raised.value is original
            assert len(instance.buffered_records()) <= 1
            instance.capture_exception(ValueError('outside'))
            assert all('CANARY' not in value for value in instance.buffered_records())
        finally: instance.close()

def test_closed_job_native_payload_rejects_hostile_fields_and_terminal_invariants():
    from soundpost.jobs import normalize_attempt
    instance = init(settings())
    try:
        with instance.job_attempt('fixture.task', RUN, 1): pass
        payload = records(instance)[0]['payload']
        assert normalize_attempt(payload) == payload
        for changes in ({'arguments': 'CANARY'}, {'producer_epoch': '0' * 32}, {'ordinal': '0'}, {'schedule_occurrence': 'unsafe/path'}, {'schedule_occurrence': 'a' * 257}, {'terminal_ns': '1'}, {'state': 'succeeded'}, {'state': 'failed', 'terminal_ns': '1'}):
            with pytest.raises((ValueError, TypeError)): normalize_attempt({**payload, **changes})
    finally: instance.close()

def test_retry_attempt_ids_nested_scopes_and_thread_boundary_do_not_conflate_runs():
    from concurrent.futures import ThreadPoolExecutor
    instance = init(settings())
    inner_run = 'c' * 32
    try:
        with instance.job_attempt('fixture.task', RUN, 1):
            instance.capture_exception(ValueError('outer before'))
            with instance.job_attempt('fixture.task', inner_run, 1):
                instance.capture_exception(ValueError('inner'))
            instance.capture_exception(ValueError('outer after'))
            with ThreadPoolExecutor(max_workers=1) as workers:
                workers.submit(instance.capture_exception, ValueError('unrelated thread')).result()
        with instance.job_attempt('fixture.task', RUN, 2): pass
        errors = records(instance, 'error')
        assert [event['payload'].get('run_id') for event in errors] == [RUN, inner_run, RUN, None]
        attempts = [event['payload'] for event in records(instance)]
        assert [event['ordinal'] for event in attempts if event['run_id'] == RUN] == ['1', '1', '2', '2']
        assert len({event['attempt_id'] for event in attempts}) == 3
        assert len({event['producer_epoch'] for event in attempts}) == 1
    finally: instance.close()

def test_terminal_clock_regression_is_unknown_loss_not_a_fabricated_time():
    clocks = iter(('9007199254740993', '9007199254740992'))
    instance = init(settings(clock_ns=lambda: next(clocks)))
    try:
        with instance.job_attempt('fixture.task', RUN, 1): pass
        assert [event['payload']['state'] for event in records(instance)] == ['started']
        assert instance.diagnostics()['job_clock_unavailable'] == 1
    finally: instance.close()


# --- Celery propagation: a real Celery app, kombu in-memory broker and a real solo-pool worker thread ---
celery = pytest.importorskip('celery')
from celery.contrib.testing.worker import start_worker
from soundpost.celery import instrument

TRACE = 'c' * 32
SPAN = 'd' * 16


class CeleryRig:
    def __init__(self, instance, name, origin='queue'):
        self.seen_context = []
        self.attempts = {'count': 0}
        self.app = celery.Celery('soundpost_rig', broker='memory://', backend='cache+memory://')
        # Each rig owns one queue: the in-memory kombu transport is process-wide, so a previous rig's worker must never consume this rig's message.
        self.app.conf.update(task_default_retry_delay=0, worker_hijack_root_logger=False, task_always_eager=False, task_default_queue='soundpost-' + secrets.token_hex(8))
        rig = self

        @self.app.task(bind=True, name=name, max_retries=2)
        def work(task, mode):
            rig.seen_context.append(instance._trace_context.current())
            rig.attempts['count'] += 1
            if mode == 'retry_once' and task.request.retries == 0:
                raise task.retry(exc=ValueError('CANARY_TASK_ARGUMENT_MESSAGE'), countdown=0)
            if mode == 'fail':
                raise ValueError('CANARY_TASK_FAILURE')
            return 'done'
        self.task = work
        self.instrumentation = instrument(self.app, instance, origin=origin)

    def run(self, mode, bind=None, timeout=20):
        with start_worker(self.app, pool='solo', perform_ping_check=False, shutdown_timeout=20):
            if bind is None:
                result = self.task.apply_async((mode,))
            else:
                with bind:
                    result = self.task.apply_async((mode,))
            try:
                return result.get(timeout=timeout)
            except ValueError:
                return 'failed'


def unique_task():
    return 'fixture.celery.' + secrets.token_hex(4)


def celery_settings(**changes):
    return settings(origins=('queue',), **changes)


def test_celery_failure_then_retry_retains_both_attempts_under_one_run():
    NAME = unique_task()
    instance = init(celery_settings(job_registry=((NAME, JOB),)))
    rig = CeleryRig(instance, NAME)
    try:
        assert rig.run('retry_once') == 'done'
        attempts = [event['payload'] for event in records(instance)]
        assert [event['state'] for event in attempts] == ['started', 'failed', 'started', 'succeeded']
        assert [event['ordinal'] for event in attempts] == ['1', '1', '2', '2']
        assert len({event['run_id'] for event in attempts}) == 1 and attempts[0]['job_id'] == JOB
        assert attempts[0]['attempt_id'] == attempts[1]['attempt_id'] != attempts[2]['attempt_id'] == attempts[3]['attempt_id']
        assert [event['sequence'] for event in attempts] == ['1', '2', '3', '4']
        error = records(instance, 'error')[0]
        assert attempts[1]['cause_error'] == error['id'] and error['payload']['run_id'] == attempts[0]['run_id']
        assert 'cause_error' not in attempts[3]
        blob = ''.join(instance.buffered_records())
        assert 'CANARY' not in blob and NAME not in blob
        assert not records(instance, 'span')
    finally:
        rig.instrumentation.close()
        instance.close()


def test_celery_exhausted_failure_is_failed_and_publisher_trace_is_a_link_not_a_child_span():
    NAME = unique_task()
    instance = init(celery_settings(job_registry=((NAME, JOB),)))
    rig = CeleryRig(instance, NAME)
    try:
        assert rig.run('fail', bind=instance._trace_context.bind(TraceContext(TRACE, SPAN, True, 1.0))) == 'failed'
        attempts = [event['payload'] for event in records(instance)]
        assert [event['state'] for event in attempts] == ['started', 'failed']
        assert {event['cause_trace'] for event in attempts} == {TRACE}
        # Safe link only: the worker never adopts the publisher's span as the active parent.
        assert rig.seen_context == [None]
        assert not records(instance, 'span')
        assert SPAN not in ''.join(instance.buffered_records())
    finally:
        rig.instrumentation.close()
        instance.close()


def test_celery_origin_must_be_allow_listed_before_trace_headers_are_published():
    NAME = unique_task()
    instance = init(celery_settings(job_registry=((NAME, JOB),)))
    rig = CeleryRig(instance, NAME, origin='external')
    try:
        assert rig.run('ok', bind=instance._trace_context.bind(TraceContext(TRACE, SPAN, True, 1.0))) == 'done'
        attempts = [event['payload'] for event in records(instance)]
        assert [event['state'] for event in attempts] == ['started', 'succeeded']
        assert all('cause_trace' not in event for event in attempts)
    finally:
        rig.instrumentation.close()
        instance.close()


def test_celery_unregistered_task_and_closed_instrumentation_change_nothing():
    NAME = unique_task()
    instance = init(celery_settings(job_registry=(('other.task', JOB),)))
    rig = CeleryRig(instance, NAME)
    try:
        assert rig.run('retry_once') == 'done' and rig.attempts['count'] == 2
        assert records(instance) == []
    finally:
        rig.instrumentation.close()
        instance.close()
    NAME = unique_task()
    instance = init(celery_settings(job_registry=((NAME, JOB),)))
    rig = CeleryRig(instance, NAME)
    try:
        assert rig.run('ok') == 'done' and len(records(instance)) == 2
        rig.instrumentation.close()
        assert rig.run('ok') == 'done' and len(records(instance)) == 2
    finally:
        instance.close()
