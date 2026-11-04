# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
"""Real C03/C05 job journey. Source permissions and independent reader are required."""
import asyncio
from dataclasses import replace
import json
import os
import platform
import secrets
import sys
import time
from soundpost import init
from soundpost.context import TraceContext
from soundpost.policy import canonical_id
from critical_path import load_config, verify_http


async def exercise(client, run_id):
    original = ValueError('CANARY_TASK_ARGUMENT_MESSAGE')
    try:
        with client.job_attempt('fixture.task', run_id, 1):
            raise original
    except ValueError as error:
        if error is not original: raise AssertionError('exception_identity_changed')
    async with client.job_attempt('fixture.task', run_id, 2):
        await asyncio.sleep(0)
        client.capture_exception(ValueError('CANARY_HANDLED_TASK_ERROR'))
    cancelled = asyncio.CancelledError('CANARY_TASK_CANCEL')
    try:
        async with client.job_attempt('fixture.task', secrets.token_hex(16), 1):
            await asyncio.sleep(0)
            raise cancelled
    except asyncio.CancelledError as error:
        if error is not cancelled: raise AssertionError('cancellation_identity_changed')
    client.capture_exception(ValueError('outside'))


def main():
    config = replace(load_config(os.environ['SOUNDPOST_FIXTURE_CONFIG'], os.environ['SOUNDPOST_FIXTURE_INGEST']),
                     job_registry=(('fixture.task', canonical_id(os.environ['SOUNDPOST_FIXTURE_JOB_ID'])),))
    if os.environ['SOUNDPOST_FIXTURE_READ_CREDENTIAL'] == config.credential:
        raise AssertionError('independent_reader_required')
    client = init(config)
    try:
        if not all((client.policy_decision.jobs, client.policy_decision.errors, client.policy_decision.loss, client.policy_decision.traces)):
            raise AssertionError('signed_signal_permissions_required')
        start = time.time_ns()
        # This actual dropped trace proves errors/jobs do not borrow span sampling.
        with client._trace_context.bind(TraceContext(secrets.token_hex(16), secrets.token_hex(8), False, 0.0)):
            with client.span('request'): pass
            asyncio.run(exercise(client, secrets.token_hex(16)))
        end = time.time_ns()
        expected = [json.loads(value) for value in client.buffered_records()]
        events = [record['payload'] for record in expected if record['kind'] == 'job_attempt']
        if [event['state'] for event in events] != ['started', 'failed', 'started', 'succeeded', 'started', 'cancelled']:
            raise AssertionError('attempt_history_changed')
        if events[0]['attempt_id'] != events[1]['attempt_id'] or events[0]['attempt_id'] == events[2]['attempt_id']:
            raise AssertionError('attempt_identity_changed')
        if [event['sequence'] for event in events] != ['1', '2', '3', '4', '5', '6']:
            raise AssertionError('attempt_sequence_changed')
        errors = [record for record in expected if record['kind'] == 'error']
        if len(errors) != 3 or 'run_id' in errors[-1]['payload'] or events[1].get('cause_error') != errors[0]['id']:
            raise AssertionError('job_error_link_changed')
        if any(record['kind'] == 'span' for record in expected): raise AssertionError('unsampled_span_exported')
        if 'CANARY_' in json.dumps(expected): raise AssertionError('prequeue_privacy_failure')
        report = client.flush(10)
        if report.pending or report.lost or not report.receipts: raise AssertionError('durable_delivery_incomplete')
        admitted, _ = verify_http(config, report, expected, start, end)
        actual = {record['id']: record for record in admitted}
        for record in expected:
            observed = actual.get(record['id'])
            if observed is None or observed['kind'] != record['kind'] or observed['payload'] != record['payload']:
                raise AssertionError('admitted_job_evidence_changed')
        if 'CANARY_' in json.dumps(admitted): raise AssertionError('admitted_privacy_failure')
        print(json.dumps({'fixture': 'python_job_attempts', 'runtime': sys.version.split()[0], 'platform': platform.system(),
                          'records': len(expected), 'batches': len(report.receipts), 'real_c03_c05': True,
                          'manual_unscheduled': True, 'current_health_claimed': False}))
    finally: client.close()


if __name__ == '__main__':
    try: main()
    except BaseException:
        # Raw exception messages may contain private source config or task values.
        raise SystemExit('job_attempt_fixture_failed') from None
