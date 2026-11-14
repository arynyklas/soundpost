# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
"""Python job journey against an actual Soundpost endpoint.

Row 1 (explicit): failure ordinal 1, success ordinal 2 and cancellation through
``fixtures/sdk/python/job_attempts.py`` (real C03/C05 receipts, independent reader).

Row 2 (Celery): a real Celery 5 worker *process* (solo pool) consuming from a kombu filesystem
broker. The publisher's trace is a cause link on the worker attempts, a retry is ordinal 2 of the
same run, and the worker's records are read back through the same independent verifier. The
filesystem transport is a real broker transport but NOT Redis/RabbitMQ: it does not qualify those. On Windows kombu's filesystem transport additionally needs pywin32.

Run: python fixtures/sdk/jobs/python_attempts.py  (SOUNDPOST_FIXTURE_CONFIG/_INGEST/_VERIFY/_READ_CREDENTIAL/_JOB_ID).
"""
import json
import os
import secrets
import subprocess
import sys
import tempfile
import time
from dataclasses import replace
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path[:0] = [str(HERE.parent / 'python'), str(ROOT / 'sdk' / 'python' / 'src')]

from celery import Celery, signals  # noqa: E402
from soundpost import init  # noqa: E402
from soundpost.celery import instrument  # noqa: E402
from soundpost.context import TraceContext  # noqa: E402
from soundpost.policy import canonical_id  # noqa: E402
from soundpost.types import FlushReport  # noqa: E402
from critical_path import load_config, verify_http  # noqa: E402

TASK = 'fixture.celery.retry'
FINISH = 'fixture.celery.finish'
ROLE = os.environ.get('SOUNDPOST_FIXTURE_CELERY_ROLE', 'parent')


def fixture_config():
    config = load_config(os.environ['SOUNDPOST_FIXTURE_CONFIG'], os.environ['SOUNDPOST_FIXTURE_INGEST'])
    if os.environ['SOUNDPOST_FIXTURE_READ_CREDENTIAL'] == config.credential:
        raise AssertionError('independent_reader_required')
    return replace(config, job_registry=((TASK, canonical_id(os.environ['SOUNDPOST_FIXTURE_JOB_ID'])),), origins=('queue',))


def make_app(directory):
    broker = Path(directory) / 'broker'
    for name in ('in', 'processed', 'control'): (broker / name).mkdir(parents=True, exist_ok=True)
    app = Celery('soundpost_fixture', broker='filesystem://', backend='file://' + (Path(directory) / 'results').as_posix())
    (Path(directory) / 'results').mkdir(exist_ok=True)
    app.conf.update(
        broker_transport_options={'data_folder_in': str(broker / 'in'), 'data_folder_out': str(broker / 'in'),
                                  'processed_folder': str(broker / 'processed'), 'control_folder': str(broker / 'control')},
        task_default_retry_delay=0, worker_hijack_root_logger=False, task_serializer='json', result_serializer='json', accept_content=['json'])
    return app


def define_tasks(app, client):
    @app.task(bind=True, name=TASK, max_retries=2)
    def retrying(task):
        if task.request.retries == 0:
            raise task.retry(exc=ValueError('CANARY_TASK_ARGUMENT_MESSAGE'), countdown=0)
        return 'recovered'

    @app.task(name=FINISH)
    def finish():
        # Runs inside the worker process: the only place the worker's records exist before delivery.
        expected = list(client.buffered_records())
        report = client.flush(10)
        return {'expected': expected, 'acknowledged_batch_ids': list(report.acknowledged_batch_ids), 'acknowledged_cursors': list(report.acknowledged_cursors),
                'pending': report.pending, 'lost': report.lost, 'deadline_exceeded': report.deadline_exceeded, 'receipts': list(report.receipts)}
    return retrying, finish


if ROLE == 'worker':
    _client = init(fixture_config())
    app = make_app(os.environ['SOUNDPOST_FIXTURE_CELERY_DIR'])
    instrument(app, _client, origin='queue')
    define_tasks(app, _client)
    signals.worker_shutdown.connect(lambda **_: _client.close(), weak=False)


def celery_row(config):
    publisher = init(config)
    directory = tempfile.mkdtemp(prefix='soundpost-celery-')
    app = make_app(directory)
    instrument(app, publisher, origin='queue')
    retrying, finish = define_tasks(app, publisher)  # the publisher process never executes these
    env = {**os.environ, 'SOUNDPOST_FIXTURE_CELERY_ROLE': 'worker', 'SOUNDPOST_FIXTURE_CELERY_DIR': directory,
           'PYTHONPATH': os.pathsep.join([str(HERE), str(HERE.parent / 'python'), str(ROOT / 'sdk' / 'python' / 'src')])}
    worker = subprocess.Popen([sys.executable, '-m', 'celery', '-A', 'python_attempts', 'worker', '--pool=solo', '--loglevel=WARNING', '--without-gossip', '--without-mingle'],
                              cwd=str(HERE), env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        trace = secrets.token_hex(16)
        start = time.time_ns()
        with publisher._trace_context.bind(TraceContext(trace, secrets.token_hex(8), True, 1.0)):
            result = retrying.apply_async()
        if result.get(timeout=90) != 'recovered': raise AssertionError('celery_task_result_changed')
        evidence = finish.apply_async().get(timeout=60)
        end = time.time_ns()
        expected = [json.loads(value) for value in evidence['expected']]
        events = [record['payload'] for record in expected if record['kind'] == 'job_attempt']
        if [(event['ordinal'], event['state']) for event in events] != [('1', 'started'), ('1', 'failed'), ('2', 'started'), ('2', 'succeeded')]:
            raise AssertionError('celery_attempt_history_changed')
        if len({event['run_id'] for event in events}) != 1 or events[0]['attempt_id'] == events[2]['attempt_id']: raise AssertionError('celery_attempt_identity_changed')
        if {event.get('cause_trace') for event in events} != {trace}: raise AssertionError('celery_cause_link_missing')
        if any(record['kind'] == 'span' for record in expected): raise AssertionError('celery_child_span_created')
        if 'CANARY_' in json.dumps(expected): raise AssertionError('celery_prequeue_privacy_failure')
        report = FlushReport(tuple(evidence['acknowledged_batch_ids']), tuple(evidence['acknowledged_cursors']), evidence['pending'], evidence['lost'], evidence['deadline_exceeded'], tuple(evidence['receipts']))
        if report.pending or report.lost or not report.receipts: raise AssertionError('celery_delivery_incomplete')
        admitted, _ = verify_http(config, report, expected, start, end)
        actual = {record['id']: record for record in admitted}
        for record in expected:
            observed = actual.get(record['id'])
            if observed is None or observed['kind'] != record['kind'] or observed['payload'] != record['payload']: raise AssertionError('celery_admitted_evidence_changed')
        return {'celery_records': len(expected), 'celery_batches': len(report.receipts)}
    finally:
        worker.terminate()
        try: worker.wait(15)
        except subprocess.TimeoutExpired: worker.kill()
        publisher.close()


def main():
    config = fixture_config()
    import job_attempts
    job_attempts.main()
    summary = celery_row(config)
    print(json.dumps({'fixture': 'python_celery_attempts', 'runtime': sys.version.split()[0], 'real_c03_c05': True, 'celery_real_worker_process': True,
                      'celery_broker': 'kombu-filesystem', 'redis_or_rabbitmq_qualified': False, 'manual_unscheduled': True, 'current_health_claimed': False, **summary}))


if __name__ == '__main__':
    try: main()
    except BaseException:
        # Raw exception messages may contain private source config or task values.
        raise SystemExit('python_attempts_fixture_failed') from None
