# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
"""Drives the real Python SDK's job API through an interrupted exporter, in two processes that share one encrypted spool.

  crash   the SDK cannot reach the product (the path to it refuses every connection): attempt 1 of a run raises, its events cannot be delivered
          (flush ends with them pending), and the process dies at once (os._exit, no close, no flush, nothing delivered).
  resume  a new process of the same job opens the same spool (the retained work is recovered) with the path restored, runs attempt 2 of the SAME run,
          which succeeds, and flushes: the recovered events and the new ones are delivered, verified by durable receipts.

Configuration: SOUNDPOST_SDK_CONFIG (the file web/e2e/support/real.ts sdkConfig writes), SOUNDPOST_SDK_JOB (the job ID), SOUNDPOST_SDK_SPOOL (the spool file),
SOUNDPOST_SDK_RUN (resume only: the run the first process printed). Prints one JSON line."""
import base64
import hashlib
import json
import os
import secrets
import sys
from pathlib import Path
from soundpost import Config, Resource, RoutingDescriptor, SignedPolicy, init
from soundpost.spool import EncryptedSpool


def load(path, job, spool):
    data = json.loads(Path(path).read_text(encoding='utf-8'))
    resource = data['resource']
    keys = {name: base64.urlsafe_b64decode(value + '=' * (-len(value) % 4)) for name, value in data['trusted_keys'].items()}
    descriptor = RoutingDescriptor(**data['descriptor'])
    store = EncryptedSpool(spool, hashlib.sha256(b'soundpost e2e interrupted exporter spool').digest(), descriptor, descriptor.policy_revision)
    return Config(org=data['org'], project=data['project'], source=data['source'], endpoint=data['endpoint'], credential=data['credential'], build=data['build'],
                  resource=Resource(resource['service_id'], resource['environment_id'], resource['build_id'], resource['instance_pseudonym'], ()),
                  descriptor=descriptor, policy=SignedPolicy(**data['policy']), trusted_keys=keys, ca_file=data.get('ca_file'),
                  job_registry=(('e2e.task', job),), spool=store)


def events_of(client):
    records = [json.loads(value) for value in client.buffered_records()]
    return [r['payload'] for r in records if r['kind'] == 'job_attempt'], [r for r in records if r['kind'] == 'error']


def crash(client):
    if not (client.policy_decision.jobs and client.policy_decision.errors):
        raise AssertionError('signed_job_and_error_permissions_required')
    run = secrets.token_hex(16)
    try:
        with client.job_attempt('e2e.task', run, 1):
            raise ValueError('e2e task failed')
    except ValueError:
        pass
    events, errors = events_of(client)
    if [e['state'] for e in events] != ['started', 'failed'] or len(errors) != 1 or events[1].get('cause_error') != errors[0]['id']:
        raise AssertionError('sdk_attempt_history_changed')
    report = client.flush(2)
    if report.receipts or report.acknowledged_batch_ids or not report.pending:
        raise AssertionError('exporter_was_not_interrupted')
    print(json.dumps({'run': run, 'failed_attempt': events[0]['attempt_id'], 'error': errors[0]['id'], 'pending': report.pending}), flush=True)
    os._exit(137)


def resume(client):
    run = os.environ['SOUNDPOST_SDK_RUN']
    recovered, _ = events_of(client)
    if [e['state'] for e in recovered] != ['started', 'failed'] or any(e['run_id'] != run for e in recovered):
        raise AssertionError('spool_did_not_retain_the_first_attempt')
    with client.job_attempt('e2e.task', run, 2):
        pass
    events, errors = events_of(client)
    if [e['state'] for e in events] != ['started', 'failed', 'started', 'succeeded'] or len(errors) != 1:
        raise AssertionError('sdk_attempt_history_changed')
    report = client.flush(30)
    if report.pending or report.lost or not report.receipts:
        raise AssertionError('durable_delivery_incomplete')
    print(json.dumps({'run': run, 'failed_attempt': events[0]['attempt_id'], 'retry_attempt': events[2]['attempt_id'], 'error': errors[0]['id'], 'events': len(events), 'recovered': len(recovered)}))


def main():
    mode = sys.argv[1]
    client = init(load(os.environ['SOUNDPOST_SDK_CONFIG'], os.environ['SOUNDPOST_SDK_JOB'], os.environ['SOUNDPOST_SDK_SPOOL']))
    try:
        {'crash': crash, 'resume': resume}[mode](client)
    finally:
        if mode == 'resume':
            client.close()


if __name__ == '__main__':
    try:
        main()
    except BaseException as e:
        raise SystemExit('sdk_job_interrupted_failed: ' + type(e).__name__ + ': ' + str(e)[:200]) from None
