# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
"""Drives the real Python SDK's job API against the live product: one run whose first attempt raises (a failed attempt with a captured
error as its cause) and whose retry succeeds. Everything is delivered by the SDK's own HTTPS transport and verified by durable receipts.
Configuration: SOUNDPOST_SDK_CONFIG (the file web/e2e/support/real.ts sdkConfig writes), SOUNDPOST_SDK_JOB (the job ID). Prints one JSON line."""
import base64
import json
import os
import secrets
import sys
from pathlib import Path
from soundpost import Config, Resource, RoutingDescriptor, SignedPolicy, init


def load(path, job):
    data = json.loads(Path(path).read_text(encoding='utf-8'))
    resource = data['resource']
    keys = {name: base64.urlsafe_b64decode(value + '=' * (-len(value) % 4)) for name, value in data['trusted_keys'].items()}
    return Config(org=data['org'], project=data['project'], source=data['source'], endpoint=data['endpoint'], credential=data['credential'], build=data['build'],
                  resource=Resource(resource['service_id'], resource['environment_id'], resource['build_id'], resource['instance_pseudonym'], ()),
                  descriptor=RoutingDescriptor(**data['descriptor']), policy=SignedPolicy(**data['policy']), trusted_keys=keys, ca_file=data.get('ca_file'),
                  job_registry=(('e2e.task', job),))


def main():
    client = init(load(os.environ['SOUNDPOST_SDK_CONFIG'], os.environ['SOUNDPOST_SDK_JOB']))
    try:
        if not (client.policy_decision.jobs and client.policy_decision.errors):
            raise AssertionError('signed_job_and_error_permissions_required')
        run = secrets.token_hex(16)
        try:
            with client.job_attempt('e2e.task', run, 1):
                raise ValueError('e2e task failed')
        except ValueError:
            pass
        with client.job_attempt('e2e.task', run, 2):
            pass
        records = [json.loads(value) for value in client.buffered_records()]
        events = [r['payload'] for r in records if r['kind'] == 'job_attempt']
        errors = [r for r in records if r['kind'] == 'error']
        if [e['state'] for e in events] != ['started', 'failed', 'started', 'succeeded'] or len(errors) != 1 or events[1].get('cause_error') != errors[0]['id']:
            raise AssertionError('sdk_attempt_history_changed')
        report = client.flush(20)
        if report.pending or report.lost or not report.receipts:
            raise AssertionError('durable_delivery_incomplete')
        print(json.dumps({'run': run, 'failed_attempt': events[0]['attempt_id'], 'retry_attempt': events[2]['attempt_id'], 'error': errors[0]['id'], 'events': len(events)}))
    finally:
        client.close()


if __name__ == '__main__':
    try:
        main()
    except BaseException as e:
        raise SystemExit('sdk_job_retry_failed: ' + type(e).__name__ + ': ' + str(e)[:200]) from None
