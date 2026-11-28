# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
"""Drives the real Python SDK's profile supplement against the live product: one bounded python_wall_samples profile of a named hot loop (and a
thread that sleeps), stopped, handed to the client's own delivery and flushed over its own HTTPS transport (durable receipts required).
Configuration: SOUNDPOST_SDK_CONFIG (the file web/e2e/support/real.ts sdkConfig writes). Prints one JSON line."""
import base64
import json
import os
import threading
import time
from pathlib import Path
from soundpost import Config, Resource, RoutingDescriptor, SignedPolicy, init
from soundpost.profile import ProfileOptions, start_profile

ROOT = str(Path(__file__).resolve().parent)


def load(path):
    data = json.loads(Path(path).read_text(encoding='utf-8'))
    resource = data['resource']
    keys = {name: base64.urlsafe_b64decode(value + '=' * (-len(value) % 4)) for name, value in data['trusted_keys'].items()}
    return Config(org=data['org'], project=data['project'], source=data['source'], endpoint=data['endpoint'], credential=data['credential'], build=data['build'],
                  resource=Resource(resource['service_id'], resource['environment_id'], resource['build_id'], resource['instance_pseudonym'], ()),
                  descriptor=RoutingDescriptor(**data['descriptor']), policy=SignedPolicy(**data['policy']), trusted_keys=keys, ca_file=data.get('ca_file'),
                  project_root=ROOT, deployment_profiles=True)


def e2e_hot_loop(seconds):
    end = time.perf_counter() + seconds
    total = 0
    while time.perf_counter() < end:
        for i in range(2000):
            total += i * i
    return total


def e2e_sleeper(seconds):
    time.sleep(seconds)


def main():
    client = init(load(os.environ['SOUNDPOST_SDK_CONFIG']))
    try:
        if not client.policy_decision.profiles:
            raise AssertionError('signed_profile_permission_required')
        # The lease hands its wire records to the client's own capture path and flushes them itself when it stops; the spy only observes what it hands over.
        handed = []
        capture = client._capture_profile
        client._capture_profile = lambda capability, chunks: (handed.append((capability, chunks)), capture(capability, chunks))[1]
        lease = start_profile(ProfileOptions(method='python_wall_samples', duration_s=30, interval_ms=2, project_root=ROOT), client)
        if not lease.active or lease.capability['status'] != 'supported':
            raise AssertionError('profile_did_not_start: ' + str(lease.capability))
        sleeper = threading.Thread(target=e2e_sleeper, args=(0.6,))
        sleeper.start()
        e2e_hot_loop(0.6)
        sleeper.join()
        report = lease.stop()
        if report['sample_count'] < 20:
            raise AssertionError('too_few_samples: %d' % report['sample_count'])
        if report['ack']['status'] != 'obtained' or len(handed) != 1 or not handed[0][1]:
            raise AssertionError('sdk_did_not_deliver_profile: ' + json.dumps(report['ack']))
        capability, chunks = handed[0]
        flushed = client.flush(30)
        if flushed.pending or flushed.lost:
            raise AssertionError('durable_delivery_incomplete')
        print(json.dumps({'profile': chunks[0]['payload']['profile_id'], 'samples': report['sample_count'], 'chunks': len(chunks), 'method': capability['payload']['method'], 'units': chunks[0]['payload']['units']}))
    finally:
        client.close()


if __name__ == '__main__':
    try:
        main()
    except BaseException as e:
        raise SystemExit('sdk_profile_failed: ' + type(e).__name__ + ': ' + str(e)[:300]) from None
