# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
"""Consume parent-provisioned *real Go* source config, signed policy and CA.
Never bootstraps a mock backend or disables certificate verification.
"""
import argparse
import base64
import json
from dataclasses import replace
from pathlib import Path
from soundpost import Config,Resource,RoutingDescriptor,SignedPolicy,Template,init
from soundpost.transport import HttpsReceiptTransport,Outcome
from soundpost.policy import resolve
from soundpost.queue import DeliveryQueue
parser=argparse.ArgumentParser();parser.add_argument('--config',required=True);parser.add_argument('--lost-response',action='store_true');parser.add_argument('--native-loss',action='store_true');args=parser.parse_args()
data=json.loads(Path(args.config).read_text(encoding='utf-8'))
resource=data['resource'];resource=Resource(resource['service_id'],resource['environment_id'],resource['build_id'],resource['instance_pseudonym'],tuple((l['name'],l['value']) for l in resource.get('labels',[])))
keys={name:base64.urlsafe_b64decode(value+'='*(-len(value)%4)) for name,value in data['trusted_keys'].items()}
config=Config(org=data['org'],project=data['project'],source=data['source'],endpoint=data['endpoint'],credential=data['credential'],build=data['build'],resource=resource,descriptor=RoutingDescriptor(**data['descriptor']),policy=SignedPolicy(**data['policy']),trusted_keys=keys,ca_file=data['ca_file'],templates=tuple(Template(t['id'],t['revision'],t['line'],tuple((key,tuple(values)) for key,values in t['fields'].items()),t['severity']) for t in data.get('templates',[])))
real=HttpsReceiptTransport(config)
class LostObservation:
    def __init__(self):self.lost=False;self.sends=0;self.lookups=0
    def send(self,batch,deadline):
        self.sends+=1;out=real.send(batch,deadline)
        if args.lost_response and not self.lost and out.kind=='receipt':self.lost=True;return Outcome('ambiguous')
        return out
    def lookup(self,batch,deadline):self.lookups+=1;return real.lookup(batch,deadline)
    def close(self):real.close()
transport=LostObservation()
if args.native_loss:
    assert resolve(config).decision.loss
    queue=DeliveryQueue(config,transport)
    try:
        import time
        assert queue.record_signal_loss('span','policy',9007199254740993,str(time.time_ns()))
        report=queue.flush()
        if report.pending:report=queue.flush()
        counters=queue.signal_loss_counters()
        assert report.pending==0 and report.lost==0 and transport.sends==1 and counters[0]['observed_count']=='9007199254740993' and counters[0]['acknowledged_count']=='9007199254740993'
        if args.lost_response:assert transport.lookups==1 and report.receipts[0].get('historical') is True
        print(json.dumps(dict(runtime='python',real_go_backend=True,tls_verification=True,native_loss=True,receipts=report.receipts,pending=report.pending,lost=report.lost,counters=counters,sends=transport.sends,lookups=transport.lookups)))
    finally:queue.close()
else:
    client=init(replace(config,transport=transport))
    try:
        event=client.capture_exception(ValueError('NEVER_EXPORT_BACKEND_CANARY'))
        report=client.flush()
        if report.pending:report=client.flush()
        assert report.pending==0 and report.lost==0 and len(report.receipts)==1
        assert transport.sends==1
        if args.lost_response:assert transport.lookups==1 and report.receipts[0].get('historical') is True
        print(json.dumps(dict(runtime='python',real_go_backend=True,tls_verification=True,event_id=event,acknowledged_batch_ids=report.acknowledged_batch_ids,acknowledged_cursors=report.acknowledged_cursors,receipts=report.receipts,pending=report.pending,lost=report.lost,sends=transport.sends,lookups=transport.lookups)))
    finally:client.close()
