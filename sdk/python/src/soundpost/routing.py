# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
import hashlib
import json
import struct
import re
from .policy import canonical, canonical_id, decimal, utf8_size
from .types import RoutingDescriptor, Resource
KINDS=('metric','log','span','error','job_attempt','replay_chunk','profile_chunk','capability','loss','condition')
def native_canonical(value):return canonical(value).replace('\u2028'.encode(),b'\\u2028').replace('\u2029'.encode(),b'\\u2029')
def validate_descriptor(d):
    if type(d) is not RoutingDescriptor or d.version!=1 or d.routing_version!=1 or d.slots!=64:raise ValueError('invalid routing descriptor')
    for value in (d.org,d.project,d.source):canonical_id(value)
    decimal(d.policy_revision)
    return d
def labels_valid(labels):
    if type(labels) is not list:raise ValueError('labels required')
    last=None
    for label in labels:
        if type(label) is not dict or set(label)!= {'name','value'} or type(label['name']) is not str or not utf8_size(label['name']) or type(label['value']) is not str:raise ValueError('invalid labels')
        name=label['name'];utf8_size(label['value'])
        if last is not None and last>=name:raise ValueError('invalid labels')
        last=name

def resource_wire(r,build):
    if type(r) is not Resource:raise ValueError('resource required')
    for value in (r.service_id,r.environment_id,r.build_id):canonical_id(value)
    if r.build_id!=build or type(r.instance_pseudonym) is not str or re.fullmatch('[a-zA-Z0-9_.:/<>+ $-]{1,256}',r.instance_pseudonym) is None:raise ValueError('invalid resource')
    labels=[{'name':name,'value':value} for name,value in r.labels];labels_valid(labels)
    return dict(service_id=r.service_id,environment_id=r.environment_id,build_id=r.build_id,instance_pseudonym=r.instance_pseudonym,labels=labels)

def owner_key(record,descriptor,producer):
    if type(record) is str:record=json.loads(record)
    kind=record['kind'];payload=record['payload']
    if kind=='metric':
        labels_valid(payload['labels'])
        if type(payload['name']) is not str or not utf8_size(payload['name']):raise ValueError('invalid metric name')
        return native_canonical({'name':payload['name'],'labels':payload['labels']})
    if kind=='log':labels_valid(payload['stream_labels']);return native_canonical(payload['stream_labels'])
    key={'span':'trace_id','error':'occurrence_id','job_attempt':'run_id','replay_chunk':'replay_id','profile_chunk':'profile_id','condition':'condition_id'}.get(kind)
    if key:return canonical_id(payload[key]).encode()
    if kind in ('capability','loss'):return (canonical_id(descriptor.source)+canonical_id(producer)+kind).encode()
    raise ValueError('invalid signal')

def route_record(record,descriptor,producer):
    if type(record) is str:record=json.loads(record)
    validate_descriptor(descriptor);canonical_id(producer)
    parts=[descriptor.org.encode(),descriptor.project.encode(),record['kind'].encode(),owner_key(record,descriptor,producer)]
    digest=hashlib.sha256(b''.join(struct.pack('>I',len(p))+p for p in parts)).digest()
    return int.from_bytes(digest[:8],'big')%64
