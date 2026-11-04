# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
"""Real HTTP→HTTP+PostgreSQL smoke with authenticated admitted-record checks."""
import argparse
import asyncio
import base64
import http.client
import json
import os
from pathlib import Path
import socket
import ssl
import time
from urllib.parse import urlsplit
from soundpost import Config, Resource, RoutingDescriptor, SignedPolicy, init
from api import application
from dependency import Dependency
from contextlib import contextmanager
import sys

_STAGES=frozenset(('config','policy','http_pg','sampling','snapshot','flush','verify_http','verify_records','close'))
_ASSERTIONS=frozenset(('asgi_listener_not_ready','application_result_changed','missing_real_dependency_propagation','admitted_records_missing','critical_path_record_counts','causal_edges_missing','trace_isolation_failure','concurrent_children_not_overlapping','database_or_cancel_span_missing','invalid_same_domain_duration','native_sampling_loss_missing','native_sampling_loss_invalid','native_sampling_loss_clock','privacy_canary_exported','verifier_read_failed','partial_verifier_result','minimum_receipt_not_visible','real_signed_trace_permission_required','real_signed_loss_permission_required','durable_delivery_not_complete'))
_CODES=_ASSERTIONS|frozenset(('unexpected_failure','assertion_failed','missing_private_setting','invalid_configuration','invalid_response_shape','dependency_unavailable','network_timeout','tls_failure','network_failure'))
_DIAGNOSTIC_COUNTS=frozenset(('unauthorized','terminal_rejected','policy_expired','policy_changed','invalid_clock','invalid_span','policy_disabled','trace_sampled_out','span_clock_unavailable','exporter_recursion','queue_full','queue_pressure','queue_expired','record_too_large','spool_failed','closed','native_loss_unavailable','invalid_signal_loss','native_loss_unbuffered','native_loss_overflow','native_loss_expired','native_loss_policy','native_loss_recovery_pending'))

class FixtureFailure(Exception):
    def __init__(self,stage,code,details=None):
        self.stage=stage if type(stage) is str and stage in _STAGES else 'config'
        self.code=code if type(code) is str and code in _CODES else 'unexpected_failure'
        self.details=details if type(details) is dict else None
        super().__init__()

def failure_code(error):
    # Never call str/repr, arbitrary attributes, or serialize exception args.
    if type(error) is AssertionError:
        values=BaseException.args.__get__(error)
        return values[0] if len(values)==1 and type(values[0]) is str and values[0] in _ASSERTIONS else 'assertion_failed'
    return {KeyError:'missing_private_setting',ValueError:'invalid_configuration',TypeError:'invalid_response_shape',TimeoutError:'network_timeout',ssl.SSLError:'tls_failure',ConnectionError:'network_failure',ModuleNotFoundError:'dependency_unavailable'}.get(type(error),'unexpected_failure')

@contextmanager
def failure_stage(stage):
    try:yield
    except FixtureFailure:raise
    except Exception as error:
        raise FixtureFailure(stage,failure_code(error)) from None

def failure_diagnostic(error):
    if type(error) is FixtureFailure:
        result={'fixture':'python_real_http_postgres','status':'failed','stage':error.stage,'code':error.code}
        if error.stage=='flush' and error.code=='durable_delivery_not_complete' and error.details is not None:
            result['delivery']=safe_delivery_details(error.details)
        return result
    return {'fixture':'python_real_http_postgres','status':'failed','stage':'config','code':'unexpected_failure'}

def safe_delivery_details(raw):
    if type(raw) is not dict:return {}
    result={}
    for key,value in dict.items(raw):
        if type(key) is not str:continue
        if key in ('pending','lost','acknowledged_batch_count') and type(value) is int and 0<=value<=18446744073709551615:result[key]=value
        elif key=='deadline_exceeded' and type(value) is bool:result[key]=value
        elif key=='diagnostics' and type(value) is dict:
            result[key]={name:count for name,count in dict.items(value) if type(name) is str and name in _DIAGNOSTIC_COUNTS and type(count) is int and 0<=count<=18446744073709551615}
    return result

def delivery_failure(report,diagnostics):
    from soundpost.types import FlushReport
    if type(report) is not FlushReport:return FixtureFailure('flush','durable_delivery_not_complete')
    details={'pending':report.pending,'lost':report.lost,'deadline_exceeded':report.deadline_exceeded,'acknowledged_batch_count':len(report.acknowledged_batch_ids),'diagnostics':diagnostics}
    return FixtureFailure('flush','durable_delivery_not_complete',safe_delivery_details(details))

def load_config(path, endpoint):
    data = json.loads(Path(path).read_text(encoding='utf-8'))
    resource = data['resource']
    keys = {name:base64.urlsafe_b64decode(value+'='*(-len(value)%4)) for name,value in data['trusted_keys'].items()}
    return Config(org=data['org'], project=data['project'], source=data['source'], endpoint=endpoint, credential=data['credential'], build=data['build'], resource=Resource(resource['service_id'],resource['environment_id'],resource['build_id'],resource['instance_pseudonym'],tuple((label['name'],label['value']) for label in resource.get('labels',[]))), descriptor=RoutingDescriptor(**data['descriptor']), policy=SignedPolicy(**data['policy']), trusted_keys=keys, ca_file=data.get('ca_file'), operations=('request','http.call','db.execute'), dependencies=('dependency','postgres'), origins=('dependency',))

async def exercise(client, dsn):
    import httpx
    import psycopg
    import uvicorn
    with Dependency() as dependency:
        async with httpx.AsyncClient() as http:
            async with await psycopg.AsyncConnection.connect(dsn, autocommit=True) as database:
                listener = socket.socket()
                listener.bind(('127.0.0.1',0)); listener.listen()
                server = uvicorn.Server(uvicorn.Config(application(client,http,database,dependency.url),lifespan='off',log_level='critical'))
                task = asyncio.create_task(server.serve(sockets=[listener]))
                try:
                    for _ in range(500):
                        if server.started: break
                        await asyncio.sleep(.01)
                    if not server.started: raise AssertionError('asgi_listener_not_ready')
                    response = await http.get(f'http://127.0.0.1:{listener.getsockname()[1]}/PRIVATE_PATH')
                    if response.status_code != 200 or response.content != b'ok': raise AssertionError('application_result_changed')
                finally:
                    server.should_exit=True
                    await asyncio.wait_for(task,10)
                    listener.close()
        if len(dependency.server.parents)!=2 or not all(dependency.server.parents): raise AssertionError('missing_real_dependency_propagation')

def verify_records(records, expected_ids, trace_ids, dsn, expected_source):
    selected = [record for record in records if record.get('id') in expected_ids]
    if {record['id'] for record in selected} != expected_ids: raise AssertionError('admitted_records_missing')
    spans = [record['payload'] for record in selected if record['kind']=='span']
    errors = [record for record in selected if record['kind']=='error']
    if len(spans)!=6 or len(errors)!=1: raise AssertionError('critical_path_record_counts')
    root = next(span for span in spans if span['span_kind']=='server')
    children = [span for span in spans if span['parent_id']==root['span_id']]
    if len(children)!=5 or len({span['span_id'] for span in spans})!=6: raise AssertionError('causal_edges_missing')
    if {span['trace_id'] for span in spans}!=trace_ids: raise AssertionError('trace_isolation_failure')
    calls = [span for span in spans if span['operation']=='http.call' and span['status']=='ok']
    if len(calls)!=2 or max(int(span['start']['mono_ns']) for span in calls)>min(int(span['end']['mono_ns']) for span in calls): raise AssertionError('concurrent_children_not_overlapping')
    if sum(span['dependency_alias']=='postgres' for span in spans)!=2 or sum(span['status']=='cancelled' for span in spans)!=1: raise AssertionError('database_or_cancel_span_missing')
    for span in spans:
        if span['end'] is None or span['start']['domain']!=span['end']['domain'] or int(span['end']['mono_ns'])<int(span['start']['mono_ns']): raise AssertionError('invalid_same_domain_duration')
    from soundpost.context import valid_id
    losses=[record['payload'] for record in records if record['kind']=='loss']
    if len(losses)!=1: raise AssertionError('native_sampling_loss_missing')
    loss=losses[0]
    if loss['signal']!='span' or loss['reason']!='policy' or loss['count']!='1' or loss['source']!=expected_source or not valid_id(loss['producer'],32) or not valid_id(loss['producer_epoch'],32): raise AssertionError('native_sampling_loss_invalid')
    if int(loss['end_ns'])<int(loss['start_ns']): raise AssertionError('native_sampling_loss_clock')
    raw=json.dumps(records)
    if any(value in raw for value in ('PRIVATE_',dsn,'SELECT','division by zero')): raise AssertionError('privacy_canary_exported')

def verify_http(config, report, expected, start, end):
    endpoint=os.environ['SOUNDPOST_FIXTURE_VERIFY']
    reader=os.environ['SOUNDPOST_FIXTURE_READ_CREDENTIAL']
    parsed=urlsplit(endpoint)
    if parsed.scheme!='https' or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment: raise ValueError('invalid_verifier_endpoint')
    body={'org_id':config.org,'project_id':config.project,'batch_ids':list(report.acknowledged_batch_ids),'minimum_receipts':[{'batch_id':receipt['batch_id'],'cursor':receipt['cursor']} for receipt in report.receipts],'trace_ids':sorted({record['payload']['trace_id'] for record in expected if record['kind']=='span'}),'start_ns':str(start),'end_ns':str(end)}
    connection=http.client.HTTPSConnection(parsed.hostname,parsed.port or 443,timeout=10,context=ssl.create_default_context(cafile=config.ca_file))
    try:
        connection.request('POST',parsed.path or '/',body=json.dumps(body).encode(),headers={'Authorization':'Bearer '+reader,'Content-Type':'application/json'})
        response=connection.getresponse()
        raw=response.read(4*1024*1024+1)
        if response.status!=200 or len(raw)>4*1024*1024: raise AssertionError('verifier_read_failed')
        result=json.loads(raw)
    finally: connection.close()
    if result['partial'] is not False: raise AssertionError('partial_verifier_result')
    watermarks={value['group']:int(value['index']) for value in result['watermarks']}
    for receipt in report.receipts:
        cursor=receipt['cursor']
        if watermarks.get(cursor['group'],-1)<int(cursor['index']): raise AssertionError('minimum_receipt_not_visible')
    return result['records'],set(body['trace_ids'])

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--dsn-env',default='SOUNDPOST_FIXTURE_PG_DSN')
    parser.add_argument('--ingest-env',default='SOUNDPOST_FIXTURE_INGEST')
    parser.add_argument('--config-env',default='SOUNDPOST_FIXTURE_CONFIG')
    args=parser.parse_args()
    with failure_stage('config'):
        config=load_config(os.environ[args.config_env],os.environ[args.ingest_env])
        client=init(config)
    try:
        with failure_stage('policy'):
            if not client.policy_decision.traces: raise AssertionError('real_signed_trace_permission_required')
            if not client.policy_decision.loss: raise AssertionError('real_signed_loss_permission_required')
        start=time.time_ns()
        with failure_stage('http_pg'):
            with asyncio.Runner(loop_factory=asyncio.SelectorEventLoop if os.name=='nt' else None) as runner:
                runner.run(exercise(client,os.environ[args.dsn_env]))
        with failure_stage('sampling'):
            from soundpost.context import TraceContext
            with client._trace_context.bind(TraceContext('c'*32,'d'*16,False,0.0)):
                with client.span('request'):pass
        end=time.time_ns()
        with failure_stage('snapshot'):
            expected=[json.loads(record) for record in client.buffered_records()]
            expected=[record for record in expected if record['kind'] in ('span','error')]
        with failure_stage('flush'):
            report=client.flush(10)
            if report.pending or report.lost or not report.receipts: raise delivery_failure(report,client.diagnostics())
        with failure_stage('verify_http'):
            records,trace_ids=verify_http(config,report,expected,start,end)
        with failure_stage('verify_records'):
            verify_records(records,{record['id'] for record in expected},trace_ids,os.environ[args.dsn_env],config.source)
        print(json.dumps({'fixture':'python_real_http_postgres','admitted_records_verified':True,'native_sampling_loss_verified':True,'tls_verified':True,'records':len(records),'batches':len(report.receipts)}))
    finally:
        primary_failure=sys.exc_info()[0] is not None
        try:
            with failure_stage('close'):client.close()
        except FixtureFailure:
            if not primary_failure:raise

if __name__=='__main__':
    try: main()
    except Exception as error:
        print(json.dumps(failure_diagnostic(error)),file=sys.stderr)
        raise SystemExit(1) from None
