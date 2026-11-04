# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
import json
import re
from .policy import canonical_id,decimal,unix_nano,pairs,utf8_size
from .routing import labels_valid
SCHEMAS={
 'metric':('name labels sample_kind unit type','value histogram start_timestamp_ns exemplar_trace exemplar_span'),
 'log':('severity template_id template_revision fields line stream_labels structured_metadata source_class','timestamp_ns trace_id span_id run_id'),
 'error':('occurrence_id exception_class mechanism frames code build_id handled fatal','exception_graph template_id release_id trace_id span_id replay_id profile_id run_id'),
 'span':('trace_id span_id parent_id span_kind operation start end status dependency_alias links sample_probability sample_decision','job_id replay_id profile_id'),
 'job_attempt':('job_id run_id attempt_id schedule_occurrence ordinal producer_epoch sequence state observed_ns terminal_ns','cause_trace cause_error'),
 'replay_chunk':('replay_id session_id recorder_version sequence previous_hash checkpoint_sequence checkpoint_hash clock nodes events loss gap capture_policy_revision',''),
 'profile_chunk':('profile_id process_id capability_id method units start_ns end_ns clock frames stacks samples intervals loss truncated','native_domain native_capabilities native_loss policy_revision sequence complete'),
 'capability':('runtime version build os arch signal method status reason coverage clock_domain expires_ns',''),
 'loss':('source producer producer_epoch start_ns end_ns signal reason count last_ack queue_bytes queue_records',''),
 'condition':('condition_id epoch sequence event_ns status severity labels links','')}
def fields(value,required,optional=''):
    required=set(required.split());allowed=required|set(optional.split())
    if type(value) is not dict or not required<=value.keys() or value.keys()-allowed:raise ValueError('closed native fields required')
    for key in optional.split():
        if value.get(key) is None or type(value.get(key)) is list and not value[key]:value.pop(key,None)
    return value
def _array(value):
    if type(value) is not list:raise ValueError('native array required')
    return value
def _text(value):
    if type(value) is not str:raise ValueError('native string required')
    utf8_size(value);return value
def _integer(value,minimum=0,maximum=4294967295):
    if type(value) is not int or not minimum<=value<=maximum:raise ValueError('invalid native integer')
def _bits(value,length=16):
    if type(value) is not str or len(value)!=length or re.fullmatch('[0-9a-f]+',value) is None:raise ValueError('invalid native bits')
def _domain(value):
    for value in fields(value,'host boot runtime').values():canonical_id(value)
def _clock(value):
    c=fields(value,'wall_ns mono_ns domain uncertainty_ns');unix_nano(c['wall_ns']);decimal(c['mono_ns']);decimal(c['uncertainty_ns']);_domain(c['domain'])
NATIVE_FRAME_REASONS=frozenset(('frame_unresolved','missing_frame_pointer_or_callchain','callchain_truncated','build_not_approved','deleted_executable','generation_changed','jit_or_anonymous_map_unavailable','jit_map_expired','artifact_unavailable','artifact_denied','invalid_elf_artifact'))
NATIVE_PROFILE_REASONS=frozenset(('platform_unsupported','permission_denied','tracefs_unavailable','event_unavailable','coverage_unmeasured','acquisition_pending','callchain_truncated','records_lost','generation_changed','clock_uncertain','frame_unresolved','missing_switch_callchain','missing_callchain','throttled','unthrottled','samples_lost'))
def _native_task(value,boot):
    task=fields(value,'boot_id pid_namespace tgid tid process_start_ns generation')
    if task['boot_id']!=boot:raise ValueError('native task boot mismatch')
    _integer(task['tgid'],1);_integer(task['tid'],1)
    if any(decimal(task[k])=='0' for k in ('pid_namespace','process_start_ns','generation')):raise ValueError('invalid native task')
    return task['tid']
def _native_profile(p,revision):
    for key in ('policy_revision','sequence'):
        if key in p and decimal(p[key])=='0':del p[key]
    if 'complete' in p and type(p['complete']) is not bool:raise ValueError('invalid native completeness')
    if p.get('complete') is False:del p['complete']
    for interval in p['intervals']:
        for key in ('unit','reason'):
            if interval.get(key)=='':del interval[key]
        if interval.get('correction') is False:del interval['correction']
        if 'correction' in interval:raise ValueError('native corrections cannot persist')
    if 'native_domain' not in p:
        if any(key in p for key in ('policy_revision','sequence','complete','native_capabilities','native_loss')) or any('native' in s for s in p['samples']) or any(any(k in i for k in ('native_task','unit','reason')) for i in p['intervals']):raise ValueError('native metadata requires native domain')
        return
    d=fields(p['native_domain'],'host_id boot_id')
    if any(re.fullmatch('[a-zA-Z0-9-]{1,128}',_text(v)) is None for v in d.values()):raise ValueError('invalid native domain')
    if decimal(p.get('policy_revision'))=='0' or p['policy_revision']!=revision or decimal(p.get('sequence'))=='0' or p['method'] not in ('native_cpu','native_offcpu') or p['units']!=('samples' if p['method']=='native_cpu' else 'nanoseconds') or p['method']=='native_offcpu' and p['samples']:raise ValueError('invalid native profile')
    capabilities=[canonical_id(v) for v in _array(p.get('native_capabilities'))]
    if len(capabilities)!=3 or len(set(capabilities))!=3 or p['capability_id'] not in capabilities:raise ValueError('invalid native capability references')
    losses=_array(p.get('native_loss',[]));genuine_loss=0
    if len(losses)>256:raise ValueError('native loss bounds exceeded')
    for value in losses:
        loss=fields(value,'at_ns cpu count reason','throttle_event_id throttle_stream_id');decimal(loss['at_ns']);_integer(loss['cpu']);count=int(decimal(loss['count']))
        for key in ('throttle_event_id','throttle_stream_id'):
            if key in loss and decimal(loss[key])=='0':del loss[key]
        if loss['reason'] in ('records_lost','samples_lost'):
            if count==0 or 'throttle_event_id' in loss or 'throttle_stream_id' in loss:raise ValueError('invalid native loss')
        elif loss['reason'] in ('throttled','unthrottled'):
            if count!=0 or decimal(loss.get('throttle_event_id'))=='0' or decimal(loss.get('throttle_stream_id'))=='0':raise ValueError('invalid native throttle transition')
        else:raise ValueError('invalid native loss reason')
        genuine_loss+=count
        if genuine_loss>18446744073709551615:raise ValueError('native loss overflow')
    for f in p['frames']:
        module=f['module_id'];reason=f['reason']
        if not module:
            if f['offset']!='0' or f['function'] or f['artifact_id'] or reason not in NATIVE_FRAME_REASONS:raise ValueError('unsafe unresolved native frame')
        else:
            _bits(module,64)
            if f['function'] and re.fullmatch('[a-zA-Z0-9_.$@:]{1,256}',f['function']) is None:raise ValueError('invalid native symbol')
            if f['artifact_id']:canonical_id(f['artifact_id'])
            if reason and reason not in NATIVE_FRAME_REASONS:raise ValueError('invalid native frame reason')
    for sample in p['samples']:
        n=fields(sample.get('native'),'task method unit requested_hz period','truncation coverage throttle_reason throttle_event_id throttle_stream_id');tid=_native_task(n['task'],d['boot_id'])
        for key in ('truncation','coverage','throttle_reason'):
            if n.get(key)=='':del n[key]
        for key in ('throttle_event_id','throttle_stream_id'):
            if key in n and decimal(n[key])=='0':del n[key]
        if sample['count']!='1' or sample['thread']!=str(tid) or type(n['requested_hz']) is not int or n['requested_hz']!=99 or decimal(n['period'])=='0' or n['method'] not in ('software_cpu_clock','hardware_cycles') or n['unit']!=('cpu_clock_nanoseconds' if n['method']=='software_cpu_clock' else 'hardware_cycles'):raise ValueError('invalid native CPU sample')
        if 'truncation' in n and n['truncation'] not in ('callchain_truncated','frame_unresolved','missing_callchain') or 'coverage' in n and n['coverage'] not in NATIVE_FRAME_REASONS:raise ValueError('invalid native sample coverage')
        if 'throttle_reason' not in n:
            if 'throttle_event_id' in n or 'throttle_stream_id' in n:raise ValueError('invalid native throttle identity')
        elif n['throttle_reason'] not in ('throttled','unthrottled') or decimal(n.get('throttle_event_id'))=='0' or decimal(n.get('throttle_stream_id'))=='0':raise ValueError('invalid native throttle')
    for i in p['intervals']:
        tid=_native_task(i.get('native_task'),d['boot_id'])
        if i['thread']!=str(tid) or i.get('unit')!='nanoseconds' or 'reason' in i and i['reason'] not in NATIVE_PROFILE_REASONS or i['kind']=='unknown_offcpu' and 'reason' not in i or i['censored'] and 'reason' not in i:raise ValueError('invalid native interval')
def _structures(kind,p,revision):
    strings={'metric':'name sample_kind unit type','log':'severity template_id line source_class','span':'span_kind operation status dependency_alias sample_decision','error':'exception_class mechanism','job_attempt':'schedule_occurrence state','replay_chunk':'recorder_version','profile_chunk':'method units','capability':'runtime version build os arch signal method status reason','loss':'signal reason','condition':'status severity'}
    for key in strings.get(kind,'').split():_text(p[key])
    if kind=='error':
        if p['code'] is not None:_text(p['code'])
        if 'template_id' in p:_text(p['template_id'])
    if kind=='log' and 'timestamp_ns' in p:unix_nano(p['timestamp_ns'])
    ids={'metric':'exemplar_trace','log':'trace_id run_id','span':'trace_id job_id replay_id profile_id','error':'occurrence_id build_id release_id trace_id replay_id profile_id run_id','job_attempt':'job_id run_id attempt_id producer_epoch cause_trace cause_error','replay_chunk':'replay_id session_id','profile_chunk':'profile_id process_id capability_id','loss':'source producer producer_epoch','condition':'condition_id epoch'}
    for key in ids.get(kind,'').split():
        if key in p:canonical_id(p[key])
    for key in ('span_id','exemplar_span'):
        if key in p:
            _bits(p[key])
            if p[key]=='0'*16:raise ValueError('invalid span ID')
    if kind=='metric':
        labels_valid(p['labels'])
        if 'value' in p:_bits(p['value'])
        if 'start_timestamp_ns' in p:unix_nano(p['start_timestamp_ns'])
        if 'histogram' in p:
            h=fields(p['histogram'],'','integer float')
            for tag in ('integer','float'):
                if tag not in h:continue
                v=fields(h[tag],'flavor schema zero_threshold sum count zero_count positive_spans negative_spans positive_buckets negative_buckets reset_hint','positive_counts negative_counts custom_bounds' if tag=='integer' else 'custom_bounds')
                _integer(v['schema'],-2147483648,2147483647)
                if v['schema']!=-53 and not -4<=v['schema']<=8:raise ValueError('invalid histogram schema')
                _bits(v['zero_threshold']);_bits(v['sum'])
                if tag=='float':_bits(v['count']);_bits(v['zero_count'])
                for key in ('positive_spans','negative_spans'):
                    for item in _array(v[key]):
                        span=fields(item,'offset length');_integer(span['offset'],-2147483648,2147483647);_integer(span['length'])
                if tag=='float':
                    for key in ('positive_buckets','negative_buckets'):
                        for value in _array(v[key]):_bits(value)
                for value in _array(v.get('custom_bounds',[])):_bits(value)
    if kind=='log':labels_valid(p['stream_labels'])
    if kind=='span':
        _bits(p['span_id'])
        if p['parent_id'] is not None:_bits(p['parent_id'])
        _clock(p['start']);_bits(p['sample_probability'])
        if p['end'] is not None:_clock(p['end'])
        for item in _array(p['links']):
            link=fields(item,'trace_id span_id');canonical_id(link['trace_id']);_bits(link['span_id'])
    if kind=='job_attempt':
        decimal(p['ordinal']);decimal(p['sequence']);unix_nano(p['observed_ns'])
        if p['terminal_ns'] is not None:unix_nano(p['terminal_ns'])
    if kind=='replay_chunk':
        _clock(p['clock'])
        for key in ('sequence','checkpoint_sequence','loss','capture_policy_revision'):decimal(p[key])
        _bits(p['previous_hash'],64);_bits(p['checkpoint_hash'],64)
        if type(p['gap']) is not bool or len(_array(p['nodes']))>4096 or len(_array(p['events']))>4096:raise ValueError('invalid replay bounds')
        for item in p['nodes']:
            n=fields(item,'id parent tag class text');decimal(n['id']);decimal(n['parent'])
            if n['tag'] not in ('div','span','p','button','input','section','canvas','masked') or n['class'] not in ('','masked') or n['text'] not in ('','[masked]'):raise ValueError('unmasked replay node')
        for item in p['events']:
            e=fields(item,'at_ns kind node x y');decimal(e['at_ns']);decimal(e['node']);_integer(e['x'],-2147483648,2147483647);_integer(e['y'],-2147483648,2147483647)
            if e['kind'] not in ('pointer','scroll','resize','mutation','checkpoint','gap'):raise ValueError('invalid replay event')
    if kind=='profile_chunk':
        _clock(p['clock']);unix_nano(p['start_ns']);unix_nano(p['end_ns']);decimal(p['loss'])
        if type(p['truncated']) is not bool or len(_array(p['frames']))>4096 or len(_array(p['stacks']))>4096 or len(_array(p['samples']))>8192 or len(_array(p['intervals']))>8192:raise ValueError('invalid profile bounds')
        for item in p['frames']:
            f=fields(item,'module_id function artifact_id offset reason');decimal(f['offset'])
            for key in ('module_id','function','artifact_id','reason'):_text(f[key])
        for item in p['stacks']:
            s=fields(item,'frames')
            if len(_array(s['frames']))>128:raise ValueError('invalid stack')
            for value in s['frames']:_integer(value,0,len(p['frames'])-1)
        for item in p['samples']:
            s=fields(item,'at_ns stack count thread','native');decimal(s['at_ns']);decimal(s['count']);decimal(s['thread']);_integer(s['stack'],0,len(p['stacks'])-1)
        for item in p['intervals']:
            i=fields(item,'start_ns end_ns stack kind thread censored','native_task unit reason correction');decimal(i['start_ns']);decimal(i['end_ns']);decimal(i['thread']);_integer(i['stack'],0,len(p['stacks'])-1)
            if type(i['censored']) is not bool or i['kind'] not in ('blocked','runnable','unknown_offcpu'):raise ValueError('invalid profile interval')
        _native_profile(p,revision)
    if kind=='capability':
        _domain(p['clock_domain']);unix_nano(p['expires_ns'])
        if any(value not in ('complete','partial','none','unknown') for value in fields(p['coverage'],'frames threads workers tasks').values()):raise ValueError('invalid coverage')
    if kind=='loss':
        for key in ('count','queue_bytes','queue_records'):decimal(p[key])
        unix_nano(p['start_ns']);unix_nano(p['end_ns'])
        if p['last_ack'] is not None:
            c=fields(p['last_ack'],'group index');canonical_id(c['group']);decimal(c['index'])
    if kind=='condition':
        decimal(p['sequence']);unix_nano(p['event_ns']);labels_valid(p['labels'])
        for value in _array(p['links']):canonical_id(value)
def parse_safe_record(serialized):
    r=fields(json.loads(serialized,object_pairs_hook=pairs),'id kind observed_at_ns policy_revision payload');canonical_id(r['id']);unix_nano(r['observed_at_ns']);decimal(r['policy_revision'])
    kind=r['kind']
    if type(kind) is not str or kind not in SCHEMAS:raise ValueError('invalid signal')
    p=fields(r['payload'],*SCHEMAS[kind])
    _structures(kind,p,decimal(r['policy_revision']))
    if kind=='error':
        canonical_id(p['occurrence_id']);canonical_id(p['build_id'])
        if p['occurrence_id']!=r['id'] or type(p['handled']) is not bool or type(p['fatal']) is not bool or p['mechanism'] not in ('manual','uncaught_exception','unhandled_rejection','thread_exception','asyncio_exception'):raise ValueError('invalid error')
        def frame(value):
            f=fields(value,'module_id function artifact_id line column in_app async')
            if any(type(f[k]) is not str for k in ('module_id','function','artifact_id')) or type(f['line']) is not int or not 1<=f['line']<=4294967295 or f['column'] is not None and (type(f['column']) is not int or not 0<=f['column']<=4294967295) or type(f['in_app']) is not bool or type(f['async']) is not bool:raise ValueError('invalid frame')
        for f in _array(p['frames']):frame(f)
        if 'exception_graph' in p:
            g=fields(p['exception_graph'],'nodes edges reasons');nodes=_array(g['nodes']);edges=_array(g['edges']);reasons=_array(g['reasons']);total=0
            if not 1<=len(nodes)<=16 or len(edges)>272 or len(reasons)>16:raise ValueError('invalid graph')
            for index,node in enumerate(nodes):
                fields(node,'id exception_class frames context_suppressed')
                if type(node['id']) is not int or node['id']!=index or type(node['exception_class']) is not str or type(node['context_suppressed']) is not bool:raise ValueError('invalid graph')
                total+=len(_array(node['frames']))
                for f in node['frames']:frame(f)
            if total>128 or nodes[0]['exception_class']!=p['exception_class'] or nodes[0]['frames']!=p['frames']:raise ValueError('invalid graph root')
            for edge in edges:
                fields(edge,'from to kind','ordinal');_integer(edge['from'],0,len(nodes)-1);_integer(edge['to'],0,len(nodes)-1)
                if edge['kind'] not in ('cause','context','group'):raise ValueError('invalid edge')
                if edge['kind']=='group':_integer(edge.get('ordinal'),0,15)
                elif 'ordinal' in edge:raise ValueError('invalid edge ordinal')
            if any(reason not in ('cycle','node_limit','frame_limit','group_limit','unknown_throw','project_root_unconfigured','frame_not_project_safe','foreign_or_custom_error_class','safe_original_stack_unavailable','native_brand_unavailable','cause_accessor','group_accessor','safe_group_boundary_unavailable','unsafe_group_container') for reason in reasons):raise ValueError('invalid graph reason')
    if kind=='log':
        decimal(p['template_revision'])
        if any(type(p[k]) is not str for k in ('template_id','line','severity','source_class')):raise ValueError('invalid log')
        for mapping in (p['fields'],p['structured_metadata']):
            if type(mapping) is not dict or any(type(v) not in (str,int,bool,type(None)) for v in mapping.values()):raise ValueError('invalid log scalar')
    if kind=='metric' and 'histogram' in p:
        h=fields(p['histogram'],'','integer float')
        if ('integer' in h)==('float' in h):raise ValueError('invalid histogram')
        if 'integer' in h:
            v=fields(h['integer'],'flavor schema zero_threshold sum count zero_count positive_spans negative_spans positive_buckets negative_buckets reset_hint','positive_counts negative_counts custom_bounds');decimal(v['count']);decimal(v['zero_count'])
            for key in ('positive_counts','negative_counts'):
                for value in v.get(key,[]):decimal(value)
            for key in ('positive_buckets','negative_buckets'):
                for value in v[key]:unix_nano(value)
    return r
