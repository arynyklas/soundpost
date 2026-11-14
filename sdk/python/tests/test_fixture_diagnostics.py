# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
import importlib.util
import json
from pathlib import Path
import pytest

@pytest.fixture
def fixture_module(monkeypatch):
    root=Path(__file__).resolve().parents[3]/'fixtures'/'sdk'/'python'
    monkeypatch.syspath_prepend(str(root))
    spec=importlib.util.spec_from_file_location('soundpost_critical_diagnostics',root/'critical_path.py')
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def test_fixture_allowlisted_assertion_reports_stage_without_raw_values(fixture_module):
    fixture=fixture_module
    with pytest.raises(fixture.FixtureFailure) as raised:
        with fixture.failure_stage('verify_records'):
            raise AssertionError('critical_path_record_counts')
    assert fixture.failure_diagnostic(raised.value)=={'fixture':'python_real_http_postgres','status':'failed','stage':'verify_records','code':'critical_path_record_counts'}

def test_fixture_hostile_exception_never_formats_or_emits_message(fixture_module):
    fixture=fixture_module
    class Trap(Exception):
        def __str__(self):raise AssertionError('str called')
        def __repr__(self):raise AssertionError('repr called')
    with pytest.raises(fixture.FixtureFailure) as raised:
        with fixture.failure_stage('http_pg'):
            raise Trap('PRIVATE_DSN PRIVATE_URL PRIVATE_BODY PRIVATE_CREDENTIAL')
    result=fixture.failure_diagnostic(raised.value)
    assert result=={'fixture':'python_real_http_postgres','status':'failed','stage':'http_pg','code':'unexpected_failure'}
    assert 'PRIVATE_' not in json.dumps(result)
    assert fixture.failure_code(AssertionError('PRIVATE_QUERY'))=='assertion_failed'
    assert fixture.failure_code(KeyError('PRIVATE_CREDENTIAL'))=='missing_private_setting'
    assert fixture.failure_code(ValueError('PRIVATE_DSN'))=='invalid_configuration'

def test_fixture_rejects_unregistered_diagnostic_codes(fixture_module):
    fixture=fixture_module
    result=fixture.failure_diagnostic(fixture.FixtureFailure('PRIVATE_PATH','PRIVATE_BODY'))
    assert result=={'fixture':'python_real_http_postgres','status':'failed','stage':'config','code':'unexpected_failure'}

def test_flush_diagnostics_include_only_exact_approved_counts(fixture_module):
    from soundpost.types import FlushReport
    fixture=fixture_module
    report=FlushReport(('PRIVATE_BATCH',),('PRIVATE_CURSOR',),7,2,True,({'credential':'PRIVATE'},))
    failure=fixture.delivery_failure(report,{'terminal_rejected':2,'trace_sampled_out':1,'PRIVATE_URL':'PRIVATE_BODY','spool_failed':True,'queue_full':-1})
    assert fixture.failure_diagnostic(failure)=={'fixture':'python_real_http_postgres','status':'failed','stage':'flush','code':'durable_delivery_not_complete','delivery':{'pending':7,'lost':2,'deadline_exceeded':True,'acknowledged_batch_count':1,'diagnostics':{'terminal_rejected':2,'trace_sampled_out':1}}}
    assert 'PRIVATE' not in json.dumps(fixture.failure_diagnostic(failure))

def test_flush_diagnostic_details_drop_arbitrary_objects_without_rendering(fixture_module):
    fixture=fixture_module
    class Trap:
        def __str__(self):raise AssertionError('str called')
        def __repr__(self):raise AssertionError('repr called')
        def __int__(self):raise AssertionError('int called')
    raw={'pending':Trap(),'lost':True,'deadline_exceeded':Trap(),'receipts':{'PRIVATE':'PRIVATE'},'diagnostics':{'terminal_rejected':Trap(),'PRIVATE':Trap()}}
    assert fixture.safe_delivery_details(raw)=={'diagnostics':{}}
