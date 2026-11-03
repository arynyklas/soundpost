# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
import json
import pytest
import base64
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
KEY=Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
def b64(v): return base64.urlsafe_b64encode(v).rstrip(b"=").decode()
from soundpost import Config, SignedPolicy, Template, init

class Trap(Exception):
    def __str__(self): raise AssertionError("str called")
    def __repr__(self): raise AssertionError("repr called")

def config(project="p", **changes):
    payload=json.dumps(dict(version=1,org="org",source="s",project=project,revision="1",expires_ns="9999999999999999999",errors=True,logs=True,replay=True,bodies=True),sort_keys=True,separators=(",", ":")).encode()
    args=dict(org="org",project=project,source="s",endpoint="https://example.invalid/ingest/v1/batches",credential="SECRET",build="build",policy=SignedPolicy(1,"Ed25519","test",b64(payload),b64(KEY.sign(payload))),trusted_keys={"test":KEY.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)},templates=(Template("operation.failed","1","operation failed: {status}",(("status",(503,)),),"error"),),clock_ns=lambda:"9007199254740993")
    args.update(changes)
    return Config(**args)

def test_policy_precedes_queue():
    c=init(config())
    assert c.capture_log("unknown", {}) is None
    assert c.diagnostics()["unknown_template"]==1
    c.capture_exception(Trap("SECRET SQL https://x/?secret"))
    c.capture_log("operation.failed", {"status":503,"password":Trap()})
    data="".join(c.buffered_records())
    assert '9007199254740993' in data
    assert 'operation failed: 503' in data
    for bad in ('SECRET','password','SQL','?secret'): assert bad not in data
    assert not c.policy_decision.replay and not c.policy_decision.bodies

def test_immutable_and_independent():
    c=init(config()); d=init(config("other"))
    c.capture_log("operation.failed",{"status":503})
    before=c.buffered_records()
    c.register_template(Template("operation.failed","2","new: {status}",(("status",(503,)),),"error"))
    assert c.buffered_records()==before
    assert not d.buffered_records()
    c.capture_log("operation.failed",{"status":503})
    assert 'new: 503' in c.buffered_records()[1]

def test_invalid_expired_and_bounds():
    with pytest.raises(ValueError): init(config(trusted_keys={"test":bytes(32)}))
    with pytest.raises(ValueError): init(config(project="wrong",policy=config().policy))
    c=init(config(clock_ns=lambda:"99999999999999999999",max_records=1))
    assert c.capture_log("operation.failed",{"status":503}) is None
    assert c.diagnostics()["policy_expired"]==1
    c=init(config(max_records=1)); c.capture_exception(Trap()); c.capture_exception(Trap())
    assert len(c.buffered_records())==1 and c.diagnostics()["queue_full"]==1

def test_canonical_policy_and_source_binding():
    from dataclasses import replace
    c=config()
    valid=base64.urlsafe_b64decode(c.policy.payload+"="*(-len(c.policy.payload)%4)).decode()
    doc=json.loads(valid)
    unsorted=json.dumps(dict(reversed(list(doc.items()))),separators=(",",":"))
    for text in (valid.replace('"version":1','"version":1.0'),valid.replace('"version":1','"version":NaN'),valid.replace('"version":1','"version":1,"version":1'),unsorted):
        payload=text.encode()
        policy=SignedPolicy(1,"Ed25519","test",b64(payload),b64(KEY.sign(payload)))
        with pytest.raises(ValueError,match="invalid signed policy"):
            init(replace(c,policy=policy))
    with pytest.raises(ValueError):init(replace(c,source="other"))
    with pytest.raises(ValueError):init(replace(c,trusted_keys={}))
    with pytest.raises(ValueError):init(replace(c,policy=replace(c.policy,payload=c.policy.payload+"=")))
    with pytest.raises(ValueError):init(replace(c,policy=replace(c.policy,signature=c.policy.signature+"=")))
    with pytest.raises(ValueError):init(replace(c,policy=replace(c.policy,key_id="unknown")))
    signature=bytearray(base64.urlsafe_b64decode(c.policy.signature+"="*(-len(c.policy.signature)%4)))
    signature[0]^=1
    with pytest.raises(ValueError):init(replace(c,policy=replace(c.policy,signature=b64(signature))))

def test_closed_fields_and_close_destroy_pending():
    class HostileMap(dict):
        def get(self,*args):raise AssertionError("getter invoked")
        def __iter__(self):raise AssertionError("iterator invoked")
    c=init(config())
    assert c.capture_log("operation.failed",HostileMap(status=503)) is None
    assert c.diagnostics()["invalid_fields"]==1
    c.capture_exception(Trap())
    c.close()
    assert c.buffered_records()==() and c.diagnostics()["closed_pending"]==1
    c.capture_exception(Trap())
    assert c.diagnostics()["closed"]==1

def test_exact_native_snake_case_record_mirror():
    c=init(config())
    c.capture_exception(Trap())
    c.capture_log("operation.failed",{"status":503})
    error,log=map(json.loads,c.buffered_records())
    for record in (error,log):
        assert set(record)=={"id","kind","observed_at_ns","payload","policy_revision"}
    assert set(error["payload"])=={"build_id","code","exception_class","exception_graph","fatal","frames","handled","mechanism","occurrence_id"}
    assert set(log["payload"])=={"fields","line","severity","source_class","stream_labels","structured_metadata","template_id","template_revision"}

def test_bool_envelope_version_is_not_numeric_one():
    from dataclasses import replace
    c=config()
    with pytest.raises(ValueError,match="invalid signed policy"):
        init(replace(c,policy=replace(c.policy,version=True)))

def test_utf8_byte_boundaries_and_registered_severity():
    from dataclasses import replace
    c=init(config())
    value="😀"*64
    c.register_template(Template("unicode","1","😀"*1024,(("value",(value,)),),"info"))
    c.capture_log("unicode",{"value":value})
    record=json.loads(c.buffered_records()[0])
    assert record["payload"]["severity"]=="info"
    assert record["payload"]["line"]=="😀"*1024
    for template in (
        Template("long.line","1","😀"*1024+"a",(),"warn"),
        Template("long.value","1","{value}",(("value",(value+"a",)),),"warn"),
        Template("surrogate.line","1","\ud800",(),"warn"),
        Template("surrogate.value","1","{value}",(("value",("\ud800",)),),"warn"),
        Template("bad.severity","1","line",(),"unknown"),
    ):
        with pytest.raises(ValueError):c.register_template(template)
    init(replace(config(),build="😀"*32))
    with pytest.raises(ValueError):init(replace(config(),build="😀"*32+"a"))
    with pytest.raises(ValueError):init(replace(config(),build="\ud800"))
