# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
import base64
import json
import re
from dataclasses import dataclass
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from .types import Config, PolicyDecision, Template, CaptureInput, SafeRecord

def utf8_size(value: str) -> int:
    try:
        return len(value.encode("utf-8", errors="strict"))
    except UnicodeEncodeError:
        raise ValueError("invalid Unicode text") from None

def decimal(value: object) -> str:
    if type(value) is not str or re.fullmatch(r"0|[1-9][0-9]{0,29}", value) is None:
        raise ValueError("invalid decimal")
    return value

def decode(value: str) -> bytes:
    if type(value) is not str or re.fullmatch(r"[A-Za-z0-9_-]+", value) is None:
        raise ValueError("invalid policy encoding")
    raw=base64.urlsafe_b64decode(value + "=" * (-len(value)%4))
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode() != value:
        raise ValueError("invalid policy encoding")
    return raw

def canonical(value: object) -> bytes:
    return json.dumps(value,sort_keys=True,separators=(",", ":"),ensure_ascii=False,allow_nan=False).encode()

def pairs(items):
    result={}
    for key,value in items:
        if key in result: raise ValueError("duplicate policy key")
        result[key]=value
    return result

@dataclass(frozen=True)
class SourcePolicy:
    decision: PolicyDecision
    expires_ns: str

def resolve(config: Config) -> SourcePolicy:
    try:
        envelope=config.policy
        if type(envelope.version) is not int or envelope.version != 1 or envelope.algorithm != "Ed25519": raise ValueError()
        payload=decode(envelope.payload)
        if len(payload)>65536: raise ValueError()
        key=config.trusted_keys[envelope.key_id]
        if type(key) is not bytes or len(key)!=32: raise ValueError()
        Ed25519PublicKey.from_public_bytes(key).verify(decode(envelope.signature),payload)
        data=json.loads(payload,object_pairs_hook=pairs,parse_float=lambda _: (_ for _ in ()).throw(ValueError()),parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        if canonical(data)!=payload: raise ValueError()
        keys={"version","org","project","source","revision","expires_ns","errors","logs","replay","bodies"}
        if type(data) is not dict or set(data)!=keys or type(data["version"]) is not int or data["version"]!=1: raise ValueError()
        for name in ("org","project","source"):
            if type(data[name]) is not str or data[name]!=getattr(config,name): raise ValueError()
        for name in ("errors","logs","replay","bodies"):
            if type(data[name]) is not bool: raise ValueError()
        revision=decimal(data["revision"]);expiry=decimal(data["expires_ns"])
        decision=PolicyDecision(True,"approved",revision,data["errors"] and config.deployment_errors,data["logs"] and config.deployment_logs,data["replay"] and config.deployment_replay,data["bodies"] and config.deployment_bodies)
        return SourcePolicy(decision,expiry)
    except Exception:
        raise ValueError("invalid signed policy") from None

def approve_template(template: Template) -> Template:
    if type(template) is not Template or type(template.id) is not str or re.fullmatch(r"[a-zA-Z0-9_.-]{1,128}",template.id) is None: raise ValueError("invalid template")
    decimal(template.revision)
    if type(template.line) is not str or utf8_size(template.line)>4096 or type(template.fields) is not tuple: raise ValueError("invalid template")
    if type(template.severity) is not str or template.severity not in ("trace","debug","info","warn","error","fatal"):raise ValueError("invalid severity")
    fields=[]
    for name,values in template.fields:
        if type(name) is not str or re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_]{0,63}",name) is None or type(values) is not tuple or not values: raise ValueError("invalid template field")
        for value in values:
            if type(value) not in (str,int,bool,type(None)) or (type(value) is str and utf8_size(value)>256) or (type(value) is int and abs(value)>9007199254740991): raise ValueError("invalid approved value")
        fields.append((name,tuple(values)))
    if len(set(name for name,_ in fields))!=len(fields): raise ValueError("duplicate template field")
    placeholders=re.findall(r"\{([^{}]+)\}",template.line)
    if set(placeholders)-set(name for name,_ in fields) or re.sub(r"\{[^{}]+\}","",template.line).count("{") or re.sub(r"\{[^{}]+\}","",template.line).count("}"): raise ValueError("invalid template placeholder")
    return Template(template.id,template.revision,template.line,tuple(fields),template.severity)

def normalize_record(policy: SourcePolicy, capture: CaptureInput, templates: dict[str,Template]) -> tuple[SafeRecord|None,str|None]:
    kind=capture["kind"]
    if int(capture["observed_at_ns"])>=int(policy.expires_ns): return None,"policy_expired"
    if not getattr(policy.decision,"errors" if kind=="error" else "logs"): return None,"policy_disabled"
    if kind=="error":
        payload={"occurrence_id":capture["id"],"exception_class":capture["exception_class"],"code":capture["code"],"build_id":capture["build_id"],"handled":True,"fatal":False,"frames":[]}
    else:
        template=templates.get(capture["template_id"])
        if template is None:return None,"unknown_template"
        raw=capture["fields"]
        if type(raw) is not dict:return None,"invalid_fields"
        # Copy only primitive string keys, without hashing/comparing hostile keys.
        approved_keys={key for key,_ in template.fields}
        selected={key:value for key,value in dict.items(raw) if type(key) is str and key in approved_keys}
        safe={}
        for key,allowed in template.fields:
            if key not in selected:return None,"invalid_field"
            value=selected[key]
            if type(value) not in (str,int,bool,type(None)) or not any(type(value) is type(v) and value==v for v in allowed):return None,"invalid_field"
            safe[key]=value
        def render(match):
            value=safe[match.group(1)]
            return value if type(value) is str else json.dumps(value,ensure_ascii=False,separators=(",", ":"))
        line=re.sub(r"\{([^{}]+)\}",render,template.line)
        payload={"template_id":template.id,"template_revision":template.revision,"fields":safe,"line":line,"severity":template.severity,"stream_labels":{},"structured_metadata":{},"source_class":"structured"}
    return canonical({"kind":kind,"id":capture["id"],"observed_at_ns":capture["observed_at_ns"],"policy_revision":policy.decision.revision,"payload":payload}).decode(),None
