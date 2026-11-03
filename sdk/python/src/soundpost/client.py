# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
import secrets
import threading
import time
from .types import Config, Template, PolicyDecision, CaptureInput, ErrorMechanism
from .policy import resolve, decimal, approve_template, normalize_record, utf8_size
from .errors import extract_exception, HandlingEpisode
from .frames import normalize_root

class Client:
    """Policy-bound local capture. Delivery APIs are intentionally unavailable."""
    def __init__(self, config: Config):
        if type(config) is not Config: raise TypeError("Config required")
        if type(config.max_records) is not int or not 1<=config.max_records<=1024 or type(config.max_bytes) is not int or not 1<=config.max_bytes<=2097152: raise ValueError("invalid queue limits")
        for identity in (config.org,config.project,config.source,config.build):
            if type(identity) is not str or not identity or utf8_size(identity)>128:raise ValueError("invalid identity")
        if any(type(flag) is not bool for flag in (config.deployment_errors,config.deployment_logs,config.deployment_replay,config.deployment_bodies)):
            raise ValueError("deployment permissions must be boolean")
        if config.integrations:raise ValueError("integrations not available")
        self._policy=resolve(config)
        self._clock=config.clock_ns
        self._max_records=config.max_records;self._max_bytes=config.max_bytes
        self._build=config.build;self._codes=frozenset(config.operations)
        self._templates={}
        self._queue: list[tuple[str,int,float]]=[];self._bytes=0;self._counts:dict[str,int]={}
        self._closed=False;self._lock=threading.RLock()
        self._project_root=normalize_root(config.project_root);self._hook_leases=[]
        for template in config.templates:self.register_template(template)
    @property
    def policy_decision(self) -> PolicyDecision:return self._policy.decision
    def _loss(self,reason):self._counts[reason]=self._counts.get(reason,0)+1
    def _expire(self):
        now=time.monotonic()
        while self._queue and now-self._queue[0][2]>=300:
            _,size,_=self._queue.pop(0);self._bytes-=size;self._loss("queue_expired")
    def register_template(self,template:Template)->None:
        safe=approve_template(template)
        with self._lock:
            if self._closed:raise RuntimeError("client closed")
            previous=self._templates.get(safe.id)
            if previous and int(previous.revision)>=int(safe.revision):raise ValueError("template revision must increase")
            self._templates[safe.id]=safe
    def _admit(self,capture:CaptureInput)->bool:
        with self._lock:
            if self._closed:self._loss("closed");return False
            self._expire()
            record,reason=normalize_record(self._policy,capture,self._templates)
            if record is None:self._loss(reason);return False
            size=len(record.encode())
            if size>262144:self._loss("record_too_large");return False
            if len(self._queue)>=self._max_records or self._bytes+size>self._max_bytes:self._loss("queue_full");return False
            self._queue.append((record,size,time.monotonic()));self._bytes+=size;return True
    def capture_exception(self,error:BaseException,*,code:str|None=None)->str:
        return self._capture_exception(error,code,"manual",False)
    def _capture_exception(self,error,code,mechanism:ErrorMechanism,fatal:bool):
        if type(mechanism) is not str or mechanism not in ("manual","uncaught_exception","unhandled_rejection","thread_exception","asyncio_exception") or type(fatal) is not bool:raise ValueError("invalid error mechanism")
        event=secrets.token_hex(16)
        graph=extract_exception(error,self._policy,project_root=self._project_root)
        safe_code=code if type(code) is str and code in self._codes else None
        self._admit({"kind":"error","id":event,"observed_at_ns":decimal(self._clock()),"exception_class":graph["nodes"][0]["exception_class"],"code":safe_code,"build_id":self._build,"exception_graph":graph,"handled":mechanism=="manual","fatal":fatal,"mechanism":mechanism})
        return event
    def begin_handling_episode(self):
        return HandlingEpisode(self)
    def _own_hook_lease(self,lease):
        with self._lock:
            if self._closed:raise RuntimeError("client closed")
            if len(self._hook_leases)>=8:raise RuntimeError("hook lease limit")
            self._hook_leases.append(lease)
    def _release_hook_lease(self,lease):
        with self._lock:
            if lease in self._hook_leases:self._hook_leases.remove(lease)
    def capture_log(self,template:str,fields:dict)->str|None:
        if type(template) is not str:
            with self._lock:self._loss("unknown_template")
            return None
        event=secrets.token_hex(16)
        return event if self._admit({"kind":"log","id":event,"observed_at_ns":decimal(self._clock()),"template_id":template,"fields":fields}) else None
    def buffered_records(self)->tuple[str,...]:
        with self._lock:self._expire();return tuple(record for record,_,_ in self._queue)
    def diagnostics(self)->dict[str,int]:
        with self._lock:return self._counts.copy()
    def close(self)->None:
        with self._lock:
            if not self._closed:
                for lease in tuple(self._hook_leases):lease.close()
                self._counts["closed_pending"]=self._counts.get("closed_pending",0)+len(self._queue)
                self._queue.clear();self._bytes=0;self._closed=True

def init(config:Config)->Client:return Client(config)
