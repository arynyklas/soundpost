# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
import secrets
import threading
import time
import warnings
from .types import Config, Template, PolicyDecision, CaptureInput, ErrorMechanism, FlushReport
from .policy import resolve, approve_template, normalize_record, canonical_id, unix_nano, decimal
from .errors import extract_exception, HandlingEpisode
from .frames import normalize_root
from .queue import DeliveryQueue
from .transport import HttpsReceiptTransport, EXPORTING
from .context import ContextState
from .tracing import SpanContextManager
from .jobs import JobProducer, AttemptContextManager

class Client:
    """Policy-first capture with immutable, durable-receipt-aware delivery."""
    def __init__(self, config: Config):
        if type(config) is not Config: raise TypeError("Config required")
        if type(config.max_records) is not int or not 1<=config.max_records<=1024 or type(config.max_bytes) is not int or not 1<=config.max_bytes<=2097152: raise ValueError("invalid queue limits")
        for identity in (config.org,config.project,config.source,config.build):
            canonical_id(identity)
        if any(type(flag) is not bool for flag in (config.deployment_errors,config.deployment_logs,config.deployment_replay,config.deployment_bodies,config.deployment_traces,config.deployment_jobs,config.deployment_loss)):
            raise ValueError("deployment permissions must be boolean")
        if config.integrations:raise ValueError("integrations not available")
        import re
        for aliases in (config.operations,config.dependencies,config.origins):
            if type(aliases) is not tuple or len(aliases)>1024 or any(type(alias) is not str or re.fullmatch(r"[A-Za-z0-9_.-]{1,128}",alias) is None for alias in aliases) or len(set(aliases))!=len(aliases):
                raise ValueError("invalid registered aliases")
        self._trace_context=ContextState()
        self._trace_operations=frozenset(config.operations)
        self._trace_dependencies=frozenset(config.dependencies)
        self._trace_origins=frozenset(config.origins)
        self._trace_domain={key:secrets.token_hex(16) for key in ("host","boot","runtime")}
        self._trace_uncertainty=decimal(config.clock_uncertainty_ns)
        self._policy=resolve(config)
        self._clock=config.clock_ns
        self._max_records=config.max_records;self._max_bytes=config.max_bytes
        self._build=config.build;self._codes=frozenset(config.operations)
        self._templates={}
        self._jobs=JobProducer(self,config.job_registry)
        self._delivery=DeliveryQueue(config,config.transport or HttpsReceiptTransport(config));self._counts:dict[str,int]={}
        self._closed=False;self._close_report=None;self._lock=threading.RLock()
        self._project_root=normalize_root(config.project_root);self._hook_leases=[]
        for template in config.templates:self.register_template(template)
    @property
    def policy_decision(self) -> PolicyDecision:return self._policy.decision
    def _loss(self,reason):self._counts[reason]=self._counts.get(reason,0)+1
    def _read_clock(self)->str|None:
        try:return unix_nano(self._clock())
        except Exception:
            with self._lock:self._loss("invalid_clock")
            return None
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
            if EXPORTING.get() or self._trace_context.is_exporting():self._loss("exporter_recursion");return False
            record,reason=normalize_record(self._policy,capture,self._templates)
            if record is None:self._loss(reason);return False
            return self._delivery.enqueue(record)
    def capture_exception(self,error:BaseException,*,code:str|None=None)->str:
        return self._capture_exception(error,code,"manual",False)
    def _capture_exception(self,error,code,mechanism:ErrorMechanism,fatal:bool):
        if type(mechanism) is not str or mechanism not in ("manual","uncaught_exception","unhandled_rejection","thread_exception","asyncio_exception") or type(fatal) is not bool:raise ValueError("invalid error mechanism")
        event=secrets.token_hex(16)
        observed=self._read_clock()
        if observed is None:return event
        graph=extract_exception(error,self._policy,project_root=self._project_root)
        safe_code=code if type(code) is str and code in self._codes else None
        if code is not None and safe_code is None:
            with self._lock:self._loss("unregistered_code")
        capture={"kind":"error","id":event,"observed_at_ns":observed,"exception_class":graph["nodes"][0]["exception_class"],"code":safe_code,"build_id":self._build,"exception_graph":graph,"handled":mechanism=="manual","fatal":fatal,"mechanism":mechanism}
        context=self._trace_context.current()
        if context is not None:capture.update(trace_id=context.trace_id,span_id=context.span_id)
        attempt=self._jobs.current()
        if attempt is not None:capture["run_id"]=attempt.run_id
        self._admit(capture)
        return event
    def capture_handled(self,error:BaseException,*,code:str|None=None)->str:
        """Capture one handled error as one logical occurrence: begin episode, capture, close, in a single call."""
        episode=self.begin_handling_episode()
        try:return episode.capture_exception(error,code=code)
        finally:episode.close()
    def span(self,operation:str,*,dependency:str|None=None,kind:str='internal')->SpanContextManager:
        return SpanContextManager(self,operation,dependency=dependency,kind=kind)
    def job_attempt(self,job:str,run_id:str,ordinal:int)->AttemptContextManager:
        return self._jobs.attempt(job,run_id,ordinal)
    def _capture_span(self,payload:dict)->bool:
        if payload["operation"] not in self._trace_operations or payload["dependency_alias"] and payload["dependency_alias"] not in self._trace_dependencies:
            with self._lock:self._loss("unregistered_span")
            return False
        if payload["sample_decision"]=="drop":
            with self._lock:self._loss("trace_sampled_out")
            self._record_signal_loss("span","policy",1)
            return False
        observed=self._read_clock()
        return observed is not None and self._admit({"kind":"span","id":secrets.token_hex(16),"observed_at_ns":observed,"payload":payload})
    def _record_signal_loss(self,signal:str,reason:str,count:int)->bool:
        with self._lock:
            if self._closed or EXPORTING.get() or self._trace_context.is_exporting() or not self._policy.decision.loss:return False
            observed=self._read_clock()
            if observed is None or int(observed)>=int(self._policy.expires_ns):return False
            return self._delivery.record_signal_loss(signal,reason,count,observed)
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
        observed=self._read_clock()
        if observed is None:return None
        return event if self._admit({"kind":"log","id":event,"observed_at_ns":observed,"template_id":template,"fields":fields}) else None
    def buffered_records(self)->tuple[str,...]:
        return self._delivery.records()
    def diagnostics(self)->dict[str,int]:
        with self._lock:
            counts=self._counts.copy()
            for key,value in self._delivery.diagnostics().items():counts[key]=counts.get(key,0)+value
            return counts
    def flush(self,timeout:float=2.0):
        with self._trace_context.exporting():
            return self._delivery.flush(timeout)
    def close(self,timeout:float=2.0)->FlushReport|None:
        """Flush within `timeout` seconds, release owned resources and return the final FlushReport.

        Records still undelivered when the bounded flush ends are never dropped silently: the report's `dropped` counts them,
        `diagnostics()["closed_pending"]` accumulates them and a RuntimeWarning names the count. With a spool nothing is dropped.
        A repeated close returns the first report."""
        if type(timeout) not in (int,float) or timeout<0 or timeout!=timeout or timeout==float("inf"):raise ValueError("invalid close deadline")
        with self._lock:
            if self._closed:return self._close_report
            self._closed=True
            for lease in tuple(self._hook_leases):lease.close()
        with self._trace_context.exporting():
            report=self._delivery.close(timeout)
        self._close_report=report
        if report is not None and report.dropped:
            warnings.warn(f"soundpost: close() discarded {report.dropped} undelivered record(s) after a {timeout}s flush; see FlushReport.dropped and diagnostics()['closed_pending']",RuntimeWarning,stacklevel=2)
        return report

def init(config:Config)->Client:return Client(config)
