# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
from dataclasses import dataclass, field
from typing import Callable, Mapping, TypeAlias, TypedDict, Literal, NotRequired
import time
EventID: TypeAlias = str
Primitive: TypeAlias = str | int | bool | None
ErrorMechanism: TypeAlias = Literal["manual","uncaught_exception","unhandled_rejection","thread_exception","asyncio_exception"]
ExceptionEdgeKind: TypeAlias = Literal["cause","context","group"]
@dataclass(frozen=True)
class SignedPolicy:
    version: int
    algorithm: str
    key_id: str
    payload: str
    signature: str
@dataclass(frozen=True)
class Template:
    id: str
    revision: str
    line: str
    fields: tuple[tuple[str, tuple[Primitive, ...]], ...]
    severity: Literal["trace", "debug", "info", "warn", "error", "fatal"]
@dataclass(frozen=True)
class Resource:
    service_id: str
    environment_id: str
    build_id: str
    instance_pseudonym: str
    labels: tuple[tuple[str,str], ...] = ()
@dataclass(frozen=True)
class RoutingDescriptor:
    version: int
    org: str
    project: str
    source: str
    routing_version: int
    slots: int
    policy_revision: str
@dataclass(frozen=True)
class Config:
    org: str
    project: str
    source: str
    endpoint: str
    credential: str = field(repr=False)
    build: str
    policy: SignedPolicy = field(repr=False)
    trusted_keys: Mapping[str, bytes] = field(repr=False)
    resource: Resource
    templates: tuple[Template, ...] = ()
    operations: tuple[str, ...] = ()
    dependencies: tuple[str, ...] = ()
    origins: tuple[str, ...] = ()
    job_registry: tuple[tuple[str,str], ...] = ()
    integrations: tuple[str, ...] = ()
    deployment_errors: bool = True
    deployment_logs: bool = True
    deployment_replay: bool = False
    deployment_bodies: bool = False
    deployment_traces: bool = True
    deployment_jobs: bool = True
    deployment_loss: bool = True
    max_records: int = 1024
    max_bytes: int = 2097152
    clock_ns: Callable[[], str] = lambda: str(time.time_ns())
    clock_uncertainty_ns: str = "18446744073709551615"
    project_root: str | None = None
    descriptor: RoutingDescriptor | None = None
    producer: str | None = None
    source_class: Literal["private","browser"] = "private"
    transport: object | None = field(default=None, repr=False)
    spool: object | None = field(default=None, repr=False)
    ca_file: str | None = None
@dataclass(frozen=True)
class PolicyDecision:
    approved: bool
    reason: str
    revision: str
    errors: bool
    logs: bool
    replay: bool
    bodies: bool
    traces: bool = False
    jobs: bool = False
    loss: bool = False
@dataclass(frozen=True)
class FlushReport:
    acknowledged_batch_ids: tuple[str, ...]
    acknowledged_cursors: tuple[str, ...]
    pending: int
    lost: int
    deadline_exceeded: bool
    receipts: tuple[dict, ...] = ()

class ErrorInput(TypedDict):
    kind: Literal["error"]
    id: str
    observed_at_ns: str
    exception_class: str
    code: str | None
    build_id: str
    exception_graph: dict
    handled: bool
    fatal: bool
    mechanism: ErrorMechanism
    trace_id: NotRequired[str]
    span_id: NotRequired[str]
    run_id: NotRequired[str]

class LogInput(TypedDict):
    kind: Literal["log"]
    id: str
    observed_at_ns: str
    template_id: str
    fields: dict[str, object]

class ClockDomain(TypedDict):
    host: str
    boot: str
    runtime: str

class TraceClock(TypedDict):
    wall_ns: str
    mono_ns: str
    domain: ClockDomain
    uncertainty_ns: str

class SpanLink(TypedDict):
    trace_id: str
    span_id: str

class SpanPayload(TypedDict):
    trace_id: str
    span_id: str
    parent_id: str | None
    span_kind: Literal["internal","server","client","producer","consumer"]
    operation: str
    start: TraceClock
    end: TraceClock | None
    status: Literal["ok","error","cancelled","incomplete"]
    dependency_alias: str
    links: list[SpanLink]
    sample_probability: str
    sample_decision: Literal["keep","drop"]
    job_id: NotRequired[str]
    replay_id: NotRequired[str]
    profile_id: NotRequired[str]

class SpanInput(TypedDict):
    kind: Literal["span"]
    id: str
    observed_at_ns: str
    payload: SpanPayload

class JobAttemptPayload(TypedDict):
    job_id: str
    run_id: str
    attempt_id: str
    schedule_occurrence: str
    ordinal: str
    producer_epoch: str
    sequence: str
    state: Literal["started","succeeded","failed","cancelled"]
    observed_ns: str
    terminal_ns: str | None
    cause_trace: NotRequired[str]
    cause_error: NotRequired[str]

class JobInput(TypedDict):
    kind: Literal["job_attempt"]
    id: str
    observed_at_ns: str
    payload: JobAttemptPayload

CaptureInput: TypeAlias = ErrorInput | LogInput | SpanInput | JobInput
SafeRecord: TypeAlias = str
