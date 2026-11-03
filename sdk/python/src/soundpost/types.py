# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
from dataclasses import dataclass, field
from typing import Callable, Mapping, TypeAlias, TypedDict, Literal
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
class Config:
    org: str
    project: str
    source: str
    endpoint: str
    credential: str = field(repr=False)
    build: str
    policy: SignedPolicy = field(repr=False)
    trusted_keys: Mapping[str, bytes] = field(repr=False)
    templates: tuple[Template, ...] = ()
    operations: tuple[str, ...] = ()
    dependencies: tuple[str, ...] = ()
    origins: tuple[str, ...] = ()
    integrations: tuple[str, ...] = ()
    deployment_errors: bool = True
    deployment_logs: bool = True
    deployment_replay: bool = False
    deployment_bodies: bool = False
    max_records: int = 1024
    max_bytes: int = 2097152
    clock_ns: Callable[[], str] = lambda: str(time.time_ns())
    project_root: str | None = None
@dataclass(frozen=True)
class PolicyDecision:
    approved: bool
    reason: str
    revision: str
    errors: bool
    logs: bool
    replay: bool
    bodies: bool
@dataclass(frozen=True)
class FlushReport:
    acknowledged_batch_ids: tuple[str, ...]
    acknowledged_cursors: tuple[str, ...]
    pending: int
    lost: int
    deadline_exceeded: bool

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

class LogInput(TypedDict):
    kind: Literal["log"]
    id: str
    observed_at_ns: str
    template_id: str
    fields: dict[str, object]

CaptureInput: TypeAlias = ErrorInput | LogInput
SafeRecord: TypeAlias = str
