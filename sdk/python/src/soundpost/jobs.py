# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
"""Manual attempt observations, not a scheduler or a source of current health."""
import asyncio
from concurrent.futures import CancelledError as FutureCancelledError
from contextvars import ContextVar
from dataclasses import dataclass
import os
import re
import secrets
from .policy import canonical_id, decimal, unix_nano


def normalize_attempt(raw: dict) -> dict:
    """Validate the closed native C04 body before any queue owns its bytes."""
    required = {'job_id', 'run_id', 'attempt_id', 'schedule_occurrence', 'ordinal', 'producer_epoch', 'sequence', 'state', 'observed_ns', 'terminal_ns'}
    optional = {'cause_trace', 'cause_error'}
    if type(raw) is not dict or any(type(key) is not str for key in raw) or not required <= set(raw) or set(raw) - required - optional:
        raise ValueError('invalid job attempt fields')
    for name in ('job_id', 'run_id', 'attempt_id', 'producer_epoch'):
        canonical_id(raw[name])
    for name in optional:
        if name in raw: canonical_id(raw[name])
    if decimal(raw['ordinal']) == '0': raise ValueError('invalid attempt ordinal')
    decimal(raw['sequence'])
    schedule = raw['schedule_occurrence']
    if type(schedule) is not str or re.fullmatch(r'[A-Za-z0-9_.-]{1,256}', schedule) is None:
        raise ValueError('invalid schedule occurrence')
    state = raw['state']
    if type(state) is not str or state not in ('started', 'succeeded', 'failed', 'cancelled'):
        raise ValueError('invalid attempt state')
    observed = unix_nano(raw['observed_ns'])
    terminal = raw['terminal_ns']
    if state == 'started':
        if terminal is not None: raise ValueError('started attempt cannot be terminal')
    elif terminal is None or int(unix_nano(terminal)) < int(observed):
        raise ValueError('invalid terminal time')
    return dict(raw)


@dataclass(frozen=True, slots=True)
class AttemptContext:
    job_id: str
    run_id: str
    attempt_id: str


class JobProducer:
    def __init__(self, client, registry):
        if type(registry) is not tuple or len(registry) > 1024:
            raise ValueError('invalid job registry')
        self._registry = {}
        for item in registry:
            if type(item) is not tuple or len(item) != 2:
                raise ValueError('invalid job registry')
            alias, identity = item
            if type(alias) is not str or re.fullmatch(r'[A-Za-z0-9_.-]{1,128}', alias) is None or alias in self._registry:
                raise ValueError('invalid job alias')
            self._registry[alias] = canonical_id(identity)
        self._client = client
        self._context = ContextVar('soundpost_job', default=None)
        self._pid = os.getpid()
        self._epoch = secrets.token_hex(16)
        self._sequence = 0

    def current(self) -> AttemptContext | None:
        return self._context.get() if os.getpid() == self._pid else None

    def attempt(self, job, run_id, ordinal):
        if type(job) is not str or job not in self._registry:
            raise ValueError('job must be registered')
        canonical_id(run_id)
        if type(ordinal) is not int or not 1 <= ordinal <= 18446744073709551615:
            raise ValueError('ordinal must be a positive uint64')
        return AttemptContextManager(self, self._registry[job], run_id, str(ordinal))

    def emit(self, attempt, state, terminal=None, cause_error=None):
        if attempt.observed_ns is None: return
        client = self._client
        try:
            # Sequence allocation and admission share the client's serialization lock.
            # A fork gets a new epoch, never a negative or reused sequence domain.
            with client._lock:
                if os.getpid() != self._pid:
                    self._pid = os.getpid()
                    self._epoch = secrets.token_hex(16)
                    self._sequence = 0
                    self._context.set(None)
                if self._sequence == 18446744073709551615:
                    client._loss('job_sequence_exhausted')
                    return
                self._sequence += 1
                payload = {'job_id': attempt.context.job_id, 'run_id': attempt.run_id, 'attempt_id': attempt.context.attempt_id,
                           'schedule_occurrence': 'manual.' + attempt.run_id, 'ordinal': attempt.ordinal,
                           'producer_epoch': self._epoch, 'sequence': str(self._sequence), 'state': state,
                           'observed_ns': attempt.observed_ns, 'terminal_ns': terminal}
                if attempt.trace_id is not None: payload['cause_trace'] = attempt.trace_id
                if cause_error is not None: payload['cause_error'] = cause_error
                client._admit({'kind': 'job_attempt', 'id': secrets.token_hex(16),
                               'observed_at_ns': terminal if terminal is not None else attempt.observed_ns,
                               'payload': payload})
        except BaseException:
            # Telemetry failures never replace the application outcome or cancellation.
            with client._lock: client._loss('job_capture_failed')


class AttemptContextManager:
    """One-use sync/async scope; no arguments, task values or raw errors retained."""
    def __init__(self, producer, job_id, run_id, ordinal):
        self._producer = producer
        self.context = AttemptContext(job_id, run_id, secrets.token_hex(16))
        self.run_id = run_id
        self.ordinal = ordinal
        self.observed_ns = None
        self.trace_id = None
        self._entered = False
        self._exited = False

    def __enter__(self):
        if self._entered: raise RuntimeError('attempt scope already entered')
        self._entered = True
        client = self._producer._client
        if client._closed: raise RuntimeError('client closed')
        # Register a fresh fork domain before binding, so inherited context is absent.
        with client._lock:
            if os.getpid() != self._producer._pid:
                self._producer._pid = os.getpid()
                self._producer._epoch = secrets.token_hex(16)
                self._producer._sequence = 0
                self._producer._context.set(None)
        self._token = self._producer._context.set(self.context)
        try:
            self.observed_ns = client._read_clock()
            trace = client._trace_context.current()
            self.trace_id = trace.trace_id if trace is not None else None
            self._producer.emit(self, 'started')
        except BaseException:
            with client._lock: client._loss('job_capture_failed')
        return self

    def __exit__(self, exception_type, exception, traceback):
        if not self._entered or self._exited: raise RuntimeError('attempt scope not active')
        self._exited = True
        client = self._producer._client
        try:
            cancelled = exception_type is not None and issubclass(exception_type, (asyncio.CancelledError, FutureCancelledError))
            state = 'cancelled' if cancelled else 'failed' if exception_type is not None else 'succeeded'
            cause_error = None
            if exception_type is not None and not cancelled:
                try: cause_error = client.capture_exception(exception)
                except BaseException:
                    with client._lock: client._loss('job_error_capture_failed')
            terminal = client._read_clock()
            if terminal is not None and self.observed_ns is not None and int(terminal) >= int(self.observed_ns):
                self._producer.emit(self, state, terminal, cause_error)
            else:
                with client._lock: client._loss('job_clock_unavailable')
        except BaseException:
            with client._lock: client._loss('job_capture_failed')
        finally:
            self._producer._context.reset(self._token)
        return False

    async def __aenter__(self):
        return self.__enter__()

    async def __aexit__(self, exception_type, exception, traceback):
        return self.__exit__(exception_type, exception, traceback)
