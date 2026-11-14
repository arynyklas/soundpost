# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
"""Celery 5 job attempts: one attempt per execution, retries as ordinals of one run.

The producer publishes only a W3C ``traceparent`` header, and only toward an allow-listed
origin alias. The worker records that trace as the attempt's ``cause_trace`` *link*; it never
becomes the active parent, so no child span is created synchronously from the publisher.
The SDK supplies attempts and evidence; the backend reducer computes run and schedule health.
"""
import asyncio
from threading import Lock
from uuid import UUID
from celery import signals
from celery.exceptions import Retry, Terminated, TaskRevokedError
from .propagation import extract, inject

_CANCELLED = (Terminated, TaskRevokedError)


class Instrumentation:
    """Disconnects every signal handler on close; idempotent."""

    def __init__(self, app, client, origin):
        self._app = app
        self._client = client
        self._origin = origin
        self._active = {}
        self._lock = Lock()
        self._closed = False
        self._handlers = (
            (signals.before_task_publish, self._publish),
            (signals.task_prerun, self._prerun),
            (signals.task_retry, self._retry),
            (signals.task_failure, self._failure),
            (signals.task_revoked, self._revoked),
            (signals.task_postrun, self._postrun),
        )
        for signal, handler in self._handlers:
            signal.connect(handler, weak=False, dispatch_uid=('soundpost', id(self), handler.__name__))

    def close(self):
        if self._closed: return
        self._closed = True
        for signal, handler in self._handlers:
            signal.disconnect(handler, dispatch_uid=('soundpost', id(self), handler.__name__))
        with self._lock: leftovers, self._active = list(self._active.values()), {}
        for state in leftovers:
            # An attempt whose worker never reached postrun is not invented as success or failure.
            state['manager'] = None

    def _owns(self, name):
        return not self._closed and type(name) is str and name in self._app.tasks

    def _publish(self, sender=None, headers=None, **_):
        try:
            if self._origin is None or not self._owns(sender) or type(headers) is not dict or 'traceparent' in headers: return
            headers.update(inject(self._client._trace_context.current(), self._origin, allowed_origins=self._client._trace_origins))
        except BaseException:
            self._loss('job_propagation_failed')

    def _prerun(self, task_id=None, task=None, **_):
        try:
            if self._closed or getattr(task, 'app', None) is not self._app or type(task_id) is not str: return
            try: run_id = UUID(task_id).hex
            except ValueError: return self._loss('job_run_id_invalid')
            request = task.request
            ordinal = int(request.retries or 0) + 1
            link = extract({'traceparent': request.get('traceparent')}) if type(request.get('traceparent')) is str else None
            try: manager = self._client.job_attempt(task.name, run_id, ordinal)
            except ValueError: return  # an unregistered task or invalid identity never changes execution
            # Bind the publisher's trace only while the attempt records its cause link.
            if link is None: manager.__enter__()
            else:
                with self._client._trace_context.bind(link): manager.__enter__()
            with self._lock: self._active[task_id] = {'manager': manager, 'error': None, 'cancelled': False}
        except BaseException:
            self._loss('job_capture_failed')

    def _state(self, task_id):
        with self._lock: return self._active.get(task_id)

    def _retry(self, request=None, reason=None, einfo=None, **_):
        state = self._state(getattr(request, 'id', None))
        if state is None: return
        error = getattr(einfo, 'exception', None)
        if isinstance(error, Retry) and isinstance(error.exc, BaseException): error = error.exc
        state['error'] = error if isinstance(error, BaseException) else reason if isinstance(reason, BaseException) else None

    def _failure(self, task_id=None, exception=None, **_):
        state = self._state(task_id)
        if state is None: return
        if isinstance(exception, _CANCELLED): state['cancelled'] = True
        state['error'] = exception if isinstance(exception, BaseException) else None

    def _revoked(self, request=None, **_):
        state = self._state(getattr(request, 'id', None))
        if state is not None: state['cancelled'] = True

    def _postrun(self, task_id=None, state=None, **_):
        with self._lock: record = self._active.pop(task_id, None)
        manager = record and record['manager']
        if manager is None: return
        try:
            error = record['error']
            if record['cancelled']: manager.__exit__(asyncio.CancelledError, None, None)
            elif error is not None: manager.__exit__(type(error), error, error.__traceback__)
            elif state in ('FAILURE', 'RETRY', 'REVOKED', 'REJECTED'):
                manager.__exit__(asyncio.CancelledError if state == 'REVOKED' else RuntimeError, None, None)
            else: manager.__exit__(None, None, None)
        except BaseException:
            self._loss('job_capture_failed')

    def _loss(self, reason):
        client = self._client
        with client._lock: client._loss(reason)


def instrument(app, client, *, origin=None):
    """Attach SDK job-attempt capture to one Celery app; ``origin`` names the destination alias; trace links are published only when the client config allow-lists it."""
    if origin is not None and type(origin) is not str:
        raise TypeError('origin must be an alias string')
    return Instrumentation(app, client, origin)
