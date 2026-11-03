# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
"""Explicit bounded leases; episode associations never retain exceptions or numeric IDs."""
import asyncio
import sys
import threading
import types
import weakref
from .errors import HandlingEpisode

class HookLease:
    def __init__(self,client,*,loop=None):
        self._client=client;self._closed=False;self._episodes=[];self._loop=loop
        self._prior_sys=sys.excepthook;self._prior_thread=threading.excepthook
        self._prior_loop=loop.get_exception_handler() if loop is not None else None
        client._own_hook_lease(self)
        self.sys_hook=self._global_hook;self.thread_hook=self._thread_hook;self.async_hook=self._async_hook
        sys.excepthook=self.sys_hook;threading.excepthook=self.thread_hook
        if loop is not None:loop.set_exception_handler(self.async_hook)
    def _global_hook(self,cls,error,tb):
        if not self._closed:self._capture(error,"uncaught_exception",True)
        self._prior_sys(cls,error,tb)
    def _thread_hook(self,args):
        if not self._closed:self._capture(threading.ExceptHookArgs.exc_value.__get__(args),"thread_exception",False,thread=threading.ExceptHookArgs.thread.__get__(args))
        self._prior_thread(args)
    def _async_hook(self,event_loop,context):
        if not self._closed:
            selected={key:value for key,value in dict.items(context) if type(key) is str and key in ("exception","task","future")} if type(context) is dict else {}
            error=selected.get("exception")
            if error is None:
                with self._client._lock:self._client._loss("asyncio_missing_exception")
            else:self._capture(error,"asyncio_exception",False,loop=event_loop,task=selected.get("task",selected.get("future")))
        if self._prior_loop is not None:self._prior_loop(event_loop,context)
        else:event_loop.default_exception_handler(context)
    @staticmethod
    def _unwind(prior,method,previous):
        while type(prior) is types.MethodType:
            owner=prior.__self__
            if type(owner) is not HookLease or prior.__func__ is not getattr(HookLease,method) or not owner._closed:break
            prior=getattr(owner,previous)
        return prior
    def _capture(self,error,mechanism,fatal,*,thread=None,loop=None,task=None):
        try:
            thread=thread if thread is not None else threading.current_thread()
            with self._client._lock:
                episode=None;pending=[]
                for arm in self._episodes:
                    token,source,thread_ref,loop_ref,task_ref,error_ref=arm
                    if token._closed or thread_ref() is None or (error_ref is not None and error_ref() is None) or (task_ref is not None and task_ref() is None):continue
                    matches=(source==mechanism and thread_ref() is thread and (loop_ref is None or loop_ref() is loop) and (task_ref is None or task_ref() is task) and (error_ref is None or error_ref() is error))
                    if episode is None and matches:episode=token
                    else:pending.append(arm)
                self._episodes=pending
            if episode is not None:episode._capture_hook(error,mechanism,fatal)
            else:self._client._capture_exception(error,None,mechanism,fatal)
        except BaseException:
            with self._client._lock:self._client._loss("hook_capture_failed")
    def use_episode(self,episode,*,error,mechanism,task=None,explicit_rethrow=False):
        """Arm a thread/source-bound rethrow; nonweak errors require explicit caller context.

        asyncio additionally requires the exact native Task and this lease's loop.
        Identity-safe weak errors are matched by weak reference, never id(error).
        """
        with self._client._lock:
            if self._closed:raise RuntimeError("hook lease closed")
            if type(episode) is not HandlingEpisode or episode._client is not self._client or episode._closed:raise ValueError("invalid handling episode")
            if type(mechanism) is not str or mechanism not in ("uncaught_exception","thread_exception","asyncio_exception"):raise ValueError("invalid hook mechanism")
            if type(explicit_rethrow) is not bool:raise ValueError("invalid explicit_rethrow")
            try:error_ref=weakref.ref(error)
            except TypeError:
                if not explicit_rethrow:raise ValueError("exception identity unavailable; explicit_rethrow required") from None
                error_ref=None
            loop_ref=task_ref=None
            if mechanism=="asyncio_exception":
                if self._loop is None or type(task) is not asyncio.Task or asyncio.Task.get_loop(task) is not self._loop:raise ValueError("exact asyncio loop/task required")
                loop_ref=weakref.ref(self._loop);task_ref=weakref.ref(task)
            elif task is not None:raise ValueError("task only valid for asyncio_exception")
            thread=threading.current_thread()
            self._episodes=[arm for arm in self._episodes if not arm[0]._closed and arm[2]() is not None and (arm[5] is None or arm[5]() is not None) and (arm[4] is None or arm[4]() is not None)]
            # Reject ambiguous same-source nonweak contexts and reused weak identities.
            for arm in self._episodes:
                if arm[1]==mechanism and arm[2]() is thread and (arm[4]() if arm[4] else None) is task and (arm[5] is None or error_ref is None or arm[5]() is error):raise ValueError("ambiguous explicit rethrow context")
            if len(self._episodes)>=8:raise RuntimeError("episode arm limit")
            self._episodes.append((episode,mechanism,weakref.ref(thread),loop_ref,task_ref,error_ref))
    def clear_episode(self,episode):
        with self._client._lock:self._episodes=[arm for arm in self._episodes if arm[0] is not episode]
    def close(self):
        with self._client._lock:
            if self._closed:return
            self._closed=True;self._episodes.clear()
            if sys.excepthook is self.sys_hook:sys.excepthook=self._unwind(self._prior_sys,"_global_hook","_prior_sys")
            if threading.excepthook is self.thread_hook:threading.excepthook=self._unwind(self._prior_thread,"_thread_hook","_prior_thread")
            if self._loop is not None and self._loop.get_exception_handler() is self.async_hook:self._loop.set_exception_handler(self._unwind(self._prior_loop,"_async_hook","_prior_loop"))
            self._client._release_hook_lease(self)

def install_hooks(client,*,loop=None):
    if loop is None:
        try:loop=asyncio.get_running_loop()
        except RuntimeError:pass
    return HookLease(client,loop=loop)
