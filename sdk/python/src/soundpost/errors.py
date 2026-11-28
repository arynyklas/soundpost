# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
"""Bounded intrinsic exception traversal; raw references live only during extraction."""
import types
from .frames import project_frame

_CAUSE=BaseException.__dict__["__cause__"]
_CONTEXT=BaseException.__dict__["__context__"]
_SUPPRESS=BaseException.__dict__["__suppress_context__"]
_TRACEBACK=BaseException.__dict__["__traceback__"]
_GROUP=BaseExceptionGroup.__dict__["exceptions"]
_TYPE_NAME=type.__dict__["__name__"]

def exception_class(error):
    """Bare class name (never module, message or value), or None when it is not a safe ASCII identifier of at most 128 characters.

    No allowlist: any custom or third-party class name that passes the identifier check is exported as-is. The name is read with
    `type`'s own descriptor, so custom metaclasses (asyncpg and ORM exception hierarchies use them) and hostile
    `__name__`/`__getattribute__` overrides on the class, its metaclass or the instance are never invoked."""
    try:name=_TYPE_NAME.__get__(type(error))
    except TypeError:return None
    if type(name) is not str or not name.isascii() or not name.isidentifier() or len(name)>128:return None
    return name

def extract_exception(error: BaseException, policy=None, *, project_root=None):
    nodes=[];edges=[];reasons=set();seen=[];remaining=128
    if project_root is None:reasons.add("project_root_unconfigured")
    def visit(current, ancestors):
        nonlocal remaining
        for index,previous in enumerate(seen):
            if current is previous:
                if index in ancestors:reasons.add("cycle")
                return index
        if len(nodes)>=16:reasons.add("node_limit");return None
        index=len(nodes);seen.append(current)
        name=exception_class(current)
        if name is None:name="UnknownError";reasons.add("foreign_or_custom_error_class")
        node={"id":index,"exception_class":name,"frames":[],"context_suppressed":False}
        nodes.append(node)
        if current is None:
            node["exception_class"]="UnknownError";reasons.add("unknown_throw");return index
        try:node["context_suppressed"]=_SUPPRESS.__get__(current)
        except TypeError:
            node["exception_class"]="UnknownError";reasons.add("unknown_throw");return index
        tb=_TRACEBACK.__get__(current)
        while type(tb) is types.TracebackType:
            if remaining==0:reasons.add("frame_limit");break
            remaining-=1
            safe=project_frame(tb,project_root)
            if safe is not None:node["frames"].append(safe)
            else:reasons.add("frame_not_project_safe" if project_root is not None else "project_root_unconfigured")
            tb=types.TracebackType.tb_next.__get__(tb)
        def link(child,kind,ordinal=None):
            target=visit(child,ancestors|{index})
            if target is not None:
                edge={"from":index,"to":target,"kind":kind}
                if ordinal is not None:edge["ordinal"]=ordinal
                edges.append(edge)
        cause=_CAUSE.__get__(current)
        context=_CONTEXT.__get__(current)
        if cause is not None:link(cause,"cause")
        elif context is not None and not node["context_suppressed"]:link(context,"context")
        try:children=_GROUP.__get__(current)
        except TypeError:children=()
        # At most 16 links inspected, including shared references. No huge group scan.
        for ordinal,child in enumerate(children[:16]):link(child,"group",ordinal)
        if len(children)>16:reasons.add("group_limit")
        return index
    try:visit(error,set())
    finally:seen.clear()
    return {"nodes":nodes,"edges":edges,"reasons":sorted(reasons)}

class HandlingEpisode:
    """Explicit single logical occurrence. Holds only its safe occurrence ID, never error identity."""
    def __init__(self,client):self._client=client;self._event=None;self._closed=False
    def capture_exception(self,error,*,code=None):
        with self._client._lock:
            if self._closed:raise RuntimeError("episode closed")
            if self._event is None:self._event=self._client.capture_exception(error,code=code)
            return self._event
    def _capture_hook(self,error,mechanism,fatal):
        with self._client._lock:
            if self._closed:raise RuntimeError("episode closed")
            if self._event is None:self._event=self._client._capture_exception(error,None,mechanism,fatal)
            return self._event
    def close(self):
        with self._client._lock:self._closed=True
