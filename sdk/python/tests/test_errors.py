# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
import json
from pathlib import Path
from test_policy import config
from soundpost import init

def payload(client): return json.loads(client.buffered_records()[-1])["payload"]

def test_intrinsic_chain_groups_cycles_and_no_values():
    class Hostile(Exception):
        def __getattribute__(self, name): raise AssertionError("getter")
        def __str__(self): raise AssertionError("str")
        def __repr__(self): raise AssertionError("repr")
    root=Hostile("CANARY_MESSAGE")
    cause=ValueError("CANARY_CAUSE")
    root.__cause__=cause
    cause.__cause__=root
    group=ExceptionGroup("CANARY_GROUP", [root, TypeError("CANARY_CHILD")])
    c=init(config()); c.capture_exception(group)
    p=payload(c); graph=p["exception_graph"]
    assert [n["exception_class"] for n in graph["nodes"]]==["ExceptionGroup","Hostile","ValueError","TypeError"]
    assert "cycle" in graph["reasons"]
    assert any(e["kind"]=="group" for e in graph["edges"])
    assert "CANARY" not in str(c.buffered_records())

def test_suppression_node_budget_and_project_frames():
    c=init(config(project_root=str(Path(__file__).parent)))
    try:
        try: raise ValueError("CANARY_CONTEXT")
        except ValueError: raise RuntimeError("CANARY_ROOT") from None
    except RuntimeError as error: c.capture_exception(error)
    p=payload(c)
    assert p["exception_graph"]["nodes"][0]["context_suppressed"] is True
    assert len(p["exception_graph"]["nodes"])==1
    assert p["frames"][0]["artifact_id"]=="test_errors.py"
    assert p["frames"][0]["function"]=="test_suppression_node_budget_and_project_frames"
    assert str(Path.home()) not in str(c.buffered_records())
    root=RuntimeError()
    for _ in range(30):
        child=RuntimeError(); child.__cause__=root; root=child
    c.capture_exception(root)
    g=payload(c)["exception_graph"]
    assert len(g["nodes"])==16 and "node_limit" in g["reasons"]

def test_explicit_handling_episodes_do_not_hold_or_mutate_errors():
    c=init(config()); error=ValueError("CANARY")
    episode=c.begin_handling_episode()
    first=episode.capture_exception(error)
    assert episode.capture_exception(error)==first
    assert len(c.buffered_records())==1 and error.__dict__=={}
    assert c.begin_handling_episode().capture_exception(error)!=first
    episode.close()
    import pytest
    with pytest.raises(RuntimeError): episode.capture_exception(error)

def test_frame_budget_and_outside_root():
    c=init(config(project_root=str(Path(__file__).parent)))
    def recurse(n):
        if n: return recurse(n-1)
        raise ValueError("CANARY")
    try: recurse(140)
    except ValueError as error: c.capture_exception(error)
    g=payload(c)["exception_graph"]
    assert sum(len(n["frames"]) for n in g["nodes"])==128
    assert "frame_limit" in g["reasons"]

def test_capture_does_not_retain_weakrefable_error_even_without_gc():
    import gc
    import weakref
    class WeakError(Exception): __slots__=("__weakref__",)
    c=init(config());episode=c.begin_handling_episode()
    error=WeakError("CANARY");reference=weakref.ref(error)
    enabled=gc.isenabled();gc.disable()
    try:
        episode.capture_exception(error);del error
        assert reference() is None
    finally:
        if enabled:gc.enable()

def test_context_group_overflow_and_unknown_getter_traps():
    c=init(config())
    try:
        try:raise ValueError("CANARY")
        except ValueError:raise TypeError("CANARY")
    except TypeError as error:c.capture_exception(error)
    assert payload(c)["exception_graph"]["edges"][0]["kind"]=="context"
    c.capture_exception(ExceptionGroup("CANARY",[ValueError() for _ in range(100)]))
    graph=payload(c)["exception_graph"]
    assert len(graph["nodes"])==16 and "group_limit" in graph["reasons"]
    class Unknown:
        def __getattribute__(self,name):raise AssertionError("getter")
    c.capture_exception(Unknown())
    assert payload(c)["exception_class"]=="UnknownError"

def test_code_identity_string_subclasses_cannot_run_path_methods():
    class HostilePath(str):
        def replace(self,*args,**kwargs):raise AssertionError("path replace")
        def __str__(self):raise AssertionError("path str")
        def encode(self,*args,**kwargs):raise AssertionError("path encode")
    c=init(config(project_root=str(Path(__file__).parent)))
    def fail():raise ValueError("CANARY")
    fail.__code__=fail.__code__.replace(co_filename=HostilePath(str(Path(__file__).parent/"safe.py")))
    try:fail()
    except ValueError as error:c.capture_exception(error)
    assert "CANARY" not in "".join(c.buffered_records())
