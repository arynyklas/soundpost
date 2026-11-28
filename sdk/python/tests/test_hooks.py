# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
import asyncio
import json
import sys
import threading
from test_policy import config
from soundpost import init
from soundpost.hooks import install_hooks

def test_prior_handlers_episode_rethrow_and_conditional_restore():
    old=sys.excepthook; seen=[]
    prior=lambda *args: seen.append("prior")
    sys.excepthook=prior
    c=init(config()); lease=install_hooks(c)
    try:
        error=ValueError("CANARY")
        episode=c.begin_handling_episode(); first=episode.capture_exception(error)
        lease.use_episode(episode,error=error,mechanism="uncaught_exception",explicit_rethrow=True)
        sys.excepthook(type(error),error,None)
        assert seen==["prior"] and len(c.buffered_records())==1
        assert json.loads(c.buffered_records()[0])["id"]==first
        replacement=lambda *args: None
        sys.excepthook=replacement
        lease.close(); lease.close()
        assert sys.excepthook is replacement
    finally: lease.close(); c.close(); sys.excepthook=old

def test_asyncio_and_threading_paths_and_client_close():
    loop=asyncio.new_event_loop(); seen=[]
    loop.set_exception_handler(lambda loop, context: seen.append("async"))
    old=threading.excepthook
    threading.excepthook=lambda args: seen.append("thread")
    c=init(config()); lease=install_hooks(c,loop=loop)
    try:
        loop.call_exception_handler({"exception":ValueError("CANARY"),"message":"CANARY"})
        args=threading.ExceptHookArgs((ValueError,ValueError("CANARY"),None,threading.current_thread()))
        threading.excepthook(args)
        records=c.buffered_records()
        assert len(records)==2 and "CANARY" not in "".join(records)
        assert seen==["async","thread"]
        c.close(); assert threading.excepthook is not lease.thread_hook
    finally: lease.close(); threading.excepthook=old; loop.close()

def test_overlapping_leases_close_without_resurrecting_capture():
    old=sys.excepthook; prior=lambda *args: None;sys.excepthook=prior
    a=init(config()); b=init(config()); la=install_hooks(a); lb=install_hooks(b)
    try:
        la.close(); lb.close()
        assert sys.excepthook is prior
        sys.excepthook(ValueError,ValueError(),None)
        assert not a.buffered_records() and not b.buffered_records()
    finally: la.close(); lb.close(); sys.excepthook=old

def test_capture_failure_does_not_replace_prior_or_leak_diagnostics():
    old=sys.excepthook;seen=[];sys.excepthook=lambda *args:seen.append("prior")
    def bad_clock():raise RuntimeError("CANARY_CAPTURE_FAILURE")
    c=init(config(clock_ns=bad_clock));lease=install_hooks(c)
    try:
        sys.excepthook(ValueError,ValueError("CANARY_NATIVE"),None)
        assert seen==["prior"] and not c.buffered_records()
        assert c.diagnostics()=={"invalid_clock":1}
    finally:lease.close();c.close();sys.excepthook=old

def test_leases_are_bounded_and_prior_handlers_keep_order():
    old=sys.excepthook;seen=[];sys.excepthook=lambda *args:seen.append("prior")
    import pytest
    c=init(config());leases=[install_hooks(c) for _ in range(8)]
    try:
        with pytest.raises(RuntimeError,match="hook lease limit"):install_hooks(c)
        c.close()
        sys.excepthook(ValueError,ValueError(),None)
        assert seen==["prior"] and not c.buffered_records()
    finally:
        for lease in leases:lease.close()
        sys.excepthook=old

def test_episode_arm_is_not_consumed_by_other_thread_or_mechanism():
    old=sys.excepthook;old_thread=threading.excepthook
    sys.excepthook=lambda *args:None;threading.excepthook=lambda args:None
    c=init(config());lease=install_hooks(c)
    try:
        error=ValueError("CANARY");episode=c.begin_handling_episode();first=episode.capture_exception(error)
        lease.use_episode(episode,error=error,mechanism="uncaught_exception",explicit_rethrow=True)
        def unrelated():
            sys.excepthook(TypeError,TypeError("CANARY"),None)
        thread=threading.Thread(target=unrelated);thread.start();thread.join()
        threading.excepthook(threading.ExceptHookArgs((TypeError,TypeError("CANARY"),None,threading.current_thread())))
        assert len(c.buffered_records())==3
        sys.excepthook(ValueError,error,None)
        records=list(map(json.loads,c.buffered_records()))
        assert len(records)==3 and records[0]["id"]==first
        assert len({record["id"] for record in records})==3
    finally:lease.close();c.close();sys.excepthook=old;threading.excepthook=old_thread

def test_nonweak_error_association_requires_explicit_context_and_weak_error_matches_identity():
    import pytest
    old=sys.excepthook;sys.excepthook=lambda *args:None
    c=init(config());lease=install_hooks(c)
    class WeakError(Exception):__slots__=("__weakref__",)
    try:
        with pytest.raises(ValueError,match="explicit_rethrow"):lease.use_episode(c.begin_handling_episode(),error=ValueError(),mechanism="uncaught_exception")
        error=WeakError();episode=c.begin_handling_episode();episode.capture_exception(error)
        lease.use_episode(episode,error=error,mechanism="uncaught_exception")
        with pytest.raises(ValueError,match="ambiguous"):lease.use_episode(c.begin_handling_episode(),error=error,mechanism="uncaught_exception")
        sys.excepthook(WeakError,WeakError(),None)
        assert len(c.buffered_records())==2
        sys.excepthook(WeakError,error,None)
        assert len(c.buffered_records())==2
    finally:lease.close();c.close();sys.excepthook=old

def test_asyncio_arm_matches_loop_task_and_skips_message_only_diagnostics():
    loop=asyncio.new_event_loop();loop.set_exception_handler(lambda *args:None)
    c=init(config());lease=install_hooks(c,loop=loop)
    async def idle():return None
    task=loop.create_task(idle());other=loop.create_task(idle())
    loop.run_until_complete(asyncio.gather(task,other))
    try:
        error=ValueError("CANARY");episode=c.begin_handling_episode();episode.capture_exception(error)
        lease.use_episode(episode,error=error,mechanism="asyncio_exception",task=task,explicit_rethrow=True)
        loop.call_exception_handler({"message":"CANARY"})
        loop.call_exception_handler({"exception":None,"message":"CANARY"})
        assert len(c.buffered_records())==1 and c.diagnostics()["asyncio_missing_exception"]==2
        loop.call_exception_handler({"exception":TypeError(),"future":other})
        assert len(c.buffered_records())==2
        loop.call_exception_handler({"exception":error,"future":task})
        assert len(c.buffered_records())==2
        assert json.loads(c.buffered_records()[1])["payload"]["fatal"] is False
    finally:lease.close();c.close();loop.close()

def test_fatal_comparator_rejects_reserved_safe_prefix_from_sdk_off_child():
    import importlib.util
    from pathlib import Path
    import pytest
    path=Path(__file__).resolve().parents[3]/"fixtures/sdk/hooks/compare_fatal.py"
    spec=importlib.util.spec_from_file_location("soundpost_fatal_comparator",path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    with pytest.raises(AssertionError,match="SDK-off"):
        module.run([sys.executable,"-c","print('SOUNDPOST_SAFE {}')"],"throw",False)

def test_armed_weak_exception_does_not_gain_a_strong_reference():
    import gc
    import weakref
    class WeakError(Exception):__slots__=("__weakref__",)
    c=init(config());lease=install_hooks(c)
    error=WeakError();reference=weakref.ref(error);episode=c.begin_handling_episode();episode.capture_exception(error)
    enabled=gc.isenabled();gc.disable()
    try:
        lease.use_episode(episode,error=error,mechanism="uncaught_exception")
        del error
        assert reference() is None
    finally:
        lease.clear_episode(episode);lease.close();c.close()
        if enabled:gc.enable()
