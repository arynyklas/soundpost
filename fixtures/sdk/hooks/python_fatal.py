# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
"""Real fatal fixture. SOUNDPOST_SAFE stdout is test-only local observation, not ACK."""
import asyncio
import json
import os
import sys
import threading
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[3]/"sdk/python/tests"))
from test_policy import config
from soundpost import init
from soundpost.hooks import install_hooks
client=None
mode=os.environ.get("SOUNDPOST_FATAL_MODE","throw")
def observe():
    if client is not None:
        print("SOUNDPOST_SAFE "+json.dumps({"records":client.buffered_records(),"diagnostics":client.diagnostics()}),flush=True)
def prior(cls,error,tb):
    print("PRIOR_GLOBAL",flush=True);observe();sys.__excepthook__(cls,error,tb)
def prior_thread(args):
    print("PRIOR_THREAD",flush=True);observe();threading.__excepthook__(args)
sys.excepthook=prior;threading.excepthook=prior_thread
loop=asyncio.new_event_loop()
def prior_async(loop,context):
    print("PRIOR_ASYNC",flush=True);observe();loop.default_exception_handler(context)
loop.set_exception_handler(prior_async)
lease=None
if "--sdk" in sys.argv:
    client=init(config());lease=install_hooks(client,loop=loop)
if mode=="closed" and lease is not None:lease.close();lease.close()
if mode=="replaced":
    def replacement(cls,error,tb):
        print("REPLACEMENT_GLOBAL",flush=True);observe();sys.__excepthook__(cls,error,tb)
    sys.excepthook=replacement
    if lease is not None:lease.close();lease.close()
error=ValueError("CANARY_NATIVE_FATAL_MESSAGE")
if mode=="episode" and client is not None:
    episode=client.begin_handling_episode();episode.capture_exception(error);lease.use_episode(episode,error=error,mechanism="uncaught_exception",explicit_rethrow=True)
def fail():raise error
if mode=="thread":
    thread=threading.Thread(target=fail,name="fixture-thread");thread.start();thread.join()
elif mode=="asyncio":
    async def task():raise error
    async def run():
        future=loop.create_task(task());await asyncio.sleep(0);del future
    loop.run_until_complete(run());loop.close()
else:fail()
