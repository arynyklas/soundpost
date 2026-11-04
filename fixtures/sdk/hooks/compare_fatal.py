# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
"""Compare actual child exits/output. Never mistake native baseline stderr for SDK bytes."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[3]
CANARY="CANARY_NATIVE_FATAL_MESSAGE"
def run(command,mode,enabled):
    env=os.environ.copy();env["SOUNDPOST_FATAL_MODE"]=mode
    completed=subprocess.run(command+(["--sdk"] if enabled else []),cwd=ROOT,env=env,capture_output=True,timeout=20)
    stdout=completed.stdout.decode("utf-8",errors="strict");safe=[];ordinary=[]
    for line in stdout.splitlines(keepends=True):
        if line.startswith("SOUNDPOST_SAFE "):
            assert enabled, "SDK-off child emitted reserved SOUNDPOST_SAFE prefix"
            data=line[len("SOUNDPOST_SAFE "):].strip()
            assert "CANARY" not in data and "SECRET" not in data, "SDK-owned bytes leaked canary"
            safe.append(json.loads(data))
        else:ordinary.append(line)
    return completed.returncode,"".join(ordinary),completed.stderr,safe

def qualify(runtime,command,modes):
    rows=[]
    for mode in modes:
        baseline=run(command,mode,False);owned=run(command,mode,True)
        assert not baseline[3], "SDK-off output must not contain SDK snapshots"
        assert baseline[:3]==owned[:3], f"{runtime}/{mode}: exit or native output changed: {baseline[:3]!r} != {owned[:3]!r}"
        if mode not in ("thread","asyncio","application-handler","capture-callback","episode-cross"):assert baseline[0]!=0, "fatal path did not exit"
        assert len(owned[3])==1, f"{runtime}/{mode}: missing test-only safe observation"
        snapshot=owned[3][0];records=snapshot["records"]
        expected=0 if runtime=="bun" or mode in ("closed","replaced","capture-failure") else 1
        if mode=="episode-cross":expected=2
        assert len(records)==expected, f"{runtime}/{mode}: expected {expected} actual safe captures, got {len(records)}"
        if runtime=="node" and mode in ("episode","episode-callback","episode-cross"):
            expected_origin="unhandledRejection" if mode=="episode" else "uncaughtException"
            assert snapshot["monitor_origin"]==expected_origin, "fixture armed wrong native monitor source"
            assert snapshot["matches_episode_error"] is True, "native monitor changed the original error identity"
        if mode=="episode-cross":
            payloads=[json.loads(record)["payload"] for record in records]
            assert [payload["exception_class"] for payload in payloads]==["TypeError","RangeError"], "unrelated failure consumed the intended episode"
            assert payloads[0]["handled"] is True and payloads[1]["mechanism"]=="uncaught_exception"
        if mode=="capture-failure":assert snapshot["diagnostics"]=={"invalid_clock":1}
        for record in records:
            payload=json.loads(record)["payload"]
            assert payload["exception_class"] in ("ValueError","TypeError","RangeError")
            assert payload["mechanism"] in ("manual","uncaught_exception","unhandled_rejection","thread_exception","asyncio_exception")
            if mode not in ("episode","episode-callback","episode-cross","thread","asyncio"):assert payload["fatal"] is True
        if runtime=="bun":assert snapshot["capabilities"]["reason"]=="bun_fatal_monitor_unavailable"
        rows.append({"runtime":runtime,"mode":mode,"exit":owned[0],"safe_captures":len(records),"sdk_canaries":0,"native_stderr_canary":CANARY.encode() in baseline[2]})
    return rows

def main():
    parser=argparse.ArgumentParser();parser.add_argument("--python",default=sys.executable);parser.add_argument("--node");parser.add_argument("--node-fixture");parser.add_argument("--bun");args=parser.parse_args()
    rows=qualify("python",[args.python,str(ROOT/"fixtures/sdk/hooks/python_fatal.py")],["throw","episode","closed","replaced","thread","asyncio"])
    if args.node:
        if not args.node_fixture:parser.error("--node requires --node-fixture bundled local .mjs artifact")
        rows+=qualify("node",[args.node,"--unhandled-rejections=strict",args.node_fixture],["throw","rejection","episode","episode-callback","episode-cross","closed","replaced","application-handler","capture-callback","capture-failure"])
    if args.bun:rows+=qualify("bun",[args.bun,str(ROOT/"fixtures/sdk/hooks/bun-fatal.ts")],["throw","rejection","closed"])
    print(json.dumps(rows,sort_keys=True))
if __name__=="__main__":main()
