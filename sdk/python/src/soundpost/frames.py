# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
"""Code identities only: never inspect source, frame locals or globals."""
import os
import re
import types

def project_frame(tb: types.TracebackType, root: str | None):
    if root is None: return None
    frame=types.TracebackType.tb_frame.__get__(tb)
    code=types.FrameType.f_code.__get__(frame)
    filename=types.CodeType.co_filename.__get__(code)
    function=types.CodeType.co_name.__get__(code)
    if type(filename) is not str or type(function) is not str:return None
    # These intrinsic code fields are exact strings; no user conversion occurs.
    filename=os.path.normpath(filename)
    try:
        if os.path.commonpath((root,filename)) != root: return None
        relative=os.path.relpath(filename,root).replace("\\","/")
    except ValueError: return None
    if not re.fullmatch(r"[A-Za-z0-9_./-]{1,256}",relative) or any(p in ("", "..", ".") for p in relative.split("/")): return None
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}|<module>|<lambda>",function): function="unknown"
    line=types.TracebackType.tb_lineno.__get__(tb)
    if type(line) is not int or line<1:return None
    return {"artifact_id":relative,"module_id":relative,"function":function,"line":line,"column":None,"in_app":True,"async":bool(types.CodeType.co_flags.__get__(code)&(0x80|0x200))}

def normalize_root(root: str | None):
    if root is None:return None
    if type(root) is not str or not os.path.isabs(root) or "\x00" in root:raise ValueError("project_root must be absolute")
    return os.path.normpath(root)
