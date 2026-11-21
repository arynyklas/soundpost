# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
"""Code identities only: never inspect source, frame locals or globals."""
import functools
import os
import re
import types

@functools.lru_cache(maxsize=4096)
def _real(path: str) -> str:
    # A root and a code file may name one directory by different paths (symlink, junction,
    # mapped drive, a resolved Path); both sides are compared as real paths. Cached: code file
    # names are a small fixed set per process.
    try:return os.path.normpath(os.path.realpath(path))
    except (OSError, ValueError):return os.path.normpath(path)

def project_frame(tb: types.TracebackType, root: str | None):
    if root is None: return None
    frame=types.TracebackType.tb_frame.__get__(tb)
    code=types.FrameType.f_code.__get__(frame)
    filename=types.CodeType.co_filename.__get__(code)
    function=types.CodeType.co_name.__get__(code)
    if type(filename) is not str or type(function) is not str or "\x00" in filename:return None
    # These intrinsic code fields are exact strings; no user conversion occurs.
    filename=_real(filename)
    try:
        if os.path.normcase(os.path.commonpath((root,filename))) != os.path.normcase(root): return None
        relative=os.path.relpath(filename,root).replace("\\","/")
    except ValueError: return None
    # A virtualenv inside the project holds third-party code: installed packages are never
    # the project's own frames.
    if any(p in ("site-packages", "dist-packages") for p in relative.split("/")): return None
    if not re.fullmatch(r"[A-Za-z0-9_./-]{1,256}",relative) or any(p in ("", "..", ".") for p in relative.split("/")): return None
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}|<module>|<lambda>",function): function="unknown"
    line=types.TracebackType.tb_lineno.__get__(tb)
    if type(line) is not int or line<1:return None
    return {"artifact_id":relative,"module_id":relative,"function":function,"line":line,"column":None,"in_app":True,"async":bool(types.CodeType.co_flags.__get__(code)&(0x80|0x200))}

def normalize_root(root: str | None):
    if root is None:return None
    if type(root) is not str or not os.path.isabs(root) or "\x00" in root:raise ValueError("project_root must be absolute")
    return _real(root)
