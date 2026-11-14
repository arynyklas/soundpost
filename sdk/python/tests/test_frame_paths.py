# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
"""A project root and the code's file names may name the same directory by different
paths (a symlink, a Windows junction or mapped drive, a resolved Path). Frames under
the project must still be recognised as the project's own."""
import os
import subprocess
import sys
import types

import pytest

from soundpost.frames import normalize_root, project_frame


def _alias(real, alias):
    if sys.platform == "win32":
        r = subprocess.run(["cmd", "/c", "mklink", "/J", alias, real], capture_output=True)
        if r.returncode != 0:
            pytest.skip("cannot create a junction here")
    else:
        os.symlink(real, alias)


def _traceback_from(path):
    code = compile("def handler():\n    raise ValueError('x')\n", path, "exec")
    ns = {}
    exec(code, ns)
    try:
        ns["handler"]()
    except ValueError as e:
        tb = e.__traceback__
        while tb.tb_next is not None:
            tb = tb.tb_next
        return tb


@pytest.mark.parametrize("root_is_alias", [True, False])
def test_frames_under_an_aliased_project_root_are_the_projects(tmp_path, root_is_alias):
    real = tmp_path / "real"
    (real / "app").mkdir(parents=True)
    alias = tmp_path / "alias"
    _alias(str(real), str(alias))
    code_root, project_root = (real, alias) if root_is_alias else (alias, real)
    tb = _traceback_from(str(code_root / "app" / "handlers.py"))
    frame = project_frame(tb, normalize_root(str(project_root)))
    assert frame is not None, "an in-project frame was dropped because the root is another path to the same directory"
    assert frame["artifact_id"] == "app/handlers.py"
    assert frame["function"] == "handler"


def test_frames_outside_the_project_stay_out(tmp_path):
    (tmp_path / "proj").mkdir()
    (tmp_path / "lib").mkdir()
    tb = _traceback_from(str(tmp_path / "lib" / "x.py"))
    assert project_frame(tb, normalize_root(str(tmp_path / "proj"))) is None


def test_installed_packages_inside_the_project_are_not_project_frames(tmp_path):
    pkg = tmp_path / ".venv" / "Lib" / "site-packages" / "framework"
    pkg.mkdir(parents=True)
    tb = _traceback_from(str(pkg / "routes.py"))
    assert project_frame(tb, normalize_root(str(tmp_path))) is None
