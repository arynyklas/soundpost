# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
"""Run-time preparation of the reference estate's volumes (compose service `init` and `handover`; root, no network).

  init.py init              the node's private TLS copy and data directory, and the web volume the build writes
  init.py handover UID GID  give the node's data directory to the operator (the acceptance smoke opens it in-process)

`init` copies ca.pem, leaf.pem and leaf.key of the run's TLS directory (/in) into the node's own volume (/out/tls-node): the key as a
0600 file of the node's own uid, because the node refuses a key anybody else can read. It makes /node-data the node's own private
(0700) directory again (recursively: after a handover the operator owns the files) and gives /web to the unprivileged uid the
applications run as. Nothing else is read or changed.
"""
import os
import shutil
import sys

APP_UID = 65534


def own(path, uid, gid, recursive=False):
    os.lchown(path, uid, gid)
    if recursive:
        for base, dirs, files in os.walk(path):
            for name in dirs + files:
                os.lchown(os.path.join(base, name), uid, gid)


def put(src, dst, mode):
    shutil.copyfile(src, dst)
    os.chown(dst, 0, 0)
    os.chmod(dst, mode)


def init():
    os.makedirs("/out/tls-node", exist_ok=True)
    for name, mode in (("ca.pem", 0o644), ("leaf.pem", 0o644), ("leaf.key", 0o600)):
        put(os.path.join("/in", name), os.path.join("/out/tls-node", name), mode)
    own("/node-data", 0, 0, recursive=True)
    os.chmod("/node-data", 0o700)
    own("/web", APP_UID, APP_UID)
    os.chmod("/web", 0o755)


def handover(uid, gid):
    own("/node-data", uid, gid, recursive=True)


def main(argv):
    mode = argv[1] if len(argv) > 1 else ""
    if mode == "init" and len(argv) == 2:
        init()
    elif mode == "handover" and len(argv) == 4:
        handover(int(argv[2]), int(argv[3]))
    else:
        sys.stderr.write("usage: init.py init | handover UID GID\n")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
