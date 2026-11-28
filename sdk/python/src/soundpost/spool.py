# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
import json
import os
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .routing import native_canonical,validate_descriptor
from .policy import decimal
class EncryptedSpool:
    """Explicit backend-only AES-256-GCM spool; no disk is touched unless constructed.

    The caller supplies an installation-protected 32-byte key. An exclusive OS
    advisory lock survives no process crash; a stale pathname is never ownership.
    """
    def __init__(self,path,key,descriptor,policy_revision,max_bytes=2097152):
        if type(key) is not bytes or len(key)!=32 or type(max_bytes) is not int or not 64<=max_bytes<=16777216:raise ValueError('invalid spool configuration')
        d=validate_descriptor(descriptor);decimal(policy_revision)
        self.path=Path(path);self._cipher=AESGCM(key);self.max_bytes=max_bytes;self._lock_file=None;self._closed=False
        self._aad=native_canonical(dict(version=1,org=d.org,project=d.project,source=d.source,routing_version=d.routing_version,slots=d.slots,policy_revision=policy_revision))
    def assert_binding(self,descriptor,revision):
        d=validate_descriptor(descriptor)
        if self._aad!=native_canonical(dict(version=1,org=d.org,project=d.project,source=d.source,routing_version=d.routing_version,slots=d.slots,policy_revision=revision)):raise ValueError('spool policy binding mismatch')
    def _lease(self):
        if self._closed:raise ValueError('spool closed')
        if self._lock_file is not None:return
        self.path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        flags=os.O_RDWR|os.O_CREAT|getattr(os,'O_NOFOLLOW',0)
        fd=os.open(str(self.path)+'.lock',flags,0o600);stream=os.fdopen(fd,'r+b',buffering=0)
        try:
            if os.name=='nt':
                import msvcrt
                if os.fstat(fd).st_size==0:stream.write(b'\0')
                stream.seek(0);msvcrt.locking(fd,msvcrt.LK_NBLCK,1)
            else:
                import fcntl
                fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except OSError:stream.close();raise OSError('spool lease unavailable') from None
        self._lock_file=stream
    def load(self):
        self._lease()
        try:
            fd=os.open(self.path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
        except FileNotFoundError:return None
        try:
            with os.fdopen(fd,'rb') as stream:raw=stream.read(self.max_bytes+1)
            if len(raw)>self.max_bytes or len(raw)<37 or raw[:5]!=b'SPQS2':raise ValueError()
            size=int.from_bytes(raw[5:9],'big')
            if size>4096 or len(raw)<size+37:raise ValueError()
            header=raw[9:9+size];stored=json.loads(header);current=json.loads(self._aad);decimal(stored['policy_revision'])
            if type(stored) is not dict or stored.keys()!=current.keys() or any(stored[k]!=current[k] for k in current if k!='policy_revision'):raise ValueError()
            plain=self._cipher.decrypt(raw[9+size:21+size],raw[21+size:],header)
            return json.loads(plain)
        except Exception:
            self.close();raise ValueError('spool authentication or corruption failure') from None
    def save(self,value):
        self._lease();plain=native_canonical(value)
        if len(plain)+37+len(self._aad)>self.max_bytes:raise OSError('spool capacity exceeded')
        nonce=os.urandom(12);raw=b'SPQS2'+len(self._aad).to_bytes(4,'big')+self._aad+nonce+self._cipher.encrypt(nonce,plain,self._aad)
        temp=Path(str(self.path)+'.'+os.urandom(16).hex()+'.tmp');fd=None
        try:
            fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
            with os.fdopen(fd,'wb') as stream:
                fd=None;stream.write(raw);stream.flush();os.fsync(stream.fileno())
            os.replace(temp,self.path)
            if os.name!='nt':
                directory=os.open(self.path.parent,os.O_RDONLY|getattr(os,'O_DIRECTORY',0))
                try:os.fsync(directory)
                finally:os.close(directory)
        except OSError:raise OSError('spool write failed') from None
        finally:
            if fd is not None:os.close(fd)
            try:temp.unlink()
            except FileNotFoundError:pass
    def close(self):
        if self._closed:return
        self._closed=True
        if self._lock_file is not None:
            stream=self._lock_file;self._lock_file=None
            if os.name=='nt':
                import msvcrt
                stream.seek(0);msvcrt.locking(stream.fileno(),msvcrt.LK_UNLCK,1)
            else:
                import fcntl
                fcntl.flock(stream.fileno(),fcntl.LOCK_UN)
            stream.close()
