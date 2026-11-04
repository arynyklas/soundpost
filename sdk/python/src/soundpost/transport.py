# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
from dataclasses import dataclass
from typing import Protocol
import contextvars
import http.client
import json
import ssl
import threading
import time
from email.utils import parsedate_to_datetime
from urllib.parse import urlsplit
from .policy import canonical_id, decimal, unix_nano, pairs
from .routing import native_canonical
EXPORTING=contextvars.ContextVar('soundpost_exporting',default=False)
@dataclass(frozen=True)
class FrozenBatch:
    id: str
    source: str
    producer: str
    route_slot: int
    hash: str
    body: bytes
    count: int
    kinds: tuple[str,...]
    first_capture: float
    policy_revision: str
@dataclass(frozen=True)
class Outcome:
    kind: str
    receipt: dict | None = None
    retry_after: float | None = None
class ReceiptTransport(Protocol):
    def send(self,batch:FrozenBatch,deadline:float)->Outcome:...
    def lookup(self,batch:FrozenBatch,deadline:float)->Outcome:...
    def close(self)->None:...

def verify_receipt(batch,value,historical):
    try:
        if type(value) is not dict or value['version']!=1 or type(value['version']) is not int or value['batch_id']!=batch.id or value['hash']!=batch.hash:return False
        if (value.get('historical') is not True) if historical else ('historical' in value):return False
        canonical_id(value['batch_id']);canonical_id(value['cursor']['group'])
        if decimal(value['cursor']['index'])=='0':return False
        minimum=int(unix_nano(value['retain_until_ns']));unix_nano(value['dedup_until_ns'])
        deadlines=value['signal_deadlines']
        if type(deadlines) is not list or len(deadlines)!=len(batch.kinds):return False
        seen=set();values=[]
        for item in deadlines:
            kind=item['kind']
            if kind not in batch.kinds or kind in seen:return False
            seen.add(kind);values.append(int(unix_nano(item['retain_until_ns'])))
        return bool(values) and min(values)==minimum
    except (ValueError,TypeError,KeyError):return False

def retry_after(value,now=None):
    if value is None:return None
    try:delay=int(value) if value.isdecimal() else parsedate_to_datetime(value).timestamp()-(time.time() if now is None else now)
    except (ValueError,TypeError,OverflowError):return None
    return min(30,max(.25,delay))

class HttpsReceiptTransport:
    """No cookie jar, redirects, ambient credentials or TLS verification bypass."""
    def __init__(self,config):
        endpoint=urlsplit(config.endpoint)
        if endpoint.scheme!='https' or not endpoint.hostname or endpoint.username or endpoint.password or endpoint.query or endpoint.fragment or endpoint.path!='/ingest/v1/batches':raise ValueError('HTTPS ingestion endpoint required')
        if type(config.credential) is not str or not config.credential or any(c.isspace() for c in config.credential):raise ValueError('invalid source credential')
        if config.source_class!='private':raise ValueError('Python requires a private source')
        self._endpoint=endpoint;self._context=ssl.create_default_context(cafile=config.ca_file)
        self._headers={'Content-Type':'application/json','Authorization':'Bearer '+config.credential}
        self._lock=threading.Lock();self._connections=set();self._closed=False
    def _post(self,path,body,deadline,lookup):
        remaining=deadline-time.monotonic()
        if remaining<=0:return Outcome('ambiguous')
        connection=http.client.HTTPSConnection(self._endpoint.hostname,self._endpoint.port or 443,context=self._context,timeout=remaining)
        with self._lock:
            if self._closed:return Outcome('denied')
            self._connections.add(connection)
        token=EXPORTING.set(True);response=None
        try:
            connection.request('POST',path,body=body,headers=self._headers)
            response=connection.getresponse()
            if response.status in (401,403):return Outcome('denied')
            if lookup and response.status==404:return Outcome('not_found')
            if response.status in (429,503):return Outcome('retryable',retry_after=retry_after(response.getheader('Retry-After')))
            if response.status!=200:return Outcome('terminal')
            # Total deadline remains authoritative even when a peer trickles bytes.
            raw=bytearray()
            while len(raw)<=65536:
                remaining=deadline-time.monotonic()
                if remaining<=0:return Outcome('ambiguous')
                if connection.sock is not None:connection.sock.settimeout(remaining)
                part=response.read1(min(4096,65537-len(raw)))
                if not part:break
                raw.extend(part)
            if len(raw)>65536:return Outcome('invalid')
            try:
                receipt=json.loads(raw.decode('utf-8'),object_pairs_hook=pairs,parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
                native_canonical(receipt)
            except (ValueError,UnicodeError):return Outcome('invalid')
            return Outcome('receipt',receipt) if type(receipt) is dict else Outcome('invalid')
        except (OSError,http.client.HTTPException,ValueError):return Outcome('ambiguous')
        finally:
            EXPORTING.reset(token)
            try:
                if response is not None:response.close()
            finally:
                try:connection.close()
                finally:
                    with self._lock:self._connections.discard(connection)
    def send(self,batch,deadline):return self._post('/ingest/v1/batches',batch.body,deadline,False)
    def lookup(self,batch,deadline):return self._post('/ingest/v1/receipts',native_canonical(dict(source=batch.source,producer=batch.producer,route_slot=batch.route_slot,batch_id=batch.id,original_hash=batch.hash)),deadline,True)
    def close(self):
        with self._lock:
            self._closed=True
            for connection in self._connections:connection.close()
            self._connections.clear()
