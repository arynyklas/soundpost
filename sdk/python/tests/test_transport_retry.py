# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
"""Real local TLS ingestion server: 429/503 + Retry-After retry, 200 receipt ACK, 401/403 denial.

TLS verification stays ON: a throwaway CA signs the server certificate and is passed as Config.ca_file.
"""
import ipaddress
import datetime
import hashlib
import json
import ssl
import threading
import time
from email.utils import formatdate
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
import pytest
from test_delivery import settings, record, receipt
from soundpost.queue import DeliveryQueue
from soundpost.transport import HttpsReceiptTransport, retry_after

def _name(common):return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,common)])
def _pem(cert):return cert.public_bytes(serialization.Encoding.PEM)

def _pki(directory):
    now=datetime.datetime.now(datetime.timezone.utc);span=datetime.timedelta(days=1)
    ca_key=ec.generate_private_key(ec.SECP256R1());ca_name=_name('soundpost test ca')
    ca=(x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now-span).not_valid_after(now+span).add_extension(x509.BasicConstraints(ca=True,path_length=None),critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True,key_cert_sign=True,crl_sign=True,content_commitment=False,key_encipherment=False,data_encipherment=False,key_agreement=False,encipher_only=False,decipher_only=False),critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),critical=False).sign(ca_key,hashes.SHA256()))
    key=ec.generate_private_key(ec.SECP256R1())
    leaf=(x509.CertificateBuilder().subject_name(_name('localhost')).issuer_name(ca_name).public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now-span).not_valid_after(now+span).add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]),critical=False)
        .add_extension(x509.BasicConstraints(ca=False,path_length=None),critical=True)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),critical=False).sign(ca_key,hashes.SHA256()))
    paths=[directory/'ca.pem',directory/'server.pem',directory/'server.key']
    paths[0].write_bytes(_pem(ca));paths[1].write_bytes(_pem(leaf))
    paths[2].write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    return [str(p) for p in paths]

class Ingest:
    """Scripted HTTPS server: each POST pops the next (status, headers) step; 200 returns a valid receipt for the posted bytes."""
    def __init__(self,directory):
        ca,cert,key=_pki(directory);self.ca=ca;self.script=[];self.requests=[];lock=threading.Lock();owner=self
        class Handler(BaseHTTPRequestHandler):
            protocol_version='HTTP/1.1'
            def log_message(self,*args):pass
            def do_POST(self):
                body=self.rfile.read(int(self.headers['Content-Length']))
                with lock:
                    owner.requests.append(dict(path=self.path,auth=self.headers['Authorization'],body=body,at=time.monotonic()))
                    status,headers=owner.script.pop(0)
                payload=b''
                if status==200:
                    wire=json.loads(body);payload=json.dumps({'version':1,'batch_id':wire['id'],'hash':hashlib.sha256(body).hexdigest(),'cursor':{'group':'9'*32,'index':'9007199254740993'},'retain_until_ns':'9007199254740994','signal_deadlines':[{'kind':k,'retain_until_ns':'9007199254740994'} for k in sorted({r['kind'] for r in wire['records']})],'dedup_until_ns':'9007199254740995'}).encode()
                self.send_response(status)
                for name,value in headers.items():self.send_header(name,value)
                self.send_header('Content-Length',str(len(payload)));self.end_headers();self.wfile.write(payload)
        self.server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(cert,key)
        self.server.socket=context.wrap_socket(self.server.socket,server_side=True)
        self.endpoint=f'https://127.0.0.1:{self.server.server_address[1]}/ingest/v1/batches'
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
    def close(self):self.server.shutdown();self.server.server_close();self.thread.join(5)

@pytest.fixture
def ingest(tmp_path):
    server=Ingest(tmp_path)
    try:yield server
    finally:server.close()

def delivery(server):
    config=settings(endpoint=server.endpoint,ca_file=server.ca,transport=None)
    return DeliveryQueue(config,HttpsReceiptTransport(config),random_value=lambda:0)

def test_unverifiable_certificate_is_not_retryable_acknowledged_or_bypassed(ingest):
    """Control: without the throwaway CA the real transport must fail verification, so the later tests prove verification stays on."""
    ingest.script=[(200,{})]
    config=settings(endpoint=ingest.endpoint,transport=None);q=DeliveryQueue(config,HttpsReceiptTransport(config),random_value=lambda:0)
    q.enqueue(record());report=q.flush(.5)
    assert report.pending==1 and report.acknowledged_batch_ids==() and not ingest.requests

@pytest.mark.parametrize('status',[429,503])
def test_429_503_stay_pending_then_same_frozen_batch_is_acked(ingest,status):
    ingest.script=[(status,{'Retry-After':'0'}),(status,{}),(200,{})]
    q=delivery(ingest);q.enqueue(record());frozen=q.freeze()
    first=q.flush(.1)
    assert first.pending==1 and first.acknowledged_batch_ids==() and q.lost==0 and len(ingest.requests)==1
    report=q.flush(5)
    assert report.pending==0 and q.lost==0 and report.acknowledged_batch_ids==(frozen[0].id,)
    assert len(ingest.requests)==3 and {r['path'] for r in ingest.requests}=={'/ingest/v1/batches'}
    assert {r['body'] for r in ingest.requests}=={frozen[0].body}
    assert hashlib.sha256(ingest.requests[-1]['body']).hexdigest()==frozen[0].hash==report.receipts[0]['hash']
    assert q.diagnostics().get('unauthorized') is None

def test_retry_after_seconds_is_honored_between_attempts(ingest):
    ingest.script=[(503,{'Retry-After':'1'}),(200,{})]
    q=delivery(ingest);q.enqueue(record());report=q.flush(5)
    assert report.pending==0 and len(ingest.requests)==2
    assert ingest.requests[1]['at']-ingest.requests[0]['at']>=.95

def test_retry_after_http_date_is_honored_between_attempts(ingest):
    ingest.script=[(429,{'Retry-After':formatdate(time.time()+2,usegmt=True)}),(200,{})]
    q=delivery(ingest);q.enqueue(record());report=q.flush(6)
    assert report.pending==0 and len(ingest.requests)==2
    assert ingest.requests[1]['at']-ingest.requests[0]['at']>=.9

@pytest.mark.parametrize('header',['999999',formatdate(time.time()+86400,usegmt=True)])
def test_huge_retry_after_is_clamped_to_30_seconds_and_batch_is_retained(ingest,header):
    ingest.script=[(429,{'Retry-After':header})]
    q=delivery(ingest);q.enqueue(record());report=q.flush(.2)
    assert report.pending==1 and q.lost==0 and len(ingest.requests)==1
    wait=q._batches[0]['next']-q.now()
    assert 29<wait<=30.01
    assert q.flush(.01).pending==1 and len(ingest.requests)==1

def test_retry_after_parsing_bounds_and_malformed_values():
    assert retry_after(None) is None
    assert retry_after('0')==.25 and retry_after('1')==1 and retry_after('999999')==30
    assert retry_after('garbage') is None and retry_after('-5') is None and retry_after('') is None
    assert retry_after('Wed, 21 Oct 2015 07:28:00 GMT',now=0)==30
    assert retry_after('Wed, 21 Oct 2015 07:28:00 GMT',now=1445412480-10)==10
    assert retry_after('Wed, 21 Oct 2015 07:28:00 GMT',now=1445412480+100)==.25

@pytest.mark.parametrize('status',[401,403])
def test_401_403_are_denied_not_retryable_and_stop_export(ingest,status):
    ingest.script=[(status,{'Retry-After':'0'}),(200,{})]
    q=delivery(ingest);q.enqueue(record());report=q.flush(1)
    assert report.pending==1 and report.acknowledged_batch_ids==() and q.diagnostics()['unauthorized']==1
    time.sleep(.4);q.flush(.5)
    assert len(ingest.requests)==1 and len(ingest.script)==1
    assert ingest.requests[0]['auth']=='Bearer SECRET'
