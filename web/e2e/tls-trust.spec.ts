// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import {execFileSync} from 'node:child_process';
import {mkdtempSync,readFileSync,rmSync} from 'node:fs';
import {createServer,type Server} from 'node:https';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {test,expect} from '@playwright/test';

// Certificate verification is on in every browser of the matrix (10.19#10). The project configuration never sets ignoreHTTPSErrors; the browser reaches
// the run's HTTPS origin because it trusts the private CA this run generated (Firefox through the enterprise policy and WebKit through the trust namespace
// of web/e2e-harness/h.sh, Chromium through the leaf's SPKI pin), and it refuses a server whose certificate chains to any other CA. The second test is the
// proof that the first one is not a browser that accepts everything: the very same server loads when verification is switched off for one context, so the
// refusal is the trust check and nothing else. Error texts are the browsers' own: Chromium net::ERR_CERT_AUTHORITY_INVALID, Firefox SEC_ERROR_UNKNOWN_ISSUER,
// WebKit "Unacceptable TLS certificate".

const REFUSED=/ERR_CERT_AUTHORITY_INVALID|SEC_ERROR_UNKNOWN_ISSUER|Unacceptable TLS certificate/;

test('the run origin loads with certificate verification on and no ignoreHTTPSErrors',async({page},testInfo)=>{
  expect(testInfo.project.use.ignoreHTTPSErrors??false).toBe(false);
  const response=await page.goto('/readyz');
  expect(response?.status()).toBe(200);
  expect(new URL(page.url()).protocol).toBe('https:');
});

test.describe('a certificate from a CA the browser was never given',()=>{
  let dir:string,server:Server,origin:string;
  test.beforeAll(async()=>{
    dir=mkdtempSync(join(tmpdir(),'e2e-untrusted-'));
    const openssl=(...args:string[]):void=>{execFileSync('openssl',args,{cwd:dir,stdio:'ignore'});};
    openssl('req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:prime256v1','-nodes','-keyout','ca.key','-out','ca.pem','-days','2','-subj','/CN=Soundpost e2e untrusted CA','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign');
    openssl('req','-newkey','ec','-pkeyopt','ec_paramgen_curve:prime256v1','-nodes','-keyout','leaf.key','-out','leaf.csr','-subj','/CN=localhost');
    execFileSync('sh',['-c','printf "subjectAltName=DNS:localhost,IP:127.0.0.1\\nextendedKeyUsage=serverAuth\\nbasicConstraints=CA:FALSE\\nkeyUsage=digitalSignature\\n" >ext.cnf'],{cwd:dir});
    openssl('x509','-req','-in','leaf.csr','-CA','ca.pem','-CAkey','ca.key','-CAcreateserial','-out','leaf.pem','-days','2','-extfile','ext.cnf');
    server=createServer({key:readFileSync(join(dir,'leaf.key')),cert:readFileSync(join(dir,'leaf.pem'))},(_request,response)=>{response.writeHead(200,{'content-type':'text/html'});response.end('<title>untrusted-origin</title>reachable');});
    await new Promise<void>(resolve=>server.listen(0,'127.0.0.1',resolve));
    const address=server.address();
    origin='https://127.0.0.1:'+(typeof address==='object'&&address?address.port:0);
  });
  test.afterAll(async()=>{
    await new Promise<void>(resolve=>server.close(()=>resolve()));
    rmSync(dir,{recursive:true,force:true});
  });

  test('is refused, and the same server loads once verification is switched off, so the refusal is the trust check',async({page,browser})=>{
    await expect(page.goto(origin+'/')).rejects.toThrow(REFUSED);
    const lax=await browser.newContext({ignoreHTTPSErrors:true});
    try{
      const control=await lax.newPage();
      const response=await control.goto(origin+'/');
      expect(response?.status()).toBe(200);
      await expect(control).toHaveTitle('untrusted-origin');
    }finally{await lax.close();}
  });
});
