// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import {test,expect} from '@playwright/test';
import {createHmac} from 'node:crypto';
const email=process.env.SOUNDPOST_TEST_EMAIL;
const password=process.env.SOUNDPOST_TEST_PASSWORD;
if(!email||!password)throw new Error('Real provisioned SOUNDPOST_TEST_EMAIL and SOUNDPOST_TEST_PASSWORD are required');
const org=process.env.SOUNDPOST_TEST_ORG;
const provider=process.env.SOUNDPOST_TEST_PROVIDER;
if(!org||!provider)throw new Error('Real configured OIDC organization/provider IDs required');
test.describe.configure({mode:'serial'});
test('real local password, rotation, TOTP, one-use recovery and logout',async({page,context})=>{
 test.setTimeout(60_000);
 await page.goto('/');await page.getByLabel('Email',{exact:true}).fill(email);await page.getByLabel('Password',{exact:true}).fill(password);await page.getByRole('button',{name:'Sign in',exact:true}).click();await expect(page.getByRole('heading',{name:'Account access',exact:true})).toBeVisible();
 const before=(await context.cookies()).find(cookie=>cookie.name==='__Host-soundpost');expect(before?.httpOnly).toBe(true);expect(before?.secure).toBe(true);expect(before?.sameSite).toBe('Strict');
 await page.getByRole('button',{name:'Start authenticator enrollment'}).click();const secret=await page.locator('output.secret').textContent();expect(secret).toBeTruthy();
 // Use the real authority's HTTP clock: the driver and server may be different OSes.
 const authorityTime=async():Promise<number>=>{const response=await page.request.get('/api/v1/session');expect(response.ok()).toBe(true);const header=response.headers().date;if(!header)throw Error('Authority time unavailable');const stamp=Date.parse(header);if(!Number.isFinite(stamp))throw Error('Authority time invalid');return stamp;};
 await expect.poll(async()=>{const phase=(await authorityTime())%30_000;return phase>=5_000&&phase<=10_000;},{timeout:31_000,intervals:[250]}).toBe(true);
 const alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';let bits='';for(const char of secret??'')bits+=alphabet.indexOf(char).toString(2).padStart(5,'0');const key=Buffer.from(bits.match(/.{8}/g)?.map(byte=>parseInt(byte,2))??[]);const counter=Buffer.alloc(8);counter.writeBigUInt64BE(BigInt(Math.floor((await authorityTime())/30000)));const hash=createHmac('sha1',key).update(counter).digest();const offset=hash[hash.length-1]!&15;const code=String((hash.readUInt32BE(offset)&0x7fffffff)%1000000).padStart(6,'0');
 await page.getByLabel('Authenticator code',{exact:true}).fill(code);await page.getByRole('button',{name:'Confirm authenticator',exact:true}).click();await expect(page.getByRole('heading',{name:'Save these one-use recovery codes now'})).toBeVisible();const recovery=await page.locator('section').filter({has:page.getByRole('heading',{name:'Save these one-use recovery codes now'})}).last().locator('li code').first().textContent();expect(recovery).toBeTruthy();
 await page.getByRole('button',{name:'Sign out',exact:true}).click();await expect(page.getByRole('heading',{name:'Access your installation'})).toBeVisible();
 await page.getByLabel('Email',{exact:true}).fill(email);await page.getByLabel('Password',{exact:true}).fill(password);await page.getByLabel('Authenticator or recovery code').fill(recovery!);await page.getByRole('button',{name:'Sign in',exact:true}).click();await expect(page.getByRole('heading',{name:'Account access',exact:true})).toBeVisible();
 const rotated=(await context.cookies()).find(cookie=>cookie.name==='__Host-soundpost');expect(rotated?.value).not.toBe(before?.value);
 expect(await page.evaluate(()=>({local:Object.keys(localStorage),session:Object.keys(sessionStorage)}))).toEqual({local:[],session:[]});
 await page.getByRole('button',{name:'Sign out',exact:true}).click();expect((await page.request.get('/api/v1/session')).status()).toBe(401);
 await page.getByLabel('Email',{exact:true}).fill(email);await page.getByLabel('Password',{exact:true}).fill(password);await page.getByLabel('Authenticator or recovery code').fill(recovery!);await page.getByRole('button',{name:'Sign in',exact:true}).click();await expect(page.getByRole('alert')).toBeVisible();
});
for(const identity of ['mapped','unmapped','wrong-issuer'] as const)test(`real OIDC Code+PKCE ${identity}`,async({page})=>{
 await page.goto('/');await page.getByRole('button',{name:'Single sign-on',exact:true}).click();await page.getByLabel('Organization ID',{exact:true}).fill(org);await page.getByLabel('Provider ID',{exact:true}).fill(provider);await page.getByRole('button',{name:'Continue to provider'}).click();await expect(page.getByRole('heading',{name:'Local identity provider'})).toBeVisible();const authorization=new URL(page.url());expect(authorization.searchParams.get('code_challenge_method')).toBe('S256');expect(authorization.searchParams.get('nonce')).toBeTruthy();await page.getByLabel('Fixture identity').selectOption(identity);await page.getByRole('button',{name:'Authorize fixture account'}).click();
 if(identity==='mapped'){await expect(page.getByRole('heading',{name:'Account access',exact:true})).toBeVisible();expect(new URL(page.url()).search).toBe('');await page.getByRole('button',{name:'Sign out',exact:true}).click();}else{expect((await page.request.get('/api/v1/session')).status()).toBe(401);}
});
