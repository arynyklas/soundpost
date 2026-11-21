// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import {test,expect,type Locator,type Page,type TestInfo} from '@playwright/test';
import {createHmac} from 'node:crypto';
import {mkdirSync,writeFileSync} from 'node:fs';
import {focusIndicated,type Stop} from './support/audit';
const email=process.env.SOUNDPOST_TEST_EMAIL;
const password=process.env.SOUNDPOST_TEST_PASSWORD;
if(!email||!password)throw new Error('Real provisioned SOUNDPOST_TEST_EMAIL and SOUNDPOST_TEST_PASSWORD are required');
const org=process.env.SOUNDPOST_TEST_ORG;
const provider=process.env.SOUNDPOST_TEST_PROVIDER;
if(!org||!provider)throw new Error('Real configured OIDC organization/provider IDs required');
test.describe.configure({mode:'serial'});
// The real authority's HTTP clock: the driver and server may be different OSes.
async function authorityTime(page:Page):Promise<number>{const response=await page.request.get('/api/v1/session');expect(response.ok()).toBe(true);const header=response.headers().date;if(!header)throw Error('Authority time unavailable');const stamp=Date.parse(header);if(!Number.isFinite(stamp))throw Error('Authority time invalid');return stamp;}
async function currentTotp(page:Page,secret:string):Promise<string>{
 await expect.poll(async()=>{const phase=(await authorityTime(page))%30_000;return phase>=5_000&&phase<=10_000;},{timeout:31_000,intervals:[250]}).toBe(true);
 const alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';let bits='';for(const char of secret)bits+=alphabet.indexOf(char).toString(2).padStart(5,'0');const key=Buffer.from(bits.match(/.{8}/g)?.map(byte=>parseInt(byte,2))??[]);const counter=Buffer.alloc(8);counter.writeBigUInt64BE(BigInt(Math.floor((await authorityTime(page))/30000)));const hash=createHmac('sha1',key).update(counter).digest();const offset=hash[hash.length-1]!&15;
 return String((hash.readUInt32BE(offset)&0x7fffffff)%1000000).padStart(6,'0');
}
// Keyboard-only driver: nothing below clicks, hovers or fills; focus moves with real Tab presses, text is typed with the keyboard and controls
// are activated with Enter. Every control the user lands on must show a visible focus ring (computed by the browser on the focused element).
async function tabTo(page:Page,target:Locator,landed:Stop[],fromTop=false,limit=40):Promise<void>{
 // Tabbing past the last control hands focus to the browser and back, and the console revalidates (and remounts) on window focus, so a
 // new view is always entered from the document start, like a user who lands on a fresh page.
 if(fromTop)await page.evaluate(()=>{(document.activeElement as HTMLElement|null)?.blur();document.body.setAttribute('tabindex','-1');document.body.focus();document.body.removeAttribute('tabindex');});
 for(let n=0;n<=limit;n++){
  const stop=await target.first().evaluate((el)=>{
   if(el!==document.activeElement)return null;
   const s=getComputedStyle(el);const r=el.getBoundingClientRect();
   return {tag:el.tagName.toLowerCase(),name:((el as HTMLInputElement).labels?.[0]?.textContent??el.textContent??'').replace(/\s+/g,' ').trim().slice(0,60),outline:`${s.outlineStyle} ${s.outlineWidth}`,shadow:s.boxShadow,inView:r.width>0&&r.height>0,path:el.tagName.toLowerCase()};
  });
  if(stop){landed.push(stop);return;}
  await page.keyboard.press('Tab');
 }
 throw new Error(`keyboard focus never reached ${String(target)} within ${limit} Tab presses`);
}
function requestIds(page:Page):{path:string;status:number;id:string}[]{
 const seen:{path:string;status:number;id:string}[]=[];
 page.on('response',(r)=>{const url=new URL(r.url());if(url.pathname.startsWith('/api/'))seen.push({path:url.pathname,status:r.status(),id:r.headers()['x-request-id']??''});});
 return seen;
}
// Attachments go to the report; when E2E_EVIDENCE_DIR is set the same bytes are also written there, so a headed run leaves sanitized files.
async function attach(info:TestInfo,name:string,body:Buffer|string,contentType:string):Promise<void>{
 await info.attach(name,{body,contentType});
 const dir=process.env.E2E_EVIDENCE_DIR;if(dir){mkdirSync(dir,{recursive:true});writeFileSync(`${dir}/${name}`,body);}
}
async function attachEvidence(info:TestInfo,page:Page,label:string,mask:Locator[]):Promise<void>{
 await attach(info,`${label}.png`,await page.screenshot({mask,fullPage:true}),'image/png');
}
async function keyboardSignIn(page:Page,landed:Stop[],email:string,password:string,code?:string):Promise<void>{
 await tabTo(page,page.getByLabel('Email',{exact:true}),landed,true);await page.keyboard.type(email);
 await tabTo(page,page.getByLabel('Password',{exact:true}),landed);await page.keyboard.type(password);
 if(code){await tabTo(page,page.getByLabel('Authenticator or recovery code'),landed);await page.keyboard.type(code);}
 await tabTo(page,page.getByRole('button',{name:'Sign in',exact:true}),landed);await page.keyboard.press('Enter');
}
test('real local password, rotation, TOTP, one-use recovery and logout',async({page,context,browserName})=>{
 test.setTimeout(60_000);
 await page.goto('/');await page.getByLabel('Email',{exact:true}).fill(email);await page.getByLabel('Password',{exact:true}).fill(password);await page.getByRole('button',{name:'Sign in',exact:true}).click();await expect(page.getByRole('heading',{name:'Account access',exact:true})).toBeVisible();
 const before=(await context.cookies()).find(cookie=>cookie.name==='__Host-soundpost');expect(before?.httpOnly).toBe(true);expect(before?.secure).toBe(true);
 // Playwright's WebKit on Windows reports sameSite 'None' for every cookie: a control cookie added through context.addCookies as Strict, Lax and None all
 // read back None (control experiment run in task 10.21). That is a driver/platform reporting gap, not the server, so only that
 // combination skips the readback; Chromium, Firefox and WebKit elsewhere keep the strict assertion.
 if(!(browserName==='webkit'&&process.platform==='win32'))expect(before?.sameSite).toBe('Strict');
 await page.getByRole('button',{name:'Start authenticator enrollment'}).click();const secret=await page.locator('output.secret').textContent();expect(secret).toBeTruthy();
 const code=await currentTotp(page,secret??'');
 await page.getByLabel('Authenticator code',{exact:true}).fill(code);await page.getByRole('button',{name:'Confirm authenticator',exact:true}).click();await expect(page.getByRole('heading',{name:'Save these one-use recovery codes now'})).toBeVisible();const recovery=await page.locator('section').filter({has:page.getByRole('heading',{name:'Save these one-use recovery codes now'})}).last().locator('li code').first().textContent();expect(recovery).toBeTruthy();
 await page.getByRole('button',{name:'Sign out',exact:true}).click();await expect(page.getByRole('heading',{name:'Access your installation'})).toBeVisible();
 await page.getByLabel('Email',{exact:true}).fill(email);await page.getByLabel('Password',{exact:true}).fill(password);await page.getByLabel('Authenticator or recovery code').fill(recovery!);await page.getByRole('button',{name:'Sign in',exact:true}).click();await expect(page.getByRole('heading',{name:'Account access',exact:true})).toBeVisible();
 const rotated=(await context.cookies()).find(cookie=>cookie.name==='__Host-soundpost');expect(rotated?.value).not.toBe(before?.value);
 expect(await page.evaluate(()=>({local:Object.keys(localStorage),session:Object.keys(sessionStorage)}))).toEqual({local:[],session:[]});
 await page.getByRole('button',{name:'Sign out',exact:true}).click();await expect(page.getByRole('heading',{name:'Access your installation'})).toBeVisible();expect((await page.request.get('/api/v1/session')).status()).toBe(401);
 await page.getByLabel('Email',{exact:true}).fill(email);await page.getByLabel('Password',{exact:true}).fill(password);await page.getByLabel('Authenticator or recovery code').fill(recovery!);await page.getByRole('button',{name:'Sign in',exact:true}).click();await expect(page.getByRole('alert')).toBeVisible();
});
for(const identity of ['mapped','unmapped','wrong-issuer'] as const)test(`real OIDC Code+PKCE ${identity}`,async({page})=>{
 await page.goto('/');await page.getByRole('button',{name:'Single sign-on',exact:true}).click();await page.getByLabel('Organization ID',{exact:true}).fill(org);await page.getByLabel('Provider ID',{exact:true}).fill(provider);await page.getByRole('button',{name:'Continue to provider'}).click();await expect(page.getByRole('heading',{name:'Local identity provider'})).toBeVisible();const authorization=new URL(page.url());expect(authorization.searchParams.get('code_challenge_method')).toBe('S256');expect(authorization.searchParams.get('nonce')).toBeTruthy();await page.getByLabel('Fixture identity').selectOption(identity);await page.getByRole('button',{name:'Authorize fixture account'}).click();
 if(identity==='mapped'){await expect(page.getByRole('heading',{name:'Account access',exact:true})).toBeVisible();expect(new URL(page.url()).search).toBe('');await page.getByRole('button',{name:'Sign out',exact:true}).click();}else{expect((await page.request.get('/api/v1/session')).status()).toBe(401);}
});
const keyboardEmail=process.env.SOUNDPOST_KEYBOARD_EMAIL;
const keyboardPassword=process.env.SOUNDPOST_KEYBOARD_PASSWORD;
const assertRings=(landed:Stop[]):void=>{
 expect(landed.length).toBeGreaterThan(5);
 const unseen=landed.filter(s=>!s.inView||!focusIndicated(s)).map(s=>`${s.tag} "${s.name}" outline=${s.outline} shadow=${s.shadow} inView=${s.inView}`);
 expect(unseen).toEqual([]);
};
test('keyboard only: local password, TOTP enrollment, one-use recovery sign-in and logout; every stop shows a focus ring',async({page,context},info)=>{
 test.setTimeout(120_000);
 if(!keyboardEmail||!keyboardPassword)throw new Error('Real provisioned SOUNDPOST_KEYBOARD_EMAIL and SOUNDPOST_KEYBOARD_PASSWORD are required');
 const landed:Stop[]=[];const ids=requestIds(page);
 await page.goto('/');
 await keyboardSignIn(page,landed,keyboardEmail,keyboardPassword);
 await expect(page.getByRole('heading',{name:'Account access',exact:true})).toBeVisible();
 await tabTo(page,page.getByRole('button',{name:'Start authenticator enrollment'}),landed,true);await page.keyboard.press('Enter');
 const secret=await page.locator('output.secret').textContent();expect(secret).toBeTruthy();
 const code=await currentTotp(page,secret??'');
 await tabTo(page,page.getByLabel('Authenticator code',{exact:true}),landed);await page.keyboard.type(code);
 await tabTo(page,page.getByRole('button',{name:'Confirm authenticator',exact:true}),landed);await page.keyboard.press('Enter');
 await expect(page.getByRole('heading',{name:'Save these one-use recovery codes now'})).toBeVisible();
 const recovery=await page.locator('section').filter({has:page.getByRole('heading',{name:'Save these one-use recovery codes now'})}).last().locator('li code').first().textContent();expect(recovery).toBeTruthy();
 // Sanitized: the secret and every recovery code are masked, the typed credentials never appear on screen (password fields are masked by the browser).
 await attachEvidence(info,page,'keyboard-local-recovery-codes',[page.locator('output.secret'),page.locator('ul').filter({has:page.locator('li code')}),page.locator('dd code')]);
 await tabTo(page,page.getByRole('button',{name:'Sign out',exact:true}),landed,true);await page.keyboard.press('Enter');
 await expect(page.getByRole('heading',{name:'Access your installation'})).toBeVisible();
 await keyboardSignIn(page,landed,keyboardEmail,keyboardPassword,recovery!);
 await expect(page.getByRole('heading',{name:'Account access',exact:true})).toBeVisible();
 await attachEvidence(info,page,'keyboard-local-signed-in',[page.locator('code')]);
 const cookie=(await context.cookies()).find(c=>c.name==='__Host-soundpost');expect(cookie?.httpOnly).toBe(true);expect(cookie?.secure).toBe(true);
 await tabTo(page,page.getByRole('button',{name:'Sign out',exact:true}),landed,true);await page.keyboard.press('Enter');
 await expect(page.getByRole('heading',{name:'Access your installation'})).toBeVisible();expect((await page.request.get('/api/v1/session')).status()).toBe(401);
 // The one-use recovery code is spent: the same keyboard sign-in is refused with an alert.
 await keyboardSignIn(page,landed,keyboardEmail,keyboardPassword,recovery!);
 await expect(page.getByRole('alert')).toBeVisible();
 assertRings(landed);
 await attach(info,'keyboard-local-request-ids.json',JSON.stringify(ids,null,1),'application/json');
 expect(ids.length).toBeGreaterThan(0);expect(ids.filter(r=>r.id==='')).toEqual([]);
});
test('keyboard only: single sign-on redirect to the provider and back with an explicit mapping',async({page},info)=>{
 test.setTimeout(60_000);
 const landed:Stop[]=[];const providerStops:Stop[]=[];const ids=requestIds(page);
 await page.goto('/');
 await tabTo(page,page.getByRole('button',{name:'Single sign-on',exact:true}),landed,true);await page.keyboard.press('Enter');
 await tabTo(page,page.getByLabel('Organization ID',{exact:true}),landed);await page.keyboard.type(org);
 await tabTo(page,page.getByLabel('Provider ID',{exact:true}),landed);await page.keyboard.type(provider);
 await tabTo(page,page.getByRole('button',{name:'Continue to provider'}),landed);await page.keyboard.press('Enter');
 await expect(page.getByRole('heading',{name:'Local identity provider'})).toBeVisible();
 const authorization=new URL(page.url());expect(authorization.searchParams.get('code_challenge_method')).toBe('S256');expect(authorization.searchParams.get('nonce')).toBeTruthy();
 await attachEvidence(info,page,'keyboard-oidc-provider',[]);
 await tabTo(page,page.getByLabel('Fixture identity'),providerStops,true);await page.keyboard.type('Explicitly');
 await expect(page.getByLabel('Fixture identity')).toHaveValue('mapped');
 await tabTo(page,page.getByRole('button',{name:'Authorize fixture account'}),providerStops);await page.keyboard.press('Enter');
 await expect(page.getByRole('heading',{name:'Account access',exact:true})).toBeVisible();expect(new URL(page.url()).search).toBe('');
 await attachEvidence(info,page,'keyboard-oidc-signed-in',[page.locator('code')]);
 await tabTo(page,page.getByRole('button',{name:'Sign out',exact:true}),landed,true);await page.keyboard.press('Enter');
 await expect(page.getByRole('heading',{name:'Access your installation'})).toBeVisible();
 expect(landed.length).toBeGreaterThan(3);
 const unseen=landed.filter(s=>!s.inView||!focusIndicated(s)).map(s=>`${s.tag} "${s.name}" outline=${s.outline} shadow=${s.shadow}`);
 expect(unseen).toEqual([]);
 await attach(info,'keyboard-oidc-request-ids.json',JSON.stringify(ids,null,1),'application/json');
});
