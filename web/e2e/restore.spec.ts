// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import {test,expect,type Page} from '@playwright/test';
import {postJson} from './support/real';
// A REAL disaster restore: the installation these accounts came from was backed up, killed and restored into a fresh root
// (`soundpost backup create`, `restore`, `activate`) and is served by a fresh process. Nothing below fakes a server answer.
// The restore harness exports the one-time recovery token of the restored root and the identities of the source installation.
const env=(name:string):string=>{const v=process.env[name];if(!v)throw new Error(`${name} is required (run the restore harness)`);return v;};
const token=env('SOUNDPOST_RESTORE_TOKEN'),readerEmail=env('SOUNDPOST_RESTORE_READER_EMAIL'),readerPassword=env('SOUNDPOST_RESTORE_READER_PASSWORD'),ownerEmail=env('SOUNDPOST_RESTORE_OWNER_EMAIL'),ownerPassword=env('SOUNDPOST_RESTORE_OWNER_PASSWORD');
const origin=new URL(process.env.SOUNDPOST_TEST_ORIGIN??'').origin;
const recovery={email:`recovery-${Date.now()}@example.test`,password:`recovery admin password ${Date.now()}`};
const loginStatus=async(page:Page,email:string,password:string):Promise<number>=>(await page.request.post(`${origin}/api/v1/login`,{headers:{Origin:origin},data:{Email:email,Password:password,Code:''}})).status();

test.describe.configure({mode:'serial'});

test('restored accounts and credentials are inactive; the recovery bootstrap shows the restricted state and lists what is inactive',async({page})=>{
 test.setTimeout(180_000);
 // Every pre-restore account, even with its right password, is refused.
 expect(await loginStatus(page,readerEmail,readerPassword)).toBe(401);
 expect(await loginStatus(page,ownerEmail,ownerPassword)).toBe(401);
 // First boot with the recovery token creates a NEW recovery administrator.
 await page.goto('/');
 await page.getByRole('button',{name:'First boot',exact:true}).click();
 await page.getByLabel('Bootstrap token',{exact:true}).fill(token);
 await page.getByLabel('Email',{exact:true}).fill(recovery.email);
 await page.getByLabel('Password',{exact:true}).fill(recovery.password);
 await page.getByRole('button',{name:'Initialize administrator',exact:true}).click();
 const panel=page.getByRole('region',{name:'Restored installation'});
 await expect(panel).toBeVisible();
 await expect(panel.getByRole('heading',{name:'Restored installation: access is bootstrap-only'})).toBeVisible();
 await expect(panel.getByRole('status').first()).toContainText(/\d+ items? still inactive/);
 // The restored items are named: the reader's account, the organization admin, memberships, the grant and the SSO provider.
 await expect(panel.locator('[data-restore-kind="account"]',{hasText:readerEmail})).toBeVisible();
 await expect(panel.locator('[data-restore-kind="org_admin"]',{hasText:env('SOUNDPOST_RESTORE_ADMIN_EMAIL')})).toHaveCount(1);
 await expect(panel.locator('[data-restore-kind="grant"]')).toHaveCount(1);
 const sso=panel.locator('[data-restore-kind="integration"]',{hasText:`sso:${env('SOUNDPOST_RESTORE_PROVIDER')}`});
 await expect(sso).toHaveCount(1);
 // No old single sign-on activation is offered, and nothing of the old identity authority is reinstated.
 await expect(sso.getByRole('button')).toHaveCount(0);
 await expect(sso).toContainText('Not offered here');
 // The restored accounts still cannot sign in, and a fresh login holds no restored grant.
 expect(await loginStatus(page,readerEmail,readerPassword)).toBe(401);
 const orgs=await postJson(page,'/api/v1/admin/read',{kind:'organizations'});
 expect(JSON.stringify(orgs.json)).not.toContain(env('SOUNDPOST_RESTORE_ORG'));
});

test('the recovery administrator reauthorizes one account with fresh authentication and an audit record; nothing else is reinstated',async({page})=>{
 test.setTimeout(180_000);
 await page.goto('/');
 await page.getByLabel('Email',{exact:true}).fill(recovery.email);
 await page.getByLabel('Password',{exact:true}).fill(recovery.password);
 await page.getByRole('button',{name:'Sign in',exact:true}).click();
 const panel=page.getByRole('region',{name:'Restored installation'});
 await expect(panel).toBeVisible();
 const before=Number(((await panel.getByRole('status').first().innerText()).match(/(\d+) item/)??[])[1]);
 expect(before).toBeGreaterThan(1);
 await panel.getByRole('button',{name:new RegExp(`^Reauthorize Account: ${readerEmail.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')}$`)}).click();
 await panel.getByLabel('Reason',{exact:true}).fill('Restored reader reauthorized by the recovery administrator');
 await panel.getByLabel('Current password',{exact:true}).fill(recovery.password);
 await panel.getByRole('button',{name:'Reauthenticate and reauthorize'}).click();
 const done=panel.locator('[data-restore-done="true"]');
 await expect(done).toContainText(`Reinstated: ${readerEmail}`);
 await expect(done).toContainText(/Audit record [0-9a-f]{32}/);
 await expect(panel.getByRole('status').first()).toContainText(`${before-1} item`);
 await expect(panel.locator('[data-restore-kind="account"]',{hasText:readerEmail})).toHaveCount(0);
 // The account itself is back, but reauthorizing an account grants nothing: its membership and grant are separate, still-inactive items.
 expect(await loginStatus(page,readerEmail,readerPassword)).toBe(200);
 await expect(panel.locator('[data-restore-kind="grant"]')).toHaveCount(1);
 await expect(panel.locator('[data-restore-kind="membership"]',{hasText:readerEmail})).toHaveCount(1);
});

// [05.03-W7] The settings page of the restored organization: its sources and notification senders are inactive, listed there, and
// each is reauthorized by the recovery administrator with fresh authentication and an audit record; nothing else comes back.
const nsOf=(ms:number):string=>String(BigInt(ms)*1_000_000n);
test('project settings after a restore list the inactive sources and senders, and each reauthorization is one audited step',async({page,request})=>{
 test.setTimeout(180_000);
 const org=env('SOUNDPOST_RESTORE_ORG'),project=env('SOUNDPOST_RESTORE_PROJECT'),source=env('SOUNDPOST_RESTORE_SOURCE'),destination=env('SOUNDPOST_RESTORE_DESTINATION'),oldCredential=env('SOUNDPOST_RESTORE_SOURCE_CREDENTIAL');
 const ingest=async(credential:string):Promise<string>=>{const r=await request.post(`${origin}/ingest/v1/batches`,{headers:{Authorization:`Bearer ${credential}`},data:{}});return `${r.status()} ${(await r.text()).slice(0,200)}`;};
 // The source credential of the backup is dead on the restored installation (403); a live credential reaches the batch check (422 for an empty batch).
 expect(await ingest(oldCredential)).toMatch(/^403 /);
 await page.goto('/');
 await page.getByLabel('Email',{exact:true}).fill(recovery.email);
 await page.getByLabel('Password',{exact:true}).fill(recovery.password);
 await page.getByRole('button',{name:'Sign in',exact:true}).click();
 await expect(page.getByRole('region',{name:'Restored installation'})).toBeVisible();
 const params=new URLSearchParams({org,projects:project,start:nsOf(Date.now()-3*3600_000),end:nsOf(Date.now()+3*3600_000),tz:'UTC',view:'settings'});
 await page.goto(`/#${params}`);
 await page.reload();
 const panel=page.getByRole('region',{name:'Restored sources and senders'});
 await expect(panel).toBeVisible();
 await expect(panel.getByRole('heading',{name:'Restored: inactive sources and senders'})).toBeVisible();
 // Exactly this organization's source and sender: not the accounts, the grant or the single sign-on provider.
 await expect(panel.locator('[data-restore-kind]')).toHaveCount(2);
 await expect(panel.locator('[data-restore-kind="source"]')).toContainText(source);
 const sender=panel.locator('[data-restore-kind="integration"]');
 await expect(sender).toHaveCount(1);
 await expect(sender).toContainText(`destination:${destination}`);
 await expect(panel.getByRole('status').first()).toContainText('2 of the');
 await expect(panel.locator('[data-restore-kind="source"] button')).toHaveText('Reauthorize');

 // The source: fresh authentication, one audit record, a new credential shown once; the old one stays dead.
 await panel.getByRole('button',{name:`Reauthorize Source: source ${source}`}).click();
 await panel.getByLabel('Reason',{exact:true}).fill('Restored source reactivated by the recovery administrator');
 await panel.getByLabel('Current password',{exact:true}).fill(recovery.password);
 await panel.getByRole('button',{name:'Reauthenticate and reauthorize'}).click();
 const done=panel.locator('[data-restore-done="true"]');
 await expect(done).toContainText(`Reinstated: source ${source}`);
 await expect(done).toContainText(/Audit record [0-9a-f]{32}/);
 await expect(panel.locator('output.secret')).toBeVisible();
 const fresh=(await panel.locator('output.secret').innerText()).trim();
 expect(fresh.length).toBeGreaterThan(20);
 expect(fresh).not.toBe(oldCredential);
 await expect(panel.locator('[data-restore-kind="source"]')).toHaveCount(0);
 await expect(panel.locator('[data-restore-kind="integration"]')).toHaveCount(1);
 expect(await ingest(oldCredential)).toMatch(/^403 /);
 expect(await ingest(fresh)).toMatch(/^422 /);

 // The sender: its own audited step; nothing else in this panel is left.
 await panel.getByRole('button',{name:new RegExp(`^Reauthorize Integration: destination:${destination}`)}).click();
 await panel.getByLabel('Reason',{exact:true}).fill('Restored sender reactivated by the recovery administrator');
 await panel.getByLabel('Current password',{exact:true}).fill(recovery.password);
 await panel.getByRole('button',{name:'Reauthenticate and reauthorize'}).click();
 await expect(done).toContainText(/Reinstated: .*destination:/);
 await expect(done).toContainText(/Audit record [0-9a-f]{32}/);
 await expect(panel.locator('[data-restore-kind]')).toHaveCount(0);
 await expect(panel.getByRole('status').first()).toContainText('0 of the');
});
