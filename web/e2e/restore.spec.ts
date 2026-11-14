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
 const sso=panel.locator('[data-restore-kind="integration"]',{hasText:'sso:'});
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
