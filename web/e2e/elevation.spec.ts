// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import {test,expect,type Page} from '@playwright/test';
import {adminCommand,at,createOrg,createProject,field,id,login,owner,postJson,queryBody} from './support/real';
const admin=process.env.SOUNDPOST_ELEVATION_EMAIL;
const password=process.env.SOUNDPOST_ELEVATION_PASSWORD;
const selected=process.env.SOUNDPOST_TEST_ORG;
if(!admin||!password||!selected)throw new Error('A real separate MFA-free instance-admin fixture and administered organization are required for elevation acceptance');

async function signIn(page:Page,email:string,secret:string):Promise<void>{
 await page.goto('/');await page.getByLabel('Email',{exact:true}).fill(email);await page.getByLabel('Password',{exact:true}).fill(secret);await page.getByRole('button',{name:'Sign in',exact:true}).click();
 // The console lands on Home; elevation, enrollment and restore are on the account page.
 await expect(page.getByRole('button',{name:'Sign out',exact:true})).toBeVisible();await page.evaluate(()=>{location.hash='#view=account';});await expect(page.getByRole('heading',{name:'Account access',level:1})).toBeVisible();
}
/** Opens the elevation form for `org`, fills it and submits; resolves with the elevation response the page received. */
async function elevate(page:Page,org:string,reason:string,secret:string){
 await page.getByRole('button',{name:'Request scoped elevation'}).click();await page.getByRole('checkbox',{name:org,exact:true}).check();await page.getByLabel('Reason',{exact:true}).fill(reason);await page.getByLabel('Current password',{exact:true}).fill(secret);
 const [response]=await Promise.all([page.waitForResponse((r)=>r.url().endsWith('/api/v1/elevation')&&r.request().method()==='POST'),page.getByRole('button',{name:'Reauthenticate and elevate'}).click()]);
 return response;
}
const denial=(text:string):string=>{
 const parsed=JSON.parse(text) as unknown;
 return `${String(field(parsed,'code'))}/${String(field(parsed,'safe_detail')??'')}`;
};

test('an organization administrator who is not the instance administrator cannot elevate and learns nothing about organizations',async({browser})=>{
 test.setTimeout(120_000);
 const o=owner();
 const ownerPage=await (await browser.newContext()).newPage();
 await login(ownerPage,o.email,o.password);
 const org=await createOrg(ownerPage,'elevation refusal org');
 await createProject(ownerPage,org,'elevation refusal project');
 const member={id:id(),email:`org-admin-${id().slice(0,8)}@example.test`,password:`org admin password ${id().slice(0,8)}`};
 await adminCommand(ownerPage,org,'create_user',{id:member.id,email:member.email,password:member.password});
 await adminCommand(ownerPage,org,'membership',{user_id:member.id,enabled:true});
 await adminCommand(ownerPage,org,'org_admin',{user_id:member.id,enabled:true});
 const page=await (await browser.newContext()).newPage();
 await signIn(page,member.email,member.password);
 // The console lists the organization the account administers; the form is reachable but the server refuses.
 await expect(page.getByRole('heading',{name:'Account access'})).toBeVisible();
 const response=await elevate(page,org,'An organization administrator tries to elevate',member.password);
 expect(response.status()).toBe(403);
 await expect(page.getByRole('alert').filter({hasText:/./})).toBeVisible();
 await expect(page.getByRole('heading',{name:'Scoped elevation active'})).toHaveCount(0);
 await expect(page.locator('.notice')).toHaveCount(0);
 // The refusal is one answer for a real organization and for one that does not exist.
 const real=await postJson(page,'/api/v1/elevation',{Reason:'refusal probe',Orgs:[org]});
 const missing=await postJson(page,'/api/v1/elevation',{Reason:'refusal probe',Orgs:[id()]});
 expect([real.status,missing.status]).toEqual([403,403]);
 expect(denial(real.text)).toBe(denial(missing.text));
 expect(real.text).not.toContain(org);
 // And no elevation id was ever issued: a protected read that names one is refused, never answered.
 expect(field(real.json,'id')).toBeUndefined();
});

test('selected organization elevation clears on navigation and expires at fifteen minutes; the server refuses an elevated read after expiry',async({page})=>{
 test.setTimeout(17*60*1000);
 await signIn(page,admin,password);
 let first=await elevate(page,selected,'Generic browser acceptance scoped investigation',password);
 expect(first.status()).toBe(200);
 await expect(page.getByRole('heading',{name:'Scoped elevation active'})).toBeVisible();
 await page.evaluate(()=>{location.hash='#view=home';});await expect(page.getByRole('heading',{name:'Home',level:1})).toBeVisible();
 await page.evaluate(()=>{location.hash='#view=account';});await expect(page.getByRole('heading',{name:'Account access',level:1})).toBeVisible();await expect(page.getByRole('heading',{name:'Scoped elevation active'})).toBeHidden();
 // A real project of the selected organization for the elevated reads below (an admin command needs a session fresh within five minutes).
 const project=await createProject(page,selected,'elevation expiry project');
 const second=await elevate(page,selected,'Generic browser acceptance expiry',password);
 expect(second.status()).toBe(200);
 const elevation=field(await second.json() as unknown,'id');
 if(typeof elevation!=='string')throw new Error(`no elevation id in the response: ${await second.text()}`);
 await expect(page.getByRole('heading',{name:'Scoped elevation active'})).toBeVisible();
 const read=async()=>postJson(page,'/api/v1/query',{...queryBody({org:selected,projects:[project],expression:'up',instant:at(0)}),elevation});
 // Control: inside the fifteen minutes the same elevated read is answered, so the refusal later is the expiry and nothing else.
 const before=await read();
 expect(before.status,before.text).toBe(200);
 // Real wall-clock expiry, not page.clock or a simulated server session.
 await expect(page.getByRole('heading',{name:'Scoped elevation active'})).toBeHidden({timeout:16*60*1000});
 // The screen holds no elevated content any more ...
 await expect(page.locator('.notice')).toHaveCount(0);
 await expect(page.getByText('Selected organizations:')).toHaveCount(0);
 // ... and the SERVER, not just the view, refuses the elevated read: no result body is returned.
 const after=await read();
 expect([403,404],after.text).toContain(after.status);
 expect(field(after.json,'result')).toBeUndefined();
 expect(after.text).not.toContain(project);
 await page.getByRole('button',{name:'Sign out',exact:true}).click();await expect(page.getByRole('heading',{name:'Access your installation'})).toBeVisible();expect((await page.request.get('/api/v1/session')).status()).toBe(401);
});
