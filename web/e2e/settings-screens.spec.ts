// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import {test,expect,type Page} from '@playwright/test';
import {createOrg,createProject,login,owner,reopen} from './support/real';
// The configuration screens of the console over the real served process: the settings hub, the alert rules screen (a rule is created and retired through the audited dialog),
// and the two screens whose routes may not be served yet (event webhooks, GitLab): each is either the real screen or says in words that it is not available yet, never an empty success.
const nsOf=(ms:number):string=>String(BigInt(ms)*1_000_000n);
const WINDOW={start:nsOf(Date.now()-3*3600_000),end:nsOf(Date.now()+3*3600_000)};
const view=(name:string,org:string,project:string,page=''):string=>`#${new URLSearchParams({org,projects:project,start:WINDOW.start,end:WINDOW.end,tz:'UTC',view:name,...(page?{page}:{})})}`;
const h1=(page:Page,name:string)=>page.getByRole('heading',{level:1,name,exact:true});

test('the settings hub offers every configuration screen, and each tile opens it',async({page})=>{
 test.setTimeout(180_000);
 const who=owner();
 await login(page,who.email,who.password);
 const org=await createOrg(page,'settings hub org');
 const project=await createProject(page,org);
 await reopen(page,`/${view('settings',org,project,'')}`);
 await expect(h1(page,'Settings')).toBeVisible();
 for(const title of ['Project','Source policies','Notification routes','Alert rules','Members and teams','Teams','Single sign-on','Audit and operations','GitLab','Event webhooks','Migration and cutover'])await expect(page.locator('a.set-tile').getByRole('heading',{name:title,exact:true})).toBeVisible();
 await expect(page.getByText('Your notifications')).toHaveCount(0);
 for(const [tile,title] of [['Notification routes','Notification routes'],['Migration and cutover','Migration and cutover'],['Single sign-on','Single sign-on']] as const){
  await reopen(page,`/${view('settings',org,project,'')}`);
  await page.locator('a.set-tile').filter({has:page.getByRole('heading',{name:tile,exact:true})}).click();
  await expect(h1(page,title)).toBeVisible();
 }
 // A settings page links to its siblings, and the crumb leads back to the hub.
 await expect(page.getByRole('navigation',{name:'Settings pages'}).getByRole('link',{name:'Teams'})).toBeVisible();
 await page.getByRole('navigation',{name:'Breadcrumb'}).getByRole('link',{name:'Settings'}).click();
 await expect(h1(page,'Settings')).toBeVisible();
});

test('alert rules: a mistake is refused before anything is sent, a rule is created and retired through audited dialogs, and the list is the committed one',async({page})=>{
 test.setTimeout(240_000);
 const who=owner();
 await login(page,who.email,who.password);
 const org=await createOrg(page,'alert rules org');
 const project=await createProject(page,org);
 await reopen(page,`/${view('rules',org,project)}`);
 await expect(h1(page,'Alert rules')).toBeVisible();
 await expect(page.getByTestId('rules-empty')).toContainText('No rule is defined');

 await page.getByRole('button',{name:'New rule'}).click();
 const create=page.locator('[data-write="rule-new"]');
 await create.getByLabel('Reason (kept in the audit record)').fill('a rule without an expression');
 await create.getByRole('button',{name:'Save rule',exact:true}).click();
 await expect(create.locator('[data-write-result="local"]')).toContainText('An expression');
 await create.getByLabel(/^Expression/).fill('vector(1)');
 await create.getByLabel('Severity').selectOption('critical');
 await create.getByRole('button',{name:'Save rule',exact:true}).click();
 await expect(page.getByText('Done. The server committed the new rule.')).toBeVisible();
 const row=page.locator('[data-rule]');
 await expect(row).toHaveCount(1);
 await expect(row).toContainText('vector(1)');
 await expect(row).toContainText('Alert');
 await expect(row).toContainText('Severity critical');
 await expect(row).toHaveAttribute('data-rule-state','active');
 await expect(row).toHaveAttribute('data-rule-version','1');

 await row.getByRole('button',{name:/^Change rule/}).click();
 const id=(await row.getAttribute('data-rule'))??'';
 const retire=page.locator(`[data-write="retire-${id}"]`);
 await retire.getByLabel('Reason (kept in the audit record)').fill('no longer needed');
 await retire.getByRole('button',{name:'Retire rule',exact:true}).click();
 await expect(page.getByTestId('rule-retired')).toContainText('This rule is retired');
 await expect(row).toHaveAttribute('data-rule-state','retired');
 await page.getByRole('button',{name:'Close',exact:true}).click();
 await page.getByRole('group',{name:'Filter rules by state'}).getByRole('button',{name:/^Active/}).click();
 await expect(page.getByText('No active rule')).toBeVisible();
 await page.getByRole('group',{name:'Filter rules by state'}).getByRole('button',{name:/^Retired/}).click();
 await expect(page.locator('[data-rule]')).toHaveCount(1);
});

for(const [screen,title,real,notBuilt] of [['events','Event webhooks','Endpoints','Event webhooks are not available yet'],['gitlab','GitLab','Connection','GitLab settings are not available yet']] as const){
 test(`${title}: the real screen of an installation that serves it, never a sentence that it is not available yet`,async({page})=>{
  test.setTimeout(180_000);
  const who=owner();
  await login(page,who.email,who.password);
  const org=await createOrg(page,`${screen} settings org`);
  const project=await createProject(page,org);
  await reopen(page,`/${view(screen,org,project)}`);
  await expect(h1(page,title)).toBeVisible();
  await expect(page.getByRole('heading',{level:2,name:real,exact:true})).toBeVisible();
  await expect(page.getByRole('heading',{level:2,name:notBuilt})).toHaveCount(0);
  await expect(page.locator('[data-state="unsupported"]')).toHaveCount(0);
 });
}
