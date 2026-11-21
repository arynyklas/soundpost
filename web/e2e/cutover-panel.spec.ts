// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import {test,expect,type Page} from '@playwright/test';
import {activate,createOrg,createProject,createReader,field,login,owner,postJson,reopen} from './support/real';
// The read-only notification cutover panel (POST /api/v1/cutover, web/src/settings/CutoverPanel.tsx) over the real served process. A project that never started a
// cutover has the product as its only owner: the page says so in words, shows no timeline or frontier, empty shadow and history tables, and carries no control that
// could advance anything (the cutover is advanced only by the operator flow). A reader who holds only telemetry.read on the project is answered the usual 404 and the
// page shows none of it. The panel is rendered from the server's answer for exactly the requested organization and project.
const nsOf=(ms:number):string=>String(BigInt(ms)*1_000_000n);
const WINDOW={start:nsOf(Date.now()-3*3600_000),end:nsOf(Date.now()+3*3600_000)};
const settings=(org:string,project:string):string=>`#${new URLSearchParams({org,projects:project,start:WINDOW.start,end:WINDOW.end,tz:'UTC',view:'settings'})}`;
const panelOf=(page:Page,project:string)=>page.locator(`[data-section="cutover"][data-project-cutover="${project}"]`);

test('a project with no cutover says the product is its only owner, in words, with nothing that could advance a cutover',async({page})=>{
 test.setTimeout(180_000);
 const who=owner();
 await login(page,who.email,who.password);
 const org=await createOrg(page,'cutover panel org');
 const project=await createProject(page,org);

 const view=await postJson(page,'/api/v1/cutover',{org,project_id:project});
 expect(view.status,view.text).toBe(200);
 const cutover=field(view.json,'cutover');
 expect(cutover===null||cutover===undefined,view.text).toBe(true);

 await reopen(page,`/${settings(org,project)}`);
 const panel=panelOf(page,project);
 await expect(panel).toBeVisible();
 await expect(panel.getByRole('heading',{name:'Notification cutover'})).toBeVisible();
 await expect(panel).toContainText('Read-only. The cutover is advanced only by the operator flow; nothing on this page changes it.');
 const owned=panel.locator('[data-cutover-owner="none"][data-cutover-phase="none"]');
 await expect(owned).toContainText('The product is the only owner of normal notifications.');
 await expect(owned).toContainText('This project has no cutover, so there is no legacy owner and no history boundary.');

 // No transition, no frontier and no legacy history: each table says so instead of showing nothing.
 await expect(panel.getByRole('table',{name:'Cutover timeline'})).toHaveCount(0);
 await expect(panel.getByRole('table',{name:'Cutover frontier'})).toHaveCount(0);
 const accounting=panel.getByRole('table',{name:'Delivery accounting'});
 await expect(accounting).toBeVisible();
 await expect(accounting.locator('tbody tr')).toHaveCount(1);
 await expect(panel.locator('[data-cutover-shadow="ended"]')).toContainText('Shadow decisions are recorded and never sent.');
 await expect(panel.getByRole('table',{name:'Shadow decisions by kind'})).toContainText('None.');
 await expect(panel.getByRole('table',{name:'Recent shadow decisions'})).toContainText('No shadow decision.');
 await expect(panel.locator('[data-cutover-history]')).toContainText('Legacy history is read-only and lives outside this product');
 await expect(panel.getByRole('table',{name:'History spans'})).toContainText('No boundary: the product is the only owner and there is no legacy history to join.');

 // Nothing in the panel can change the cutover: no form, no button, no input; every table has a caption and column headers.
 await expect(panel.locator('button,input,select,textarea,form,a[href]')).toHaveCount(0);
 for(const name of ['Delivery accounting','Shadow decisions by kind','Recent shadow decisions','History spans']){
  const table=panel.getByRole('table',{name});
  await expect(table.locator('caption')).toHaveCount(1);
  expect(await table.locator('thead th[scope="col"]').count(),name).toBeGreaterThan(0);
 }
 // The state is words, never colour alone: the same sentences are in the text the accessibility tree reads.
 const text=(await panel.innerText()).replace(/\s+/g,' ');
 expect(text).toContain('Who owns normal notifications now');
 expect(text).not.toContain('Restore pending.');
 expect(text).not.toMatch(/\bundefined\b|\bNaN\b|\[object Object\]/);
});

test('a reader without policy.write on the project is refused the cutover answer and the page shows none of it',async({page})=>{
 test.setTimeout(180_000);
 const who=owner();
 await login(page,who.email,who.password);
 const org=await createOrg(page,'cutover panel reader org');
 const project=await createProject(page,org);
 const reader=await createReader(page,org,[project]);
 await page.context().clearCookies();
 await login(page,reader.email,reader.password);

 const denied=await postJson(page,'/api/v1/cutover',{org,project_id:project});
 expect(denied.status,denied.text).toBe(404);
 expect(denied.text).not.toContain('shadow');

 await reopen(page,`/${settings(org,project)}`);
 await activate(page);
 const panel=panelOf(page,project);
 await expect(panel).toBeVisible();
 await expect(panel.getByText('Who owns normal notifications now')).toHaveCount(0);
 await expect(panel.getByRole('table')).toHaveCount(0);
});
