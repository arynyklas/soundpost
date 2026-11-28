// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import {test,expect} from '@playwright/test';
import {adminCommand,createOrg,createProject,field,id,ingestError,login,onboardErrorSource,origin,owner,postJson,setGrant} from './support/real';
// D33 in a real browser against the real server. The console stays hash-routed; the server also serves the same public shell for GET on the
// known console path prefixes, and the shell rewrites the path to the equivalent hash route without a reload. The incident here is the REAL
// one the leader-only runner opens for an error ingested through a real source; a notification-style PATH link names only IDs.
const nsOf=(ms:number):string=>String(BigInt(ms)*1_000_000n);

test('a path-shaped notification link opens the right view; unknown paths stay 404; the shell carries no data',async({page,browser,playwright})=>{
 test.setTimeout(240_000);
 const o=owner();
 await login(page,o.email,o.password);
 const org=await createOrg(page,'path links org'),project=await createProject(page,org,'path links project');
 const ops={id:id(),email:`ops-${id().slice(0,8)}@example.test`,password:`path links ops password ${id().slice(0,8)}`};
 await adminCommand(page,org,'create_user',{id:ops.id,email:ops.email,password:ops.password});
 await adminCommand(page,org,'membership',{user_id:ops.id,enabled:true});
 await adminCommand(page,org,'org_admin',{user_id:ops.id,enabled:true});
 await setGrant(page,org,ops.id,project,true);
 const source=await onboardErrorSource(page,org,project);
 const api=await playwright.request.newContext();
 await ingestError(api,source,{at:nsOf(Date.now()),class:'PathLinkFailure',fatal:false,handled:false});
 let incident='';
 await expect.poll(async()=>{
  const r=await postJson(page,'/api/v1/queue',{org,projects:[project],limit:50});
  const entries=field(r.json,'entries');
  const first=Array.isArray(entries)?field(entries[0],'incident_id'):undefined;
  incident=typeof first==='string'?first:'';
  return incident;
 },{message:'the runner opens an incident for the ingested error',timeout:90_000,intervals:[250,500,1000]}).not.toBe('');

 // Logged out, a path link gets the public shell and nothing else: no scope data in the document, and every read stays a 401.
 const anonymous=await playwright.request.newContext({baseURL:origin()});
 const shell=await anonymous.get(`/incidents/${project}:${incident}?org=${org}`);
 expect(shell.status()).toBe(200);
 expect(shell.headers()['content-security-policy']).toContain("default-src 'none'");
 expect(shell.headers()['cache-control']).toBe('no-store');
 const shellText=await shell.text();
 expect(shellText).toContain('id="root"');
 for(const secret of [org,project,incident])expect(shellText).not.toContain(secret);
 expect((await anonymous.post('/api/v1/investigate',{headers:{Origin:origin()},data:{}})).status()).toBe(401);
 await anonymous.dispose();

 // Unknown paths stay 404 (an API typo must not look like a working page).
 for(const bad of ['/nowhere','/incidents/not-an-id',`/incidents/${project}:${incident}/extra`,'/api/v1/nowhere']){
  const r=await page.request.get(bad);
  expect(r.status(),bad).toBe(404);
  expect(await r.text(),bad).not.toContain('id="root"');
 }

 const ctx=await browser.newContext();
 const reader=await ctx.newPage();
 await login(reader,ops.email,ops.password);
 const hashRoute=new RegExp(`^${origin().replace(/[.*+?^${}()|[\]\\]/g,'\\$&')}/#view=incidents&org=${org}&projects=${project}&incident=${project}%3A${incident}$`);

 // 1. project:id pair: opens the incident, the address is the hash route, and the document was loaded once, from the path.
 await reader.goto(`/incidents/${project}:${incident}?org=${org}`);
 await expect(reader.locator('main h1')).toBeVisible(); // the incident page's own h1 (its title, or the fallback built from its ID)
 await expect(reader.getByTestId('revision')).toBeVisible();
 await expect(reader).toHaveURL(hashRoute);
 await expect(reader.getByTestId('visible-org')).toHaveText(org);
 await expect(reader.getByTestId('visible-projects')).toHaveText(project);
 const nav=await reader.evaluate(()=>{const e=performance.getEntriesByType('navigation');return {entries:e.length,name:e[0]?.name??''};});
 expect(nav.entries).toBe(1);
 expect(nav.name).toBe(`${origin()}/incidents/${project}:${incident}?org=${org}`);

 // 2. bare id with the project in the query: the same view.
 await reader.goto(`/incidents/${incident}?org=${org}&projects=${project}`);
 await expect(reader.locator('main h1')).toBeVisible();
 await expect(reader.getByTestId('revision')).toBeVisible();
 await expect(reader).toHaveURL(hashRoute);

 // 3. a section without an entity: the queue lists the real incident; settings opens the settings view.
 await reader.goto(`/queue?org=${org}&projects=${project}`);
 await expect(reader.getByRole('heading',{level:1,name:'Incidents',exact:true})).toBeVisible();
 await expect(reader.locator(`tr[data-incident="${incident}"]`)).toBeVisible();
 await expect(reader).toHaveURL(new RegExp(`/#view=queue&org=${org}&projects=${project}$`));
 await reader.goto(`/settings?org=${org}&projects=${project}`);
 await expect(reader.getByRole('heading',{level:1,name:'Settings',exact:true})).toBeVisible();

 // 4. A link that names no scope opens no data: the console asks for a scope and reads nothing.
 await reader.goto('/incidents');
 await expect(reader.getByText('Select an organization and projects to begin')).toBeVisible();
 await expect(reader.getByTestId('revision')).toHaveCount(0);

 // 5. A project the link does not carry in its scope is not opened (the pair names a project outside `projects`).
 const stranger=id();
 await reader.goto(`/incidents/${stranger}:${incident}?org=${org}&projects=${project}`);
 await expect(reader.getByRole('heading',{level:1,name:'Incidents',exact:true})).toBeVisible();
 await expect(reader.getByTestId('revision')).toHaveCount(0);

 // 6. Signed out, the link first asks for credentials; after sign-in the same link opens the incident.
 const fresh=await browser.newContext();
 const signedOut=await fresh.newPage();
 await signedOut.goto(`/incidents/${project}:${incident}?org=${org}`);
 await expect(signedOut.getByRole('heading',{level:1,name:'Access your installation'})).toBeVisible();
 await expect(signedOut.getByTestId('revision')).toHaveCount(0);
 await signedOut.getByLabel('Email').fill(ops.email);
 await signedOut.getByLabel('Password',{exact:true}).fill(ops.password);
 await signedOut.getByRole('button',{name:'Sign in'}).click();
 await expect(signedOut.locator('main h1')).toBeVisible();
 await expect(signedOut.getByTestId('revision')).toBeVisible();
 await expect(signedOut).toHaveURL(hashRoute);
 await fresh.close();
 await ctx.close();
});
