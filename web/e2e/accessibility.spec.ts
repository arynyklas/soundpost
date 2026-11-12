// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {test,expect,request as pwRequest,type Browser,type BrowserContext,type Page} from '@playwright/test';
import {mkdirSync} from 'node:fs';
import {join} from 'node:path';
import {login,owner} from './support/real';
import {auditDom,focusIndicated,tabStops,type Violation} from './support/audit';
import {deepLink,seedJourney,type JourneySeed} from './support/journey';

// Real server, real Chrome, real data (see support/journey.ts). The first-party DOM audits in support/audit.ts SUPPLEMENT the real
// keyboard checks below (real Tab and Enter presses, the focus the browser really reports, the computed focus ring the browser
// really draws); they do not replace them. No third-party audit library is used.
// NOT covered here, on purpose and stated (see docs/user/investigation-acceptance.md):
//  - the conflict dialog of the incident action form: incidents have no committed create route, so no real incident exists to conflict on;
//  - stale: no committed route returns a stale investigation view; the component is covered by the bun test src/app/accessibility.test.tsx;
//  - error and rate_limited are produced by a transport-level fault (the browser is answered 500 / 429 for one request), not by the server.
// Firefox and WebKit are configured in playwright.config.ts and are NOT installed on this host: they are not run.
test.describe.configure({mode:'serial'});
let br:Browser,ctx:BrowserContext,owners:Page,seed:JourneySeed;
const shots=process.env.SOUNDPOST_SHOT_DIR;
const NONE='b'.repeat(32);

async function settled(page:Page):Promise<void>{
 await expect(page.locator('main h1')).toBeVisible();
 await expect(page.locator('main [data-state="loading"]')).toHaveCount(0);
}
async function visit(page:Page,view:string,extra:Record<string,string>={}):Promise<void>{
 await page.goto(deepLink(seed,view,extra));
 await expect(page.getByRole('heading',{level:2,name:/^Investigation/})).toBeVisible();
 await settled(page);
 await page.waitForTimeout(400); // the investigate read of a freshly opened view is issued by an effect; let it publish
 await settled(page);
}
const target=(id:string):Record<string,string>=>({target:`${seed.explore.p1}:${id}`});

test.beforeAll(async({browser})=>{
 test.setTimeout(280_000);
 br=browser;
 const o=owner();
 owners=await (await browser.newContext()).newPage();
 await login(owners,o.email,o.password);
 seed=await seedJourney(owners,await pwRequest.newContext());
 ctx=await browser.newContext();
 const page=await ctx.newPage();
 await login(page,seed.explore.reader.email,seed.explore.reader.password);
 await page.close();
 if(shots)mkdirSync(shots,{recursive:true});
});
test.afterEach(async()=>{for(const p of ctx.pages())await p.close();});

// ---- the pages the app renders ---------------------------------------------------------------------------------------------
const PAGES:{name:string;view:string;extra:()=>Record<string,string>}[]=[
 {name:'queue (empty)',view:'queue',extra:()=>({})},
 {name:'incident (not found)',view:'incidents',extra:()=>({incident:`${seed.explore.p1}:${NONE}`})},
 {name:'issue (not available)',view:'issues',extra:()=>target(NONE)},
 {name:'release (not available)',view:'releases',extra:()=>target(NONE)},
 {name:'trace (critical path)',view:'traces',extra:()=>target(seed.traces.clean.trace)},
 {name:'trace (gateway to dependency)',view:'traces',extra:()=>target(seed.traces.gateway.trace)},
 {name:'explore',view:'explore',extra:()=>({})},
 {name:'services (partial)',view:'services',extra:()=>({})},
 {name:'jobs (empty)',view:'jobs',extra:()=>({})},
 {name:'replay',view:'replays',extra:()=>target(seed.replays.clean.replay)},
 {name:'profile',view:'profiles',extra:()=>target(seed.profile)},
 {name:'project settings',view:'settings',extra:()=>({})},
];
for(const p of PAGES){
 test(`DOM audit: ${p.name} has names, labels, landmarks, heading order, status text and contrast`,async()=>{
  const page=await ctx.newPage();
  await visit(page,p.view,p.extra());
  if(shots)await page.screenshot({path:join(shots,`audit-${p.view}-${p.name.replace(/[^a-z]+/gi,'-')}.png`),fullPage:true});
  const found:Violation[]=await auditDom(page);
  expect(found,JSON.stringify(found,null,1)).toEqual([]);
 });
}
test('DOM audit: the account page without a scope, and the signed-out sign-in page',async()=>{
 const page=await ctx.newPage();
 await page.goto('/');
 await expect(page.getByRole('heading',{level:1,name:'Account access'})).toBeVisible();
 const account=await auditDom(page);
 expect(account,JSON.stringify(account,null,1)).toEqual([]);
 const fresh=await br.newContext();
 const out=await fresh.newPage();
 await out.goto('/');
 await expect(out.getByRole('heading',{level:1,name:'Access your installation'})).toBeVisible();
 const signedOut=await auditDom(out);
 expect(signedOut,JSON.stringify(signedOut,null,1)).toEqual([]);
 await fresh.close();
});

// ---- real keyboard -----------------------------------------------------------------------------------------------------------
test('keyboard: the first Tab stop is the skip link, every stop shows a focus ring, and focus is never trapped',async()=>{
 const page=await ctx.newPage();
 await visit(page,'traces',target(seed.traces.clean.trace));
 await page.evaluate(()=>{(document.activeElement as HTMLElement|null)?.blur();window.scrollTo(0,0);});
 await page.locator('body').evaluate((b)=>{b.setAttribute('tabindex','-1');b.focus();b.removeAttribute('tabindex');});
 const stops=await tabStops(page,160);
 expect(stops.length).toBeGreaterThan(20);
 expect(stops[0]?.name).toBe('Skip to content');
 const unseen=stops.filter((s)=>!focusIndicated(s)).map((s)=>`${s.path} "${s.name}" outline=${s.outline} shadow=${s.shadow}`);
 expect(unseen).toEqual([]);
 expect(stops.filter((s)=>!s.inView).map((s)=>s.path)).toEqual([]);
 expect(stops.filter((s)=>s.name==='').map((s)=>s.path)).toEqual([]);
});
test('keyboard: the skip link moves focus to the main landmark and the investigation scope in the address survives',async()=>{
 const page=await ctx.newPage();
 await visit(page,'queue');
 const before=page.url();
 await page.locator('body').evaluate((b)=>{b.setAttribute('tabindex','-1');b.focus();b.removeAttribute('tabindex');});
 await page.keyboard.press('Tab');
 await expect(page.getByRole('link',{name:'Skip to content'})).toBeFocused();
 await page.keyboard.press('Enter');
 await expect(page.locator('main')).toBeFocused();
 expect(page.url()).toBe(before);
 await expect(page.getByTestId('visible-org')).toHaveText(seed.explore.org);
});
test('focus management: a section change announces itself in the page title and moves focus to a heading that names the section',async()=>{
 const page=await ctx.newPage();
 await visit(page,'queue');
 for(const [label,view] of [['Traces','traces'],['Explore','explore'],['Jobs','jobs']] as const){
  await page.getByRole('link',{name:label,exact:true}).focus();
  await page.keyboard.press('Enter');
  await expect(page).toHaveURL(new RegExp(`view=${view}`));
  const focused=page.locator(':focus');
  await expect(focused).toHaveAttribute('tabindex','-1');
  await expect(focused).toHaveText(new RegExp(label));
  expect(await focused.evaluate((e)=>/^H[1-6]$/.test(e.tagName))).toBe(true);
  await expect(page).toHaveTitle(new RegExp(`^${label}`));
 }
});
test('focus management: opening an entity from its form with the keyboard moves focus to the entity heading once it has loaded, and Back restores the previous view with focus on a heading',async()=>{
 const page=await ctx.newPage();
 await visit(page,'traces');
 await page.getByLabel('Trace ID').fill(seed.traces.clean.trace);
 await page.keyboard.press('Enter');
 const heading=page.getByRole('heading',{name:`Trace ${seed.traces.clean.trace}`});
 await expect(heading).toBeVisible();
 await expect(heading).toBeFocused();
 await page.goBack();
 await expect(page.getByTestId('critical-path')).toHaveCount(0);
 await expect(page.getByText('Open a trace by its ID.')).toBeVisible();
 expect(await page.locator(':focus').evaluate((e)=>/^H[1-6]$/.test(e.tagName))).toBe(true);
 await expect(page.getByTestId('visible-org')).toHaveText(seed.explore.org);
});
test('focus management: a span selected with the keyboard moves focus to its details, and activating the same row again keeps focus there',async()=>{
 const page=await ctx.newPage();
 await visit(page,'traces',target(seed.traces.clean.trace));
 const row=page.locator('table.path-table tbody tr').first().getByRole('button');
 await row.focus();
 await page.keyboard.press('Enter');
 await expect(page.getByTestId('span-details').getByRole('heading')).toBeFocused();
});

// ---- motion ------------------------------------------------------------------------------------------------------------------
test('reduced motion: under prefers-reduced-motion nothing animates or transitions, even against an author rule that tries to',async()=>{
 const free=await br.newContext({bypassCSP:true});
 const page=await free.newPage();
 await login(page,seed.explore.reader.email,seed.explore.reader.password);
 await visit(page,'queue');
 const probe=`@keyframes soundpost-probe{from{opacity:.2}to{opacity:1}}.investigation *{animation:soundpost-probe 2s linear infinite;transition:opacity 2s;scroll-behavior:smooth}`;
 await page.emulateMedia({reducedMotion:'no-preference'});
 await page.addStyleTag({content:probe});
 expect(await page.evaluate(()=>document.getAnimations().length)).toBeGreaterThan(0); // the control: motion exists when it is allowed
 await page.emulateMedia({reducedMotion:'reduce'});
 expect(await page.evaluate(()=>document.getAnimations().length)).toBe(0);
 const moving=await page.evaluate(()=>Array.from(document.querySelectorAll('*')).filter((e)=>{const s=getComputedStyle(e);return parseFloat(s.transitionDuration)>0.001||(s.animationName!=='none'&&parseFloat(s.animationDuration)>0.001)||s.scrollBehavior==='smooth';}).map((e)=>e.tagName));
 expect(moving).toEqual([]);
 await free.close();
});

// ---- every LoadState -----------------------------------------------------------------------------------------------------------
async function statusOf(page:Page,state:string):Promise<{label:string;role:string|null;live:string|null;text:string}>{
 const node=page.locator(`.status[data-state="${state}"]`).first();
 await expect(node).toBeVisible();
 return {label:(await node.locator('strong').first().innerText()).trim(),role:await node.getAttribute('role'),live:await node.getAttribute('aria-live'),text:(await node.innerText()).trim()};
}
async function achromatopsia(page:Page,name:string):Promise<void>{
 // Emulation.setEmulatedVisionDeficiency is a Chromium DevTools command: Firefox and WebKit have no CDP. It only changes the optional
 // screenshot; every assertion of this test (words, roles, live regions) runs unchanged in every browser.
 if(page.context().browser()?.browserType().name()!=='chromium'){if(shots)await page.screenshot({path:join(shots,`state-${name}.png`),fullPage:true});return;}
 const cdp=await page.context().newCDPSession(page);
 await cdp.send('Emulation.setEmulatedVisionDeficiency',{type:'achromatopsia'});
 if(shots)await page.screenshot({path:join(shots,`state-${name}.png`),fullPage:true});
 await cdp.send('Emulation.setEmulatedVisionDeficiency',{type:'none'});
}
const WORDS:Record<string,RegExp>={loading:/^Loading/,ready:/^Ready/,empty:/^Empty/,unauthorized:/^Not found/,unsupported:/^Not available/,incomplete:/^Partial/,error:/^Error/,rate_limited:/^Rate limited/};
test('every load state reachable here says what it is in words, is announced through a live region and survives without colour',async()=>{
 const seen=new Map<string,string>();
 const check=async(page:Page,state:string,assertLive:'polite'|'assertive'):Promise<void>=>{
  const s=await statusOf(page,state);
  expect(s.label,state).toMatch(WORDS[state]!);
  expect(s.role,state).toBe(assertLive==='assertive'?'alert':'status');
  expect(s.live,state).toBe(assertLive);
  expect(s.text.length,state).toBeGreaterThan(s.label.length+10);
  await achromatopsia(page,state);
  const found=await auditDom(page);
  expect(found,`${state}: ${JSON.stringify(found)}`).toEqual([]);
  seen.set(state,s.label);
 };
 // loading: the REAL answer, held back so the loading state can be observed.
 const slow=await ctx.newPage();
 await slow.route('**/api/v1/queue',async(route)=>{await slow.waitForTimeout(2500);await route.continue();});
 await slow.goto(deepLink(seed,'queue'));
 await check(slow,'loading','polite');
 await check(slow,'empty','polite');
 // ready, unauthorized, unsupported, incomplete: real server answers.
 const live=await ctx.newPage();
 await visit(live,'traces',target(seed.traces.clean.trace));await check(live,'ready','polite');
 await visit(live,'incidents',{incident:`${seed.explore.p1}:${NONE}`});await check(live,'unauthorized','assertive');
 await visit(live,'releases',target(NONE));await check(live,'unsupported','polite');
 await visit(live,'services');await check(live,'incomplete','polite');
 // error and rate_limited: a transport fault, one request answered with the status; the page and the server are real.
 for(const [state,status] of [['error',500],['rate_limited',429]] as const){
  const faulty=await ctx.newPage();
  await faulty.route('**/api/v1/queue',(route)=>route.fulfill({status,contentType:'application/json',headers:{'x-request-id':'a'.repeat(32)},body:JSON.stringify({code:status===429?'rate_limited':'internal'})}));
  await faulty.goto(deepLink(seed,'queue'));
  await check(faulty,state,'assertive');
 }
 // Distinct words for distinct states: no two states share a label.
 expect(new Set(seen.values()).size).toBe(seen.size);
});

// ---- the audits themselves --------------------------------------------------------------------------------------------------------
test('the audits have teeth: each defect injected into the real rendered page is reported under its own rule',async()=>{
 const page=await ctx.newPage();
 await visit(page,'traces',target(seed.traces.clean.trace));
 expect(await auditDom(page)).toEqual([]);
 const injected:[string,string][]=[
  ['interactive-name',`document.querySelector('nav a').textContent=''`],
  ['form-label',`Array.from(document.querySelectorAll('form[aria-label="Open a trace"] label')).find((l)=>l.textContent.startsWith('Trace')).childNodes.forEach((n)=>{if(n.nodeType===3)n.textContent=''})`],
  ['heading-order',`document.querySelector('main').insertAdjacentHTML('beforeend','<h2>Section</h2><h6>Skipped levels</h6>')`],
  ['landmarks',`document.body.insertAdjacentHTML('beforeend','<main>second</main>')`],
  ['status-text',`document.querySelector('main').insertAdjacentHTML('beforeend','<span class="badge" data-state="failed">●</span>')`],
  ['aria-references',`document.querySelector('main').insertAdjacentHTML('beforeend','<p aria-labelledby="no-such-id">x</p>')`],
  ['svg-alternative',`document.querySelector('main').insertAdjacentHTML('beforeend','<svg width="10" height="10"></svg>')`],
  ['table-structure',`document.querySelector('main').insertAdjacentHTML('beforeend','<table><tr><td>x</td></tr></table>')`],
  ['contrast',`document.querySelector('main').insertAdjacentHTML('beforeend','<p id="faint">faint grey text</p>');document.getElementById('faint').style.color='#bbbbbb'`],
 ];
 for(const [rule,code] of injected){
  const probe=await br.newContext({bypassCSP:true});
  const p=await probe.newPage();
  await login(p,seed.explore.reader.email,seed.explore.reader.password);
  await visit(p,'traces',target(seed.traces.clean.trace));
  await p.evaluate(code);
  const rules=new Set((await auditDom(p)).map((v)=>v.rule));
  expect(rules.has(rule),`${rule} not reported for: ${code}`).toBe(true);
  await probe.close();
 }
});

test('conflict dialog: NOT run, no real incident can exist to conflict on (no committed incident create route); recorded in the acceptance document',async()=>{
 test.skip(true,'incidents have no committed create route, so the 05.03 conflict surface cannot be reached on a real server; incident-actions.spec.ts needs uncommitted seed routes');
});
