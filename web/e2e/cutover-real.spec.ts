// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import {test,expect,type Locator,type Page} from '@playwright/test';
import {activate,field,login,owner,postJson,reopen} from './support/real';
// The notification cutover panel (web/src/settings/CutoverPanel.tsx, POST /api/v1/cutover) over a REAL ownership cutover: the cutover of the
// project was committed by the product's own operator facade (notify.CutoverService.AdvanceCutover, through web/fixtures/cutoverseed) into the control
// state of the installation this server serves, with the cutover evidence the barrier verifies (authorization, rollback route, independent observer
// proof, old-owner-disabled evidence, product delivery accounting and the source checkpoint). Nothing below fakes a server answer: the panel is compared,
// cell by cell, with what the served route answers for the committed state, and the committed state is checked against what was committed.
// The harness (e2e-harness/cutover.sh) runs this file once per stage, restarting the server between stages (the cutover is advanced only by the operator flow,
// never by the console):
//   CUTOVER_STAGE=shadow       the cutover is in `shadow`; the served workers evaluate an alert rule saved over the real rules route and the product
//                              records shadow decisions: decided, never sent (no delivery attempt, nothing pending)
//   CUTOVER_STAGE=new_active   quiescing_old -> barrier_verified -> new_active were committed: the new owner is the only active owner, the shadow decisions
//                              of the first stage are still there as history, and the history boundary has a legacy side, a handover and a product side
//   CUTOVER_STAGE=old_active   rollback_quiescing -> old_active were committed: the old owner sends again, the product is shadowing again
// Needs SOUNDPOST_TEST_ORIGIN, SOUNDPOST_SCOPE_EMAIL/PASSWORD (the bootstrapped owner) and the identities the seeding step wrote (CUTOVER_ORG, CUTOVER_PROJECT, CUTOVER_SOURCE, CUTOVER_SOURCE_VERSION).
const env=(name:string):string=>{const v=process.env[name];if(!v)throw new Error(`${name} is required (run the cutover harness: web/e2e-harness/cutover.sh)`);return v;};
const stage=env('CUTOVER_STAGE');
if(!['shadow','new_active','old_active'].includes(stage))throw new Error(`CUTOVER_STAGE must be shadow, new_active or old_active, got ${stage}`);
const org=env('CUTOVER_ORG'),project=env('CUTOVER_PROJECT'),source=env('CUTOVER_SOURCE'),sourceVersion=env('CUTOVER_SOURCE_VERSION');
// The identities the cutover was committed with (web/fixtures/cutoverseed/main.go).
const OLD_OWNER='e201'.padEnd(32,'0'),NEW_OWNER='e202'.padEnd(32,'0'),FRONTIER_GROUP='e2f0'.padEnd(32,'0'),FRONTIER_INDEX='100';
const PHASE_WORDS:Record<string,string>={'':'Created (no previous phase)',shadow:'Shadow',quiescing_old:'Quiescing the old owner',barrier_verified:'Barrier verified',new_active:'New owner active',rollback_quiescing:'Rolling back: quiescing the new owner',old_active:'Old owner active (rolled back)'};
const SIDE_WORDS:Record<string,string>={legacy:'Legacy (external, read-only)',product:'Product',handover:'Handover (no owner)'};
const nsOf=(ms:number):string=>String(BigInt(ms)*1_000_000n);
const panelOf=(page:Page):Locator=>page.locator(`[data-section="cutover"][data-project-cutover="${project}"]`);

interface View{
 org:string;project:string;
 cutover:{id:string;revision:string;phase:string;epoch:string;old_owner:string;new_owner:string;active_owners:string[];frontier:{source:string;version:string;cursor:{group:string;index:string}}[];restore:{pending?:string;acknowledged?:string};timeline:{revision:string;from:string;to:string;epoch:string;command:string;principal:string;digest:string;evidence_digest?:string}[]}|null;
 accounting:{pending:number;claimed:number;lapsed:number;unknown:number;unknown_digest:string};
 shadow:{observing:boolean;decisions:number;by_kind:Record<string,number>;recent:{id:string;subject:string;kind:string;recipient?:string;decided_ns:string;digest:string}[]};
 history:{legacy_owner?:string;legacy_history:string;importer:boolean;spans:{owner?:string;side:string;phase:string;from_ns:string;to_ns?:string}[]};
}
async function view(page:Page):Promise<View>{
 const r=await postJson(page,'/api/v1/cutover',{org,project_id:project});
 expect(r.status,r.text).toBe(200);
 return r.json as View;
}
const committed=(v:View)=>{expect(v.cutover,'a cutover was committed for the project').not.toBeNull();return v.cutover as NonNullable<View['cutover']>;};

/** Every cell of the panel is what the served route answered for the committed state. */
async function expectPanelShows(page:Page,v:View):Promise<void>{
 const c=committed(v);
 const panel=panelOf(page);
 await expect(panel).toBeVisible();
 await expect(panel.getByRole('heading',{name:'Notification cutover'})).toBeVisible();
 await expect(panel).toContainText('Read-only. The cutover is advanced only by the operator flow; nothing on this page changes it.');
 const owner=c.active_owners.length===1?c.active_owners[0]:'none';
 const header=panel.locator(`[data-cutover-owner="${owner}"][data-cutover-phase="${c.phase}"]`);
 await expect(header).toBeVisible();
 await expect(header).toContainText(`${PHASE_WORDS[c.phase]} (${c.phase}), epoch ${c.epoch}, revision ${c.revision}`);
 await expect(header).toContainText(c.old_owner);
 await expect(header).toContainText(c.new_owner);
 // The timeline: one row per committed transition, oldest first, with the revision, both phases in words and the command identity.
 const timeline=panel.getByRole('table',{name:'Cutover timeline'});
 await expect(timeline.locator('tbody tr')).toHaveCount(c.timeline.length);
 for(const [i,step] of c.timeline.entries()){
  const row=timeline.locator('tbody tr').nth(i);
  await expect(row.locator('td').nth(0)).toHaveText(step.revision);
  await expect(row.locator('td').nth(1)).toHaveText(PHASE_WORDS[step.from]!);
  await expect(row.locator('td').nth(2)).toHaveText(PHASE_WORDS[step.to]!);
  await expect(row.locator('td').nth(3)).toHaveText(step.epoch);
  await expect(row).toContainText(step.command);
  await expect(row).toContainText(step.digest);
 }
 // The frontier: the registered source, its policy version and the cursor the old owner had processed through.
 const frontier=panel.getByRole('table',{name:'Cutover frontier'});
 await expect(frontier.locator('tbody tr')).toHaveCount(c.frontier.length);
 for(const [i,f] of c.frontier.entries()){
  const row=frontier.locator('tbody tr').nth(i);
  await expect(row.locator('td').nth(0)).toHaveText(f.source);
  await expect(row.locator('td').nth(1)).toHaveText(f.version);
  await expect(row.locator('td').nth(2)).toHaveText(f.cursor.group);
  await expect(row.locator('td').nth(3)).toHaveText(f.cursor.index);
 }
 // The product's own delivery accounting.
 const accounting=panel.getByRole('table',{name:'Delivery accounting'}).locator('tbody tr td');
 for(const [i,n] of [v.accounting.pending,v.accounting.claimed,v.accounting.lapsed,v.accounting.unknown].entries())await expect(accounting.nth(i)).toHaveText(String(n));
 await expect(accounting.nth(4)).toHaveText(v.accounting.unknown_digest);
 // Shadow decisions: the observing flag, the counts by kind and the newest decisions with their stable delivery IDs.
 await expect(panel.locator(`[data-cutover-shadow="${v.shadow.observing?'observing':'ended'}"]`)).toBeVisible();
 await expect(panel.locator('[data-cutover-shadow]')).toContainText(`Decisions recorded: ${v.shadow.decisions}`);
 const kinds=Object.entries(v.shadow.by_kind);
 const byKind=panel.getByRole('table',{name:'Shadow decisions by kind'});
 if(kinds.length===0)await expect(byKind).toContainText('None.');
 for(const [kind,count] of kinds)await expect(byKind.locator('tbody tr',{hasText:kind}).locator('td').nth(1)).toHaveText(String(count));
 const recent=panel.getByRole('table',{name:'Recent shadow decisions'});
 if(v.shadow.recent.length===0)await expect(recent).toContainText('No shadow decision.');
 else await expect(recent.locator('tbody tr')).toHaveCount(v.shadow.recent.length);
 for(const r of v.shadow.recent){const row=recent.locator('tbody tr',{hasText:r.id});await expect(row).toHaveCount(1);await expect(row).toContainText(r.kind);await expect(row).toContainText(r.digest);}
 // The history boundary: the legacy owner's read-only history, the handover and the product's own history.
 await expect(panel.locator('[data-cutover-history]')).toContainText('Legacy history is read-only and lives outside this product');
 const spans=panel.getByRole('table',{name:'History spans'});
 await expect(spans.locator('tbody tr')).toHaveCount(v.history.spans.length);
 for(const s of v.history.spans)await expect(spans.locator('tbody tr',{hasText:SIDE_WORDS[s.side]!}).first()).toBeVisible();
 // Nothing on the page can change the cutover.
 await expect(panel.locator('button,input,select,textarea,form,a[href]')).toHaveCount(0);
 const text=(await panel.innerText()).replace(/\s+/g,' ');
 expect(text).not.toMatch(/\bundefined\b|\bNaN\b|\[object Object\]/);
 expect(text).not.toContain('Restore pending.');
}

async function openPanel(page:Page):Promise<void>{
 const hash=new URLSearchParams({org,projects:project,start:nsOf(Date.now()-3*3600_000),end:nsOf(Date.now()+3*3600_000),tz:'UTC',view:'cutover'});
 await reopen(page,`/#${hash}`);
 await expect(panelOf(page)).toBeVisible();
 await expect(panelOf(page).getByRole('heading',{name:'Notification cutover'})).toBeVisible();
 await expect(panelOf(page).locator('[data-cutover-phase]'),'the panel renders the committed state (not a loading or error state)').toBeVisible({timeout:30_000});
}

const SENDING=/^notify\.delivery\.(accepted|failed|unknown|retry|claimed)$/;
async function deliveryAttemptAudits(page:Page):Promise<string[]>{
 const r=await postJson(page,'/api/v1/admin/read',{kind:'audit',org_id:org});
 expect(r.status,r.text).toBe(200);
 const audits=field(r.json,'audits');
 expect(Array.isArray(audits),r.text).toBe(true);
 return (audits as {action:string}[]).map((a)=>a.action).filter((a)=>SENDING.test(a));
}

test.describe.configure({mode:'serial'});

test('shadow: the committed cutover is shown, and the product records decisions that it never sends',async({page})=>{
 test.skip(stage!=='shadow','stage shadow only');
 test.setTimeout(300_000);
 const who=owner();
 await login(page,who.email,who.password);

 // What was committed is what the route serves: one transition, the old owner active, the frontier the seeding step named.
 let v=await view(page);
 const c=committed(v);
 expect(c.phase).toBe('shadow');
 expect(c.old_owner).toBe(OLD_OWNER);
 expect(c.new_owner).toBe(NEW_OWNER);
 expect(c.active_owners).toEqual([OLD_OWNER]);
 expect(c.timeline).toHaveLength(1);
 expect(c.timeline[0]!.to).toBe('shadow');
 expect(c.frontier).toEqual([{source,version:sourceVersion,cursor:{group:FRONTIER_GROUP,index:FRONTIER_INDEX}}]);
 expect(v.shadow.observing).toBe(true);
 expect(v.history.legacy_history).toBe('read_only');
 expect(v.history.importer).toBe(false);
 expect(v.history.legacy_owner).toBe(OLD_OWNER);
 await openPanel(page);
 const header=panelOf(page).locator(`[data-cutover-owner="${OLD_OWNER}"][data-cutover-phase="shadow"]`);
 await expect(header).toContainText('The old owner sends normal notifications.');
 await expect(header).toContainText('The product only watches: its decisions are recorded as shadow decisions and never sent.');
 await expectPanelShows(page,v);

 // A real alert rule saved over the real rules route; the served workers evaluate it, open its condition and the product decides to notify.
 const listed=await postJson(page,'/api/v1/rules',{org,project_id:project,operation:'list'});
 expect(listed.status,listed.text).toBe(200);
 const profiles=field(listed.json,'profiles') as {id:string;feature_sets:string[]}[];
 const profile=profiles.find((p)=>p.id.startsWith('promql')&&p.feature_sets.length>0);
 expect(profile,'a PromQL profile with a feature set is advertised').toBeTruthy();
 const saved=await postJson(page,'/api/v1/rules',{org,project_id:project,operation:'save',command_id:`${Date.now().toString(16).padStart(32,'a')}`,rule_id:`${Date.now().toString(16).padStart(32,'b')}`,expected_revision:'0',reason:'real cutover e2e rule',
  rule:{kind:'alert',profile:profile!.id,feature_set:profile!.feature_sets[0],expression:'vector(1)',interval_seconds:60,severity:'critical'}});
 expect(saved.status,saved.text).toBe(200);
 await expect.poll(async()=>(await view(page)).shadow.decisions,{message:'the product records a shadow decision for the open condition',timeout:180_000,intervals:[1000,2000,3000]}).toBeGreaterThan(0);

 v=await view(page);
 expect(v.shadow.observing).toBe(true);
 expect(v.shadow.recent.length).toBeGreaterThan(0);
 for(const r of v.shadow.recent){expect(r.id).toMatch(/^[0-9a-f]{32}$/);expect(r.digest).toMatch(/^[0-9a-f]{64}$/);}
 // Decided, never sent: nothing pending or in flight, no delivery attempt in the audit trail.
 expect(v.accounting).toMatchObject({pending:0,claimed:0,lapsed:0,unknown:0});
 expect(await deliveryAttemptAudits(page)).toEqual([]);
 await openPanel(page);
 await expectPanelShows(page,v);
 await expect(panelOf(page).locator('[data-cutover-shadow="observing"]')).toContainText('The product is observing: new decisions are shadow decisions.');
});

test('new_active: the new owner is the only active owner; the shadow history and the legacy/handover/product boundary are kept',async({page})=>{
 test.skip(stage!=='new_active','stage new_active only');
 test.setTimeout(300_000);
 const who=owner();
 await login(page,who.email,who.password);
 const v=await view(page);
 const c=committed(v);
 expect(c.phase).toBe('new_active');
 expect(c.active_owners).toEqual([NEW_OWNER]);
 expect(c.timeline.map((s)=>`${s.from}>${s.to}`)).toEqual(['>shadow','shadow>quiescing_old','quiescing_old>barrier_verified','barrier_verified>new_active']);
 const revisions=c.timeline.map((s)=>BigInt(s.revision));
 expect(revisions.every((r,i)=>i===0||r>revisions[i-1]!),'revisions increase').toBe(true);
 // Only the barrier and activation steps carry verified evidence.
 expect(c.timeline.map((s)=>s.evidence_digest!==undefined)).toEqual([false,false,true,true]);
 expect(c.frontier).toEqual([{source,version:sourceVersion,cursor:{group:FRONTIER_GROUP,index:FRONTIER_INDEX}}]);
 expect(v.shadow.observing).toBe(false);
 expect(v.shadow.decisions,'the shadow decisions of the first stage are history').toBeGreaterThan(0);
 // shadow and quiescing_old are two legacy-owned stretches (one span per phase), then the handover, then the product.
 expect(v.history.spans.map((s)=>s.side).sort()).toEqual(['handover','legacy','legacy','product']);
 expect(v.history.spans.filter((s)=>s.to_ns===undefined).map((s)=>s.side)).toEqual(['product']);
 await openPanel(page);
 const header=panelOf(page).locator(`[data-cutover-owner="${NEW_OWNER}"][data-cutover-phase="new_active"]`);
 await expect(header).toContainText('The new owner sends normal notifications.');
 await expect(header).toContainText('The old owner has been quiesced; shadow observation has ended.');
 await expect(panelOf(page).locator('[data-cutover-shadow="ended"]')).toContainText('The product is not observing now; the decisions below were made earlier.');
 await expectPanelShows(page,v);
});

test('old_active: after a rollback the old owner sends again and the product is shadowing again',async({page})=>{
 test.skip(stage!=='old_active','stage old_active only');
 test.setTimeout(300_000);
 const who=owner();
 await login(page,who.email,who.password);
 const v=await view(page);
 const c=committed(v);
 expect(c.phase).toBe('old_active');
 expect(c.active_owners).toEqual([OLD_OWNER]);
 expect(c.timeline.map((s)=>`${s.from}>${s.to}`)).toEqual(['>shadow','shadow>quiescing_old','quiescing_old>barrier_verified','barrier_verified>new_active','new_active>rollback_quiescing','rollback_quiescing>old_active']);
 expect(c.timeline.map((s)=>s.evidence_digest!==undefined)).toEqual([false,false,true,true,false,true]);
 expect(v.shadow.observing).toBe(true);
 expect(v.history.spans.map((s)=>s.side)).toContain('handover');
 await openPanel(page);
 const header=panelOf(page).locator(`[data-cutover-owner="${OLD_OWNER}"][data-cutover-phase="old_active"]`);
 await expect(header).toContainText('The old owner sends normal notifications again (rolled back).');
 await expect(header).toContainText('The product is not the active owner; its decisions are recorded as shadow decisions and never sent.');
 await expectPanelShows(page,v);
 await activate(page);
});
