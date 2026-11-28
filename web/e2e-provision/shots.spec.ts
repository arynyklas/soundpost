// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// Screenshots of every console screen, dark and light, of the running DEMO server (h.sh demo). Not a test of the product; it runs through
// playwright.provision.config.ts. DEMO_JSON is the demo.json the demo spec wrote, SHOTS_OUT the directory that receives NN-name-theme.png and manifest.json.
// The window is the default, Last 1 hour (span=60 in the address); the one exception is the native profile, whose capture is anchored at the
// suite's fixed epoch (web/e2e/support/real.ts T0): its screens open on a window around it and say so in the manifest.
import {test,expect,type Page} from '@playwright/test';
import {mkdirSync,readFileSync,writeFileSync} from 'node:fs';
import {join} from 'node:path';
import {login} from '../e2e/support/real';

interface Demo{org:string;projects:{storefront:string;api:string;jobs:string};admin:{email:string;password:string};incidents:{project:string;id:string}[];issues:{checkout:string;payment:string};releases:{a:string;b:string;c:string};services:{storefront:string;api:string};trace:{id:string;project:string};job:{id:string;project:string};replay:{id:string;gap:string;project:string};profile:{project:string;id:string;t0_ns:string}}
const need=(name:string):string=>{const v=process.env[name];if(!v)throw Error(`${name} is required`);return v;};
const demo=JSON.parse(readFileSync(need('DEMO_JSON'),'utf8')) as Demo;
const out=need('SHOTS_OUT');
const NS=1_000_000n;

interface Screen{name:string;params:Record<string,string>;note?:string;before?:(page:Page)=>Promise<void>;window?:{start:string;end:string}}
const all=[demo.projects.storefront,demo.projects.api,demo.projects.jobs].join(',');
const ref=(project:string,id:string):string=>`${project}:${id}`;
const metricsQuery=async(page:Page):Promise<void>=>{
 await page.getByLabel('Query expression').fill('request_latency_ms');
 await page.getByLabel('Range over the selected window').check();
 await page.getByRole('button',{name:'Run query'}).click();
 await page.getByTestId('results').locator('svg,table').first().waitFor({timeout:30_000}).catch(()=>undefined);
};
const screens:Screen[]=[
 {name:'home',params:{view:'home'}},
 {name:'incidents',params:{view:'incidents'}},
 {name:'incident',params:{view:'incidents',incident:ref(demo.incidents[0]!.project,demo.incidents[0]!.id)}},
 {name:'rules',params:{view:'rules'}},
 {name:'routing',params:{view:'routing'}},
 {name:'issues',params:{view:'issues'}},
 {name:'issue',params:{view:'issues',target:ref(demo.projects.storefront,demo.issues.checkout)}},
 {name:'releases',params:{view:'releases'}},
 {name:'release',params:{view:'releases',target:ref(demo.projects.storefront,demo.releases.c)}},
 {name:'services',params:{view:'services'}},
 {name:'service',params:{view:'services',service:demo.services.storefront}},
 {name:'jobs',params:{view:'jobs'}},
 {name:'job',params:{view:'jobs',target:ref(demo.job.project,demo.job.id)}},
 {name:'traces',params:{view:'traces'}},
 {name:'trace',params:{view:'traces',target:ref(demo.trace.project,demo.trace.id)}},
 {name:'logs',params:{view:'logs'}},
 {name:'metrics',params:{view:'metrics'},before:metricsQuery},
 {name:'replays',params:{view:'replays'}},
 {name:'replay',params:{view:'replays',target:ref(demo.replay.project,demo.replay.id)}},
 {name:'profiles',params:{view:'profiles'},window:{start:String(BigInt(demo.profile.t0_ns)-10n*1_000_000_000n),end:String(BigInt(demo.profile.t0_ns)+20n*1_000_000_000n)},note:'native capture is anchored at the suite epoch, not at now'},
 {name:'profile',params:{view:'profiles',target:ref(demo.profile.project,demo.profile.id)},window:{start:String(BigInt(demo.profile.t0_ns)-10n*1_000_000_000n),end:String(BigInt(demo.profile.t0_ns)+20n*1_000_000_000n)},note:'native capture is anchored at the suite epoch, not at now'},
 {name:'dashboards',params:{view:'dashboards'}},
 {name:'onboarding',params:{view:'onboarding'}},
 {name:'settings',params:{view:'settings'}},
 {name:'gitlab',params:{view:'gitlab'}},
 {name:'events',params:{view:'events'}},
 {name:'cutover',params:{view:'cutover'}},
 {name:'account',params:{view:'account'}},
 {name:'search-palette',params:{view:'home'},before:async(page)=>{await page.keyboard.press('Control+k');await page.getByRole('dialog').waitFor({timeout:10_000});}},
 {name:'scope-picker',params:{view:'home'},before:async(page)=>{await page.locator('button.scope-btn').click({timeout:10_000});await page.getByRole('dialog').waitFor({timeout:10_000});}},
];

test('screenshots of every screen, dark and light',async({browser})=>{
 test.setTimeout(1_800_000);
 mkdirSync(out,{recursive:true});
 const manifest:{file:string;screen:string;theme:string;note?:string;url:string}[]=[];
 for(const theme of ['dark','light'] as const){
  const context=await browser.newContext({viewport:{width:1440,height:900},colorScheme:theme,baseURL:need('SOUNDPOST_TEST_ORIGIN')});
  await context.addInitScript((t)=>{try{window.localStorage.setItem('soundpost.theme',t);}catch{/* no storage */}},theme);
  const page=await context.newPage();
  await login(page,demo.admin.email,demo.admin.password);
  let n=0;
  for(const s of screens){
   n++;
   const end=BigInt(Date.now())*NS;
   const params=new URLSearchParams({org:demo.org,projects:all,tz:'UTC',...(s.window?{start:s.window.start,end:s.window.end}:{start:String(end-3600n*1_000_000_000n),end:String(end),span:'60'}),...s.params});
   if(s.window||s.params.target)params.set('projects',s.params.target?.split(':')[0]??all);
   const url=`/#${params}`;
   await page.goto(url);
   await page.reload();
   await expect(page.locator('main h1').first()).toBeVisible({timeout:30_000});
   await page.waitForLoadState('networkidle',{timeout:30_000}).catch(()=>undefined);
   if(s.before)await s.before(page).catch((e:unknown)=>{console.log(`${s.name}: step failed: ${String(e)}`);});
   await page.waitForTimeout(800);
   const file=`${String(n).padStart(2,'0')}-${s.name}-${theme}.png`;
   await page.screenshot({path:join(out,file),fullPage:s.name!=='search-palette'&&s.name!=='scope-picker'});
   manifest.push({file,screen:s.name,theme,...(s.note?{note:s.note}:{}),url});
  }
  await context.close();
 }
 writeFileSync(join(out,'manifest.json'),JSON.stringify(manifest,null,1));
 const names=[...new Set(manifest.map((m)=>m.screen))];
 const cell=(m:{file:string}|undefined,theme:string):string=>m?`<a href="${m.file}"><img loading="lazy" src="${m.file}" alt="${theme}"></a>`:'';
 const rows=names.map((name)=>{
  const d=manifest.find((m)=>m.screen===name&&m.theme==='dark'),l=manifest.find((m)=>m.screen===name&&m.theme==='light');
  const note=d?.note?` <small>(${d.note})</small>`:'';
  return `<section><h2>${name}${note}</h2><div class="pair">${cell(d,'dark')}${cell(l,'light')}</div></section>`;
 }).join('\n');
 writeFileSync(join(out,'index.html'),`<!doctype html><meta charset="utf-8"><title>Console screens with the demo data set</title><style>body{font:14px system-ui;margin:16px;background:#fff;color:#111}.pair{display:flex;gap:12px}.pair a{flex:1;min-width:0}img{width:100%;border:1px solid #888}h2{margin:24px 0 6px}</style><h1>Console screens (${names.length} screens, dark and light)</h1>${rows}`);
 expect(names.length).toBe(screens.length);
});
