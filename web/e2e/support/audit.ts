// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// First-party DOM audits for the 05.09 accessibility spec. They SUPPLEMENT the real keyboard, focus and visual checks of
// that spec and replace nothing: no third-party audit library is used. Each rule reports plain violations; an empty list is the
// only passing result. The page function is self-contained (it is serialized into the browser).
import type {Page} from '@playwright/test';

export interface Violation{rule:string;node:string;detail:string}

/** Runs every DOM rule against the rendered page. Rules: interactive-name, form-label, heading-order, landmarks,
 * status-text, aria-references, svg-alternative, table-structure, document, contrast. */
export async function auditDom(page:Page):Promise<Violation[]>{
 return page.evaluate(()=>{
  const out:{rule:string;node:string;detail:string}[]=[];
  const describe=(el:Element):string=>{
   const id=el.id?`#${el.id}`:'';
   const cls=typeof el.className==='string'&&el.className?`.${el.className.trim().split(/\s+/).join('.')}`:'';
   const tid=el.getAttribute('data-testid');
   return `${el.tagName.toLowerCase()}${id}${cls}${tid?`[data-testid=${tid}]`:''}`;
  };
  const add=(rule:string,el:Element,detail:string):void=>{out.push({rule,node:describe(el),detail});};
  const visible=(el:Element):boolean=>{
   if(!(el instanceof HTMLElement||el instanceof SVGElement))return false;
   for(let n:Element|null=el;n;n=n.parentElement){
    if(n.getAttribute('aria-hidden')==='true'||n.hasAttribute('hidden'))return false;
    const s=getComputedStyle(n);
    if(s.display==='none'||s.visibility==='hidden')return false;
   }
   return el.getClientRects().length>0;
  };
  const text=(el:Element):string=>(el.textContent??'').replace(/\s+/g,' ').trim();
  const byId=(id:string):Element|null=>document.getElementById(id);
  const labelledBy=(el:Element):string|null=>{
   const ids=(el.getAttribute('aria-labelledby')??'').split(/\s+/).filter(Boolean);
   if(ids.length===0)return null;
   return ids.map((i)=>{const t=byId(i);return t?text(t):'';}).join(' ').trim();
  };
  const nameOf=(el:Element):string=>{
   const lb=labelledBy(el);
   if(lb)return lb;
   const al=(el.getAttribute('aria-label')??'').trim();
   if(al)return al;
   if(el instanceof HTMLInputElement||el instanceof HTMLSelectElement||el instanceof HTMLTextAreaElement){
    const labels=Array.from(el.labels??[]).map((l)=>text(l)).join(' ').trim();
    if(labels)return labels;
    if(el instanceof HTMLInputElement&&['submit','button','reset'].includes(el.type)&&el.value.trim())return el.value.trim();
    if(el instanceof HTMLInputElement&&el.type==='image'&&(el.alt??'').trim())return el.alt.trim();
    return (el.title??'').trim();
   }
   if(el instanceof HTMLIFrameElement)return (el.title??'').trim();
   if(el instanceof SVGElement){const t=el.querySelector('title');return t?text(t):'';}
   const own=Array.from(el.querySelectorAll('img[alt]')).map((i)=>i.getAttribute('alt')??'').join(' ');
   return (text(el)+' '+own).trim()||((el as HTMLElement).title??'').trim();
  };

  // 1. interactive-name: every interactive element has an accessible name.
  const interactive='a[href],button,input:not([type=hidden]),select,textarea,summary,iframe,[role=button],[role=link],[role=tab],[role=menuitem],[role=checkbox],[role=radio],[role=switch],[role=slider],[role=textbox],[role=combobox],[tabindex]:not([tabindex="-1"])';
  for(const el of Array.from(document.querySelectorAll(interactive))){
   if(!visible(el))continue;
   if(nameOf(el)==='')add('interactive-name',el,'no accessible name');
  }

  // 2. form-label: every form control has a programmatic label (a title alone or a placeholder is not a label).
  for(const el of Array.from(document.querySelectorAll('input:not([type=hidden]):not([type=submit]):not([type=button]):not([type=reset]):not([type=image]),select,textarea'))){
   if(!visible(el))continue;
   const f=el as HTMLInputElement;
   const labelled=(f.labels&&f.labels.length>0&&Array.from(f.labels).some((l)=>text(l)!==''))||(el.getAttribute('aria-label')??'').trim()!==''||(labelledBy(el)??'')!=='';
   if(!labelled)add('form-label',el,'control has no label, aria-label or aria-labelledby');
  }

  // 3. heading-order: one level-1 heading per page state, none skipped when going deeper, none empty.
  const headings=Array.from(document.querySelectorAll('h1,h2,h3,h4,h5,h6,[role=heading]')).filter(visible);
  let previous=0;
  const level=(h:Element):number=>h.hasAttribute('aria-level')?Number(h.getAttribute('aria-level')):h.tagName.length===2&&h.tagName[0]==='H'?Number(h.tagName[1]):2;
  const h1s=headings.filter((h)=>level(h)===1);
  if(headings.length>0&&h1s.length!==1)out.push({rule:'heading-order',node:'document',detail:`${h1s.length} level-1 headings, want exactly 1`});
  for(const h of headings){
   const l=level(h);
   if(text(h)==='')add('heading-order',h,'empty heading');
   if(previous===0&&l!==1)add('heading-order',h,`first heading is level ${l}, want 1`);
   else if(previous!==0&&l>previous+1)add('heading-order',h,`level ${l} follows level ${previous}`);
   previous=l;
  }

  // 4. landmarks: exactly one main; at most one banner; same-role landmarks have unique accessible names.
  const mains=Array.from(document.querySelectorAll('main,[role=main]')).filter(visible);
  if(mains.length!==1)out.push({rule:'landmarks',node:'document',detail:`${mains.length} main landmarks, want exactly 1`});
  const banners=Array.from(document.querySelectorAll('header,[role=banner]')).filter((h)=>visible(h)&&!h.closest('main,section,article,aside,nav'));
  if(banners.length>1)out.push({rule:'landmarks',node:'document',detail:`${banners.length} banner landmarks`});
  const groups=new Map<string,Element[]>();
  const push=(role:string,el:Element):void=>{const g=groups.get(role)??[];g.push(el);groups.set(role,g);};
  for(const el of Array.from(document.querySelectorAll('nav,[role=navigation]')).filter(visible))push('navigation',el);
  for(const el of Array.from(document.querySelectorAll('section,[role=region]')).filter((s)=>visible(s)&&(s.hasAttribute('aria-label')||s.hasAttribute('aria-labelledby'))))push('region',el);
  for(const el of Array.from(document.querySelectorAll('form,[role=form]')).filter((s)=>visible(s)&&(s.hasAttribute('aria-label')||s.hasAttribute('aria-labelledby'))))push('form',el);
  for(const [role,els] of groups){
   const seen=new Map<string,Element>();
   for(const el of els){
    const n=labelledBy(el)||(el.getAttribute('aria-label')??'').trim(); // a landmark is named by its label, never by its content
    if(n===''&&els.length>1){add('landmarks',el,`${role} landmark without a name among ${els.length}`);continue;}
    const prior=seen.get(n);
    if(prior)add('landmarks',el,`${role} landmark name "${n}" is not unique`);
    else seen.set(n,el);
   }
  }

  // 5. status-text: every status/alert/live node and every state-carrying node says its state in words, never in colour alone.
  const stateNodes=Array.from(document.querySelectorAll('[role=status],[role=alert],[data-state],[data-status],[data-outcome],[data-health],.status,.badge')).filter(visible);
  for(const el of stateNodes){
   if(el.getAttribute('data-outcome')==='idle')continue;
   if(!/[A-Za-z]{2,}/.test(text(el)))add('status-text',el,'state node has no words (colour or symbol only)');
  }

  // 6. aria-references: ids referenced by aria attributes and skip links exist, and ids are unique.
  for(const attr of ['aria-labelledby','aria-describedby','aria-controls','aria-owns']){
   for(const el of Array.from(document.querySelectorAll(`[${attr}]`))){
    for(const i of (el.getAttribute(attr)??'').split(/\s+/).filter(Boolean))if(!byId(i))add('aria-references',el,`${attr} references missing id "${i}"`);
   }
  }
  const ids=new Map<string,number>();
  for(const el of Array.from(document.querySelectorAll('[id]')))ids.set(el.id,(ids.get(el.id)??0)+1);
  for(const [i,n] of ids)if(n>1)out.push({rule:'aria-references',node:`#${i}`,detail:`id used ${n} times`});
  for(const a of Array.from(document.querySelectorAll('a[href^="#"]'))){
   const frag=(a.getAttribute('href')??'').slice(1);
   if(/^[A-Za-z][\w-]*$/.test(frag)&&!byId(frag))add('aria-references',a,`in-page link target "#${frag}" does not exist`);
  }

  // 7. svg-alternative: every drawing is hidden from assistive technology or is an image with a name.
  for(const svg of Array.from(document.querySelectorAll('svg')).filter((s)=>s.getAttribute('aria-hidden')!=='true')){
   if(svg.closest('[aria-hidden=true]'))continue;
   if(svg.getAttribute('role')!=='img'||nameOf(svg)==='')add('svg-alternative',svg,'svg is neither aria-hidden nor a named img');
  }
  for(const img of Array.from(document.querySelectorAll('img')).filter(visible))if(!img.hasAttribute('alt'))add('svg-alternative',img,'img without alt');

  // 8. table-structure: a data table is named and its headers are scoped.
  for(const t of Array.from(document.querySelectorAll('table')).filter(visible)){
   if(!t.querySelector('caption')&&(labelledBy(t)??'')===''&&(t.getAttribute('aria-label')??'').trim()==='')add('table-structure',t,'table has no caption or name');
   for(const th of Array.from(t.querySelectorAll('th')))if(!th.hasAttribute('scope')&&!th.closest('thead'))add('table-structure',th,'row header without scope');
  }

  // 9. document: language, title, zoom is not disabled.
  if(!document.documentElement.getAttribute('lang'))out.push({rule:'document',node:'html',detail:'no lang attribute'});
  if(document.title.trim()==='')out.push({rule:'document',node:'title',detail:'empty title'});
  const vp=document.querySelector('meta[name=viewport]')?.getAttribute('content')??'';
  if(/user-scalable\s*=\s*(no|0)|maximum-scale\s*=\s*1(\.0)?\b/.test(vp))out.push({rule:'document',node:'meta[viewport]',detail:'zoom is disabled'});

  // 10. contrast: WCAG 2.x ratio of rendered text over the first opaque ancestor background (no images or gradients exist under the CSP).
  const parse=(c:string):[number,number,number,number]|null=>{const m=c.match(/rgba?\(([^)]+)\)/);if(!m||!m[1])return null;const p=m[1].split(/[ ,/]+/).filter(Boolean).map(Number);return [p[0]??0,p[1]??0,p[2]??0,p[3]??1];};
  const lum=(c:[number,number,number,number]):number=>{const f=(v:number)=>{const s=v/255;return s<=0.03928?s/12.92:Math.pow((s+0.055)/1.055,2.4);};return 0.2126*f(c[0])+0.7152*f(c[1])+0.0722*f(c[2]);};
  const backdrop=(el:Element):[number,number,number,number]=>{for(let n:Element|null=el;n;n=n.parentElement){const c=parse(getComputedStyle(n).backgroundColor);if(c&&c[3]>=0.99)return c;}return [255,255,255,1];};
  const walker=document.createTreeWalker(document.body,NodeFilter.SHOW_TEXT);
  const checked=new Set<Element>();
  for(let n=walker.nextNode();n;n=walker.nextNode()){
   const el=n.parentElement;
   if(!el||checked.has(el)||(n.textContent??'').trim()===''||!visible(el))continue;
   if(el.closest('script,style,noscript,svg'))continue;
   checked.add(el);
   const s=getComputedStyle(el);
   if(el instanceof HTMLButtonElement&&el.disabled)continue;
   const fg=parse(s.color),bg=backdrop(el);
   if(!fg)continue;
   const blend=(a:number,b:number):number=>a*fg[3]+b*(1-fg[3]);
   const eff:[number,number,number,number]=[blend(fg[0],bg[0]),blend(fg[1],bg[1]),blend(fg[2],bg[2]),1];
   const l1=lum(eff),l2=lum(bg),ratio=(Math.max(l1,l2)+0.05)/(Math.min(l1,l2)+0.05);
   const size=parseFloat(s.fontSize),bold=Number(s.fontWeight)>=700;
   const need=size>=24||(size>=18.66&&bold)?3:4.5;
   if(ratio<need)add('contrast',el,`ratio ${ratio.toFixed(2)} below ${need} for "${(n.textContent??'').trim().slice(0,40)}"`);
  }
  return out;
 });
}

export interface Stop{tag:string;name:string;outline:string;shadow:string;inView:boolean;path:string}

/** Presses the real Tab key up to `max` times from the current focus and records each stop. The keyboard is the subject:
 * what is measured is the computed style the browser applies to the element that really holds focus after the key press. */
export async function tabStops(page:Page,max:number):Promise<Stop[]>{
 const stops:Stop[]=[];
 for(let i=0;i<max;i++){
  await page.keyboard.press('Tab');
  const stop=await page.evaluate(()=>{
   const el=document.activeElement;
   if(!el||el===document.body)return null;
   const s=getComputedStyle(el);
   const r=el.getBoundingClientRect();
   const own=(el.getAttribute('aria-label')??'').trim()||(((el as HTMLElement).innerText??el.textContent)??'').replace(/\s+/g,' ').trim()||(el.getAttribute('title')??'');
   const labels=(el as HTMLInputElement).labels?Array.from((el as HTMLInputElement).labels??[]).map((l)=>(l.textContent??'').replace(/\s+/g,' ').trim()).join(' '):'';
   const path:string[]=[];
   for(let n:Element|null=el;n&&n!==document.body;n=n.parentElement)path.unshift(n.tagName.toLowerCase()+(n.id?`#${n.id}`:''));
   return {tag:el.tagName.toLowerCase(),name:(labels||own).slice(0,60),outline:`${s.outlineStyle} ${s.outlineWidth}`,shadow:s.boxShadow,inView:r.width>0&&r.height>0,path:path.join('>')};
  });
  if(stop===null)break;
  if(stops.length>0&&stops[stops.length-1]?.path===stop.path&&stops[stops.length-1]?.name===stop.name&&stops.length>1&&stops[stops.length-2]?.path===stop.path)break;
  stops.push(stop);
 }
 return stops;
}

/** A stop shows where focus is when the browser draws a visible outline or a box shadow ring on it. */
export const focusIndicated=(s:Stop):boolean=>(!s.outline.startsWith('none')&&!s.outline.endsWith(' 0px'))||(s.shadow!==''&&s.shadow!=='none');
