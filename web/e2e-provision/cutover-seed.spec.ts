// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// Seeding step of the real-cutover browser test (e2e/cutover-real.spec.ts). NOT a test of the product: run once through
// playwright.provision.config.ts against the installation `h.sh up` bootstrapped, before the cutover harness (e2e-harness/cutover.sh)
// stops it and commits the cutover with the operator facade. Everything goes through the real admin and source routes: an
// organization with a project, a notification destination with a sealed secret (what a shadow decision is made for) and one
// registered source (what the cutover's frontier names).
//   SOUNDPOST_TEST_ORIGIN, SOUNDPOST_SCOPE_EMAIL, SOUNDPOST_SCOPE_PASSWORD  the real server and its bootstrapped instance owner
//   PROVISION_OUT                                                            file that receives `export NAME='value'` lines (mode 0600)
import {test,expect} from '@playwright/test';
import {writeFileSync} from 'node:fs';
import {adminCommand,createOrg,createProject,id,login,onboardMetricSource,owner} from '../e2e/support/real';

test('seed the organization, project, destination and source the real cutover is committed for',async({page})=>{
 const out=process.env.PROVISION_OUT;
 if(!out)throw new Error('PROVISION_OUT is required');
 await login(page,owner().email,owner().password);
 const org=await createOrg(page,'real cutover e2e org');
 const project=await createProject(page,org,'real cutover e2e project');
 await adminCommand(page,org,'destination',{id:id(),secret:'REAL-CUTOVER-E2E-DESTINATION-SECRET',config:{type:'webhook',endpoint:'https://hooks.example.test/real-cutover-e2e',enabled:true}});
 const source=await onboardMetricSource(page,org,project);
 const values:[string,string][]=[['CUTOVER_ORG',org],['CUTOVER_PROJECT',project],['CUTOVER_SOURCE',source.id],['CUTOVER_SOURCE_VERSION',source.policyRevision]];
 writeFileSync(out,values.map(([k,v])=>`export ${k}='${v}'\n`).join(''),{mode:0o600});
 expect(values.every(([,v])=>v.length>0)).toBe(true);
});
