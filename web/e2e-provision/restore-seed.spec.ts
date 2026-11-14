// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// Seeding step of the restore browser test (e2e/restore.spec.ts). NOT a test of the product: run once through
// playwright.provision.config.ts against the SOURCE installation before it is backed up. Everything goes through the real admin
// commands: an organization with a project, a local reader with a project grant, a second organization administrator, one
// single sign-on provider (an integration the restored installation must never offer to reactivate).
//   SOUNDPOST_TEST_ORIGIN, SOUNDPOST_SCOPE_EMAIL, SOUNDPOST_SCOPE_PASSWORD  the real server and its bootstrapped instance owner
//   PROVISION_OUT                                                            file that receives `export NAME='value'` lines (mode 0600)
import {test,expect} from '@playwright/test';
import {writeFileSync} from 'node:fs';
import {adminCommand,createOrg,createProject,createReader,id,login,origin,owner} from '../e2e/support/real';

test('seed the installation that is backed up and restored',async({page})=>{
 const out=process.env.PROVISION_OUT;
 if(!out)throw new Error('PROVISION_OUT is required');
 const o=owner();
 await login(page,o.email,o.password);
 const org=await createOrg(page,'restore e2e org');
 const project=await createProject(page,org,'restore e2e project');
 const reader=await createReader(page,org,[project]);
 const admin={id:id(),email:`restored-admin-${id().slice(0,8)}@example.test`,password:`restored admin password ${id().slice(0,8)}`};
 await adminCommand(page,org,'create_user',{id:admin.id,email:admin.email,password:admin.password});
 await adminCommand(page,org,'membership',{user_id:admin.id,enabled:true});
 await adminCommand(page,org,'org_admin',{user_id:admin.id,enabled:true});
 const provider=id();
 await adminCommand(page,org,'sso',{id:provider,config:{Issuer:'https://127.0.0.1:18799',ClientID:'soundpost-browser',RedirectURL:`${origin()}/api/v1/oidc/callback`,Subjects:{'restored-subject':reader.id}}});
 const values:[string,string][]=[['SOUNDPOST_RESTORE_ORG',org],['SOUNDPOST_RESTORE_READER_EMAIL',reader.email],['SOUNDPOST_RESTORE_READER_PASSWORD',reader.password],['SOUNDPOST_RESTORE_ADMIN_EMAIL',admin.email],['SOUNDPOST_RESTORE_OWNER_EMAIL',o.email],['SOUNDPOST_RESTORE_OWNER_PASSWORD',o.password],['SOUNDPOST_RESTORE_PROVIDER',provider]];
 writeFileSync(out,values.map(([k,v])=>`export ${k}='${v}'\n`).join(''),{mode:0o600});
 expect(values.length).toBe(7);
});
