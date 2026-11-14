// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// Provisioning step of the e2e suite. It is NOT a test of the product and is not part of `playwright test` (the main config's
// testDir is ./e2e); run it once per fresh server through playwright.provision.config.ts, before the suite:
//   SOUNDPOST_TEST_ORIGIN, SOUNDPOST_SCOPE_EMAIL, SOUNDPOST_SCOPE_PASSWORD  the real server and its bootstrapped instance owner
//   SOUNDPOST_OIDC_ISSUER   the issuer URL of the OIDC fixture (web/fixtures/oidc) the server was told to trust
//   PROVISION_OUT           file that receives `export NAME='value'` lines (mode 0600) for the suite
// Everything goes through the real admin commands: an organization with one project, a local-password member (auth.spec.ts),
// a member the fixture's `mapped-subject` identity maps to (OIDC mapped), and one single sign-on provider.
import {test,expect} from '@playwright/test';
import {randomBytes} from 'node:crypto';
import {writeFileSync} from 'node:fs';
import {adminCommand,createOrg,createProject,id,login,origin,owner} from '../e2e/support/real';

function required(name:string):string{
 const value=process.env[name];
 if(!value)throw new Error(`${name} is required`);
 return value;
}
const password=():string=>randomBytes(18).toString('base64url');

test('provision the accounts and the OIDC provider the suite needs',async({page})=>{
 const out=required('PROVISION_OUT');
 const issuer=new URL(required('SOUNDPOST_OIDC_ISSUER')).origin;
 const o=owner();
 await login(page,o.email,o.password);
 const org=await createOrg(page,'e2e provisioned org');
 await createProject(page,org,'e2e provisioned project');
 const local={id:id(),email:`auth-${id().slice(0,8)}@example.test`,password:password()};
 const mapped={id:id(),email:`oidc-${id().slice(0,8)}@example.test`,password:password()};
 for(const user of [local,mapped]){
  await adminCommand(page,org,'create_user',{id:user.id,email:user.email,password:user.password});
  await adminCommand(page,org,'membership',{user_id:user.id,enabled:true});
 }
 const provider=id();
 await adminCommand(page,org,'sso',{id:provider,config:{Issuer:issuer,ClientID:'soundpost-browser',RedirectURL:`${origin()}/api/v1/oidc/callback`,Subjects:{'mapped-subject':mapped.id}}});
 const values:[string,string][]=[['SOUNDPOST_TEST_EMAIL',local.email],['SOUNDPOST_TEST_PASSWORD',local.password],['SOUNDPOST_TEST_ORG',org],['SOUNDPOST_TEST_PROVIDER',provider],['SOUNDPOST_ELEVATION_EMAIL',o.email],['SOUNDPOST_ELEVATION_PASSWORD',o.password]];
 writeFileSync(out,values.map(([k,v])=>`export ${k}='${v}'\n`).join(''),{mode:0o600});
 expect(values.length).toBe(6);
});
