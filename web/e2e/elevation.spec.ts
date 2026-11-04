// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import {test,expect} from '@playwright/test';
const admin=process.env.SOUNDPOST_ELEVATION_EMAIL;
const password=process.env.SOUNDPOST_ELEVATION_PASSWORD;
const selected=process.env.SOUNDPOST_TEST_ORG;
if(!admin||!password||!selected)throw new Error('A real separate MFA-free instance-admin fixture and administered organization are required for elevation acceptance');
test('selected organization elevation clears on navigation and expires at fifteen minutes',async({page})=>{
 test.setTimeout(17*60*1000);
 await page.goto('/');await page.getByLabel('Email',{exact:true}).fill(admin);await page.getByLabel('Password',{exact:true}).fill(password);await page.getByRole('button',{name:'Sign in',exact:true}).click();await page.getByRole('button',{name:'Request scoped elevation'}).click();await page.getByRole('checkbox',{name:selected,exact:true}).check();await page.getByLabel('Reason',{exact:true}).fill('Generic browser acceptance scoped investigation');await page.getByLabel('Current password',{exact:true}).fill(password);await page.getByRole('button',{name:'Reauthenticate and elevate'}).click();await expect(page.getByRole('heading',{name:'Scoped elevation active'})).toBeVisible();
 await page.evaluate(()=>{location.hash='access';});await expect(page.getByRole('heading',{name:'Scoped elevation active'})).toBeHidden();
 await page.getByRole('button',{name:'Request scoped elevation'}).click();await page.getByRole('checkbox',{name:selected,exact:true}).check();await page.getByLabel('Reason',{exact:true}).fill('Generic browser acceptance expiry');await page.getByLabel('Current password',{exact:true}).fill(password);await page.getByRole('button',{name:'Reauthenticate and elevate'}).click();await expect(page.getByRole('heading',{name:'Scoped elevation active'})).toBeVisible();
 // Real wall-clock expiry, not page.clock or a simulated server session.
 await expect(page.getByRole('heading',{name:'Scoped elevation active'})).toBeHidden({timeout:16*60*1000});await page.getByRole('button',{name:'Sign out',exact:true}).click();expect((await page.request.get('/api/v1/session')).status()).toBe(401);
});
