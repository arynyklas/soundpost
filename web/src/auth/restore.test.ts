// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import { describe, expect, test } from 'bun:test';
import { offersReauthorization, reconciliation, type RestoreItem } from './RestorePanel';

const ID = 'a'.repeat(32);
describe('restore reauthorization', () => {
 test('a reconciliation body names only the identifiers the listed item has, plus the reason', () => {
  const grant: RestoreItem = { kind: 'grant', org: ID, user: 'b'.repeat(32), project: 'c'.repeat(32), label: 'grant' };
  expect(reconciliation(grant, 'why')).toEqual({ Kind: 'grant', Org: ID, User: 'b'.repeat(32), Project: 'c'.repeat(32), Reason: 'why' });
  const integration: RestoreItem = { kind: 'integration', org: ID, key: 'destination:' + ID, label: 'destination' };
  expect(reconciliation(integration, 'r')).toEqual({ Kind: 'integration', Org: ID, Key: 'destination:' + ID, Reason: 'r' });
  expect(reconciliation({ kind: 'source', source: ID, label: 's' }, 'r')).toEqual({ Kind: 'source', Source: ID, Reason: 'r' });
 });
 test('no old single sign-on provider is offered for activation, every other item is', () => {
  expect(offersReauthorization({ kind: 'integration', org: ID, key: 'sso:' + ID, label: 'sso' })).toBe(false);
  expect(offersReauthorization({ kind: 'integration', org: ID, key: 'destination:' + ID, label: 'destination' })).toBe(true);
  expect(offersReauthorization({ kind: 'account', user: ID, label: 'a' })).toBe(true);
 });
});
