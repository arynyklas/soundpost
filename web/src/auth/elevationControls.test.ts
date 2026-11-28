// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
// The elevation request form and the active-elevation notice are offered on the account page and beside the Explore query (navigating clears an elevation, so it
// is requested where it is spent). The same component serves both, and says in words whether an elevation is active.
import { describe, expect, test } from 'bun:test';
import * as React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { ElevationControls, SessionContext, type ElevationState, type SessionValue } from './ElevationDialog';

const none = (): void => undefined;
const value = (elevation: ElevationState | null): SessionValue => ({
 session: { csrf: 'c', user: 'u', expires: '100' } as SessionValue['session'],
 epoch: 0,
 refresh: async () => undefined,
 elevation,
 elevate: none,
 fail: none,
 orgs: [{ id: 'a'.repeat(32), name: 'Acme' }],
 orgState: '',
 error: '',
 busy: false,
 secret: '',
 codes: [],
 clearCodes: none,
 clearElevation: none,
 action: async () => undefined,
});
const render = (v: SessionValue | null): string => renderToStaticMarkup(React.createElement(SessionContext.Provider, { value: v }, React.createElement(ElevationControls)));

describe('ElevationControls', () => {
 test('without a session there is nothing to offer', () => expect(render(null)).toBe(''));
 test('offers the request form and no active notice while no elevation is held', () => {
  const html = render(value(null));
  expect(html).toContain('Request scoped elevation');
  expect(html).not.toContain('Scoped elevation active');
  expect(html).not.toContain('Clear elevated view');
 });
 test('says an elevation is active, for which organization, with the control that clears it', () => {
  const html = render(value({ id: 'e'.repeat(32), expires: String(Math.floor(Date.now() / 1000) + 900), orgs: ['a'.repeat(32)] }));
  expect(html).toContain('Request scoped elevation');
  expect(html).toContain('Scoped elevation active');
  expect(html).toContain('a'.repeat(32));
  expect(html).toContain('Clear elevated view');
 });
});
