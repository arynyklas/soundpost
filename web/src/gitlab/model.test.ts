// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import { describe, expect, test } from 'bun:test';
import * as React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { ApiFault } from '../api/types';
import { CopyMenu } from './CopyMenu';
import { GitlabCreateDialog, GitlabLink } from './GitlabCreateDialog';
import { answerWords, copyItemsFor, copyOutcomeOf, copyWords, labelsText, parseLabels, previewUnavailableWords, previousWords, refusedWords, safeHref } from './model';

const LINK = { url: 'https://git.example.test/shop/web/-/issues/7', gitlab_project: 'shop/web', iid: '7' };

describe('copy', () => {
 test('an incident offers link, description and timeline; an issue has no timeline', () => {
  expect(copyItemsFor('incident').map((i) => i.format)).toEqual(['link', 'description', 'timeline']);
  expect(copyItemsFor('issue').map((i) => i.format)).toEqual(['link', 'description']);
 });
 test('a copied text says which one was copied; a refused clipboard says so and does not claim a copy', () => {
  const o = copyOutcomeOf('timeline', { kind: 'ok', data: { markdown: '# t' } });
  expect(o).toEqual({ kind: 'copied', format: 'timeline', markdown: '# t' });
  expect(copyWords(o, true)).toBe('Timeline copied as Markdown.');
  expect(copyWords(o, false)).toContain('did not allow copying');
  expect(copyWords(o, false)).not.toContain('copied as Markdown');
 });
 test('a missing public origin is said in words; any other unavailable reason is generic, never the raw code', () => {
  const origin = copyOutcomeOf('link', { kind: 'ok', data: { state: 'not_available', reason: 'public_origin_not_configured' } });
  expect(copyWords(origin, true)).toContain('public address is not configured');
  expect(copyWords(origin, true)).toContain('Nothing was copied');
  const other = copyOutcomeOf('link', { kind: 'ok', data: { state: 'not_available', reason: 'weird_internal_code' } });
  expect(copyWords(other, true)).not.toContain('weird_internal_code');
 });
 test('a route this installation does not serve and a fault both say nothing was copied', () => {
  expect(copyWords(copyOutcomeOf('link', { kind: 'not_built' }), true)).toContain('not available yet');
  expect(copyWords(copyOutcomeOf('link', { kind: 'fault', fault: new ApiFault(404, 'not_found', '', '') }), true)).toContain('not found or is not available to this account');
  expect(copyWords(copyOutcomeOf('link', { kind: 'fault', fault: new ApiFault(500, 'unavailable', '', '') }), true)).toContain('Nothing was copied');
 });
 test('the closed menu renders the button only', () => {
  const html = renderToStaticMarkup(React.createElement(CopyMenu, { entity: 'incident', org: 'a'.repeat(32), project: 'b'.repeat(32), id: 'c'.repeat(32) }));
  expect(html).toContain('aria-haspopup="menu"');
  expect(html).toContain('aria-expanded="false"');
  expect(html).not.toContain('role="menuitem"');
 });
});

describe('create outcomes are spelled in words', () => {
 test('linked, created or already linked, never a second issue', () => {
  expect(answerWords({ state: 'linked', created: true, link: LINK }, 'incident')).toMatchObject({ tone: 'ok', title: 'GitLab issue created and linked' });
  const again = answerWords({ state: 'linked', created: false, link: LINK }, 'issue');
  expect(again.title).toBe('Already linked');
  expect(again.text).toContain('No second GitLab issue was created');
  expect(again.text).toContain('error issue');
 });
 test('unknown is never a failure to retry: it says the issue may exist and points at the lookup', () => {
  const w = answerWords({ state: 'unknown' }, 'incident');
  expect(w.title).toBe('Outcome unknown');
  expect(w.text).toContain('may exist');
  expect(w.text).toContain('Check whether it was created');
  expect(w.text).toContain('no second issue is created blindly');
 });
 test('refused names the closed code in words and keeps the code for support; an unknown code is not echoed in the sentence', () => {
  const w = answerWords({ state: 'refused', code: 'gitlab_forbidden' }, 'incident');
  expect(w.text).toContain('no permission');
  expect(w.code).toBe('gitlab_forbidden');
  expect(refusedWords('gitlab_unauthorized')).toContain('token');
  expect(refusedWords('gitlab_not_found')).toContain('project mapping');
  expect(refusedWords('gitlab_made_up')).not.toContain('gitlab_made_up');
  for (const code of ['gitlab_invalid', 'gitlab_unprocessable', 'gitlab_rate_limited', 'gitlab_redirect_refused', 'gitlab_egress_blocked', 'gitlab_tls_failed', 'gitlab_unreachable']) expect(refusedWords(code), code).not.toBe(refusedWords('gitlab_made_up'));
  expect(previousWords({ state: 'unknown', code: 'gitlab_timeout' })).toContain('may have reached GitLab');
  expect(previousWords({ state: 'creating' })).toContain('creating this GitLab issue now');
  expect(previousWords({ state: 'refused', code: 'gitlab_forbidden' })).toContain('no permission');
 });
 test('in progress, not found, not built and faults', () => {
  expect(answerWords({ state: 'in_progress' }, 'incident').title).toBe('Another create is running');
  expect(answerWords({ state: 'not_found' }, 'incident').text).toContain('Nothing was created by this check');
  expect(answerWords({ state: 'not_built' }, 'incident').title).toBe('GitLab issue creation is not available yet');
  expect(answerWords({ state: 'fault', fault: new ApiFault(429, 'rate_limited', '', '') }, 'incident').text).toContain('Too many requests');
 });
 test('a preview that is unavailable says why in words', () => {
  expect(previewUnavailableWords('gitlab_not_connected')).toContain('not connected');
  expect(previewUnavailableWords('gitlab_project_not_mapped')).toContain('not mapped');
  expect(previewUnavailableWords('anything_else')).toBe('GitLab issue creation is not available for this project.');
 });
});

describe('labels and links', () => {
 test('labels are one comma separated line without empties or duplicates', () => {
  expect(parseLabels(' incident, , severity::major,incident ')).toEqual(['incident', 'severity::major']);
  expect(labelsText(['a', 'b'])).toBe('a, b');
  expect(parseLabels('x'.repeat(65))).toEqual([]);
 });
 test('only a web address becomes a link', () => {
  expect(safeHref('https://git.example.test/a')).toBe('https://git.example.test/a');
  expect(safeHref('javascript:alert(1)')).toBeUndefined();
  expect(safeHref('/relative')).toBeUndefined();
  const html = renderToStaticMarkup(React.createElement(GitlabLink, { link: { ...LINK, url: 'javascript:alert(1)' } }));
  expect(html).not.toContain('<a');
  expect(html).toContain('shop/web#7');
  expect(renderToStaticMarkup(React.createElement(GitlabLink, { link: LINK }))).toContain('rel="noopener noreferrer"');
 });
 test('the dialog renders nothing while closed', () => {
  const html = renderToStaticMarkup(React.createElement(GitlabCreateDialog, { entity: 'incident', org: 'a'.repeat(32), project: 'b'.repeat(32), id: 'c'.repeat(32), subject: 'x', open: false, onClose: () => undefined }));
  expect(html).toBe('');
 });
});
