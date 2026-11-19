// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
// The parts of a job view (attempts, health, observer, loss) are shown with the state the server sent, in words, and a part's reason
// is a sentence that says what it means, never the generic "Not available.". The server marks the observer part stale when the schedule
// observer's newest report is older than its stale-after limit (internal/httpapi/jobs_view.go).
import { describe, expect, test } from 'bun:test';
import * as React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import type { ViewSection } from '../api/types';
import { reasonText, SectionList } from '../app/StatusPanel';
import { EvidenceSections } from '../evidence/Sections';

const render = (el: React.ReactElement): string => renderToStaticMarkup(el);
const text = (html: string): string => html.replace(/<[^>]+>/g, '').replace(/&#x27;/g, "'").replace(/&amp;/g, '&').replace(/\s+/g, ' ').trim();
const item = (html: string, name: string): string => /<li[^>]*>.*?<\/li>/gs.exec(html.slice(html.indexOf(`data-section="${name}"`) - 4))?.[0] ?? '';

const STALE: ViewSection[] = [
 { name: 'attempts', state: 'ready' },
 { name: 'health', state: 'incomplete', reason: 'job_evidence_incomplete' },
 { name: 'observer', state: 'stale', reason: 'schedule_observer_stale' },
 { name: 'loss', state: 'ready' },
] as ViewSection[];
const FRESH: ViewSection[] = STALE.map((s) => s.name === 'observer' ? { name: 'observer', state: 'ready' } : s) as ViewSection[];

describe('a stale schedule observer is a stale part, in words, with what staleness means', () => {
 for (const [label, List] of [['EvidenceSections (the job page)', EvidenceSections], ['SectionList', SectionList]] as const) {
  test(label, () => {
   const html = render(React.createElement(List, { sections: STALE }));
   const observer = item(html, 'observer');
   expect(observer).toContain('data-state="stale"');
   const words = text(observer);
   expect(words).toContain('observer: Stale');
   expect(words).toContain('newest report is older than its stale-after limit');
   expect(words).toContain('unknown rather than last observed');
   expect(words).not.toContain('Not available');
   // The other parts keep their own states.
   expect(item(html, 'attempts')).toContain('data-state="ready"');
   expect(item(html, 'health')).toContain('data-state="incomplete"');
   expect(item(html, 'loss')).toContain('data-state="ready"');
   expect(html.match(/data-state="stale"/g)).toHaveLength(1);
  });
  test(`${label}: a fresh observer is Ready and nothing is stale`, () => {
   const html = render(React.createElement(List, { sections: FRESH }));
   expect(text(item(html, 'observer'))).toBe('observer: Ready');
   expect(html).not.toContain('data-state="stale"');
   expect(html).not.toContain('Stale');
  });
 }
});

describe('the reasons a job part can carry are sentences, not the generic fallback', () => {
 test('each reason of internal/httpapi/jobs_view.go has its own words', () => {
  const generic = reasonText('a_code_from_the_future');
  expect(generic).toBe('Not available.');
  const codes = ['job_evidence_incomplete', 'schedule_observer_stale', 'no_schedule_observer', 'evidence_loss_recorded'];
  const sentences = codes.map(reasonText);
  for (const s of sentences) expect(s).not.toBe(generic);
  expect(new Set(sentences).size).toBe(codes.length);
 });
 test('an observer that never reported is not available, and a recorded loss is partial, each in words', () => {
  const html = render(React.createElement(EvidenceSections, { sections: [
   { name: 'observer', state: 'not_available', reason: 'no_schedule_observer' },
   { name: 'loss', state: 'incomplete', reason: 'evidence_loss_recorded' },
  ] as ViewSection[] }));
  expect(text(item(html, 'observer'))).toContain('observer: Not available');
  expect(text(item(html, 'observer'))).toContain('No external schedule observer has reported');
  expect(text(item(html, 'loss'))).toContain('loss: Partial');
  expect(text(item(html, 'loss'))).toContain('Producer or evidence loss is recorded');
 });
});
