// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import { describe, expect, test } from 'bun:test';
import type { LifecycleOperation } from '../api/types';
import { operationWords } from './ProjectSettings';

const op = (over: Partial<LifecycleOperation>): LifecycleOperation => ({ id: 'a'.repeat(32), state: 'ready', phase: 'fencing', physical: 'pending', generation: '9', pending_groups: 1, applied_barriers: 63, holds: 0, physical_deadline: '1800000000000000000', backup_deadline: '1800086400000000000', ...over });

describe('operation progress is never reported as success early', () => {
 test('fencing with an unavailable group is pending, with the real counts', () => {
  const w = operationWords(op({}), 'UTC');
  expect(w.success).toBe(false);
  expect(w.label).toContain('Pending');
  expect(w.text).toContain('63 confirmed, 1 group still pending');
  expect(w.text).toContain('not success');
 });
 test('logically complete is not physical erasure and names both deadlines', () => {
  const w = operationWords(op({ phase: 'complete', pending_groups: 0, applied_barriers: 64 }), 'UTC');
  expect(w.success).toBe(false);
  expect(w.text).toContain('Physical erasure is still pending');
  expect(w.text).toMatch(/due by .*2027|due by .*2026/);
  expect(w.text).toContain('backup copies remain until');
 });
 test('only complete with physical erasure done is finished, and backups still carry a deadline', () => {
  const w = operationWords(op({ phase: 'complete', physical: 'done', pending_groups: 0, applied_barriers: 64 }), 'UTC');
  expect(w.success).toBe(true);
  expect(w.text).toContain('Backup copies remain until');
 });
 test('a legal hold and a failure are not success and do not claim erasure', () => {
  const held = operationWords(op({ phase: 'held', physical: 'held', holds: 2 }), 'UTC');
  expect([held.success, held.label]).toEqual([false, 'Held']);
  expect(held.text).toContain('has not been erased');
  const heldAfterComplete = operationWords(op({ phase: 'complete', physical: 'held' }), 'UTC');
  expect(heldAfterComplete.success).toBe(false);
  expect(heldAfterComplete.text).toContain('not erased');
  const failed = operationWords(op({ phase: 'failed', safe_fault: 'barrier_failed' }), 'UTC');
  expect([failed.success, failed.label]).toEqual([false, 'Failed']);
  expect(failed.text).toContain('barrier_failed');
 });
 test('an operation the installation cannot report is not available, not success', () => {
  const bare = operationWords({ id: 'a'.repeat(32), state: 'not_available', reason: 'lifecycle_operation_store_not_wired', generation: '0', pending_groups: 0, applied_barriers: 0, holds: 0, physical_deadline: '0', backup_deadline: '0' }, 'UTC');
  expect(bare.success).toBe(false);
  expect(bare.label).toBe('Not available');
 });
});
