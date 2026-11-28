// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import { describe, expect, test } from 'bun:test';
import { isTheme, resolveTheme } from './theme';

describe('theme choice', () => {
 test('dark is the default: nothing stored and no light preference', () => { expect(resolveTheme(null, false)).toBe('dark'); });
 test('the browser preference applies only while nothing is stored', () => {
  expect(resolveTheme(null, true)).toBe('light');
  expect(resolveTheme('dark', true)).toBe('dark');
  expect(resolveTheme('light', false)).toBe('light');
 });
 test('a stored value that is not a theme is ignored, not trusted', () => {
  expect(resolveTheme('<script>', true)).toBe('light');
  expect(resolveTheme('', false)).toBe('dark');
  expect(isTheme('blue')).toBe(false);
  expect(isTheme('dark')).toBe(true);
 });
});
