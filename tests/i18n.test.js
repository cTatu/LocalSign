// tests/i18n.test.js — every language ships the exact same keys, non-empty.
import { describe, it, expect } from 'vitest';
import { STRINGS, LANGS, t, tx, detectLang } from '../js/i18n.js';

describe('i18n parity', () => {
  it('all langs share identical key sets', () => {
    const base = Object.keys(STRINGS.en).sort();
    expect(base.length).toBeGreaterThan(30);
    for (const lang of LANGS) {
      expect(Object.keys(STRINGS[lang]).sort()).toEqual(base);
    }
  });
  it('no empty strings', () => {
    for (const lang of LANGS) {
      for (const [k, v] of Object.entries(STRINGS[lang])) {
        expect(typeof v).toBe('string');
        expect(v.length, `${lang}.${k}`).toBeGreaterThan(0);
      }
    }
  });
  it('falls back to key for unknown entries', () => {
    expect(t('nope_missing_xyz')).toBe('nope_missing_xyz');
  });
  it('interpolates vars', () => {
    expect(tx('signed_by', { n: 'X' })).toContain('X');
    expect(tx('signed_by', { n: 'X' })).not.toContain('{n}');
  });
  it('detectLang is a supported language', () => {
    expect(LANGS.includes(detectLang())).toBe(true);
  });
});
