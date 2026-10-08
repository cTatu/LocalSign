// tests/api.test.js — backend origin resolution.
import { describe, it, expect } from 'vitest';
import { DEFAULT_API, apiUrl } from '../js/api.js';

describe('api', () => {
  it('defaults to the Render backend', () => {
    expect(DEFAULT_API).toBe('https://localsign-api.onrender.com');
    expect(apiUrl('/healthz')).toBe('https://localsign-api.onrender.com/healthz');
  });
});
