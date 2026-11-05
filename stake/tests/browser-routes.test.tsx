// @vitest-environment jsdom
import { act, cleanup, renderHook } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
vi.mock('../src/data/runtime-mode', () => ({ browserMode: true }));
import { readParams, replaceReportRoute, routeHref, useRoute } from '../src/app/state';
afterEach(() => { cleanup(); window.history.replaceState({}, '', '/'); });

describe('hosted fragment routes', () => {
  it('reads and copies complete report selections without request query parameters', () => {
    const selection = new URLSearchParams({ view: 'findings', finding: '["finding","audit","F-001"]', panel: 'repair', detailRecord: '["repair-location","ACTION-1",0]' });
    window.history.replaceState({}, '', routeHref(selection));
    expect(window.location.search).toBe('');
    expect(readParams().toString()).toBe(selection.toString());
    expect(routeHref(selection)).toContain('/#?view=findings');
  });
  it('responds to fragment/history changes and clears report parameters on replacement', () => {
    window.history.replaceState({}, '', '/#?view=code&location=old');
    const { result } = renderHook(useRoute);
    expect(result.current.value('location')).toBe('old');
    act(() => result.current.navigate({ view: 'remediation', repairAction: 'action', location: null }));
    expect(result.current.value('repairAction')).toBe('action');
    act(() => { window.history.replaceState({}, '', '/#?view=code&location=restored'); window.dispatchEvent(new PopStateEvent('popstate')); });
    expect(result.current.value('location')).toBe('restored');
    act(() => replaceReportRoute());
    expect(window.location.hash).toBe('#?view=overview');
    expect(window.location.search).toBe('');
  });
});
