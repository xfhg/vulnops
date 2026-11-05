// @vitest-environment jsdom
import { act, cleanup, renderHook, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { BrowserSnapshot } from '../src/data/browser-coordinator';
import { normalizeWorkspace, summarizeWorkspace } from '../src/domain';
import { makePublication } from './fixtures/bundles';

const mocked = vi.hoisted(() => ({ snapshot: null as unknown as BrowserSnapshot, listeners: new Set<() => void>(), match: vi.fn(), remove: vi.fn(async () => undefined) }));
vi.mock('../src/data/runtime-mode', () => ({ browserMode: true }));
vi.mock('../src/app/browser-destination', () => ({ matchesBrowserDestination: mocked.match }));
vi.mock('../src/data/browser-coordinator', () => ({ BrowserCoordinator: class {
  subscribe = (listener: () => void) => { mocked.listeners.add(listener); return () => mocked.listeners.delete(listener); };
  getSnapshot = () => mocked.snapshot;
  initialize = async () => undefined;
  refresh = async () => undefined;
  remove = mocked.remove;
  importArchive = async () => undefined;
  cancelImport = () => undefined;
} }));
import { useBrowserWorkspace } from '../src/app/useBrowserWorkspace';

const summary = summarizeWorkspace(normalizeWorkspace([makePublication()]));
function snapshot(generation: string, loaded: boolean): BrowserSnapshot {
  return { generation, workspace: loaded ? { ...summary, generation } : null, phase: loaded ? 'ready' : 'empty', error: '', ownCompletion: 0 };
}
function publish(value: BrowserSnapshot) { act(() => { mocked.snapshot = value; mocked.listeners.forEach(listener => listener()); }); }
beforeEach(() => { mocked.snapshot = snapshot('empty', false); mocked.match.mockReset().mockResolvedValue(true); mocked.remove.mockClear(); vi.stubGlobal('requestAnimationFrame', (callback: FrameRequestCallback) => { callback(0); return 0; }); });
afterEach(() => { cleanup(); mocked.listeners.clear(); window.history.replaceState({}, '', '/'); vi.unstubAllGlobals(); });

describe('browser pending-route lifetime', () => {
  it('retains a matching first-import destination then resets a later replacement', async () => {
    window.history.replaceState({}, '', '/#?view=code&location=qualified-file');
    renderHook(useBrowserWorkspace); publish(snapshot('first', true));
    await waitFor(() => expect(mocked.match).toHaveBeenCalledTimes(1));
    expect(window.location.hash).toBe('#?view=code&location=qualified-file');
    publish(snapshot('second', true));
    expect(window.location.hash).toBe('#?view=overview');
    expect(mocked.match).toHaveBeenCalledTimes(1);
  });
  it('resets a nonmatching initial child destination after validation', async () => {
    mocked.match.mockResolvedValue(false);
    window.history.replaceState({}, '', '/#?view=remediation&repairSelected=not-owned');
    renderHook(useBrowserWorkspace); publish(snapshot('first', true));
    await waitFor(() => expect(window.location.hash).toBe('#?view=overview'));
  });
  it('leaves a restored route unchanged rather than treating restoration as a new import', () => {
    mocked.snapshot = { ...snapshot('initial', false), phase: 'restoring' };
    window.history.replaceState({}, '', '/#?view=attacks&entrySelected=retained-composition');
    renderHook(useBrowserWorkspace); publish(snapshot('saved', true));
    expect(window.location.hash).toContain('entrySelected=retained-composition');
    expect(mocked.match).not.toHaveBeenCalled();
  });
  it('does not revive an initial link after explicit navigation away and back', () => {
    const url = '/#?view=code&location=qualified-file'; window.history.replaceState({}, '', url);
    renderHook(useBrowserWorkspace);
    act(() => { window.history.replaceState({}, '', '/#?view=overview'); window.dispatchEvent(new PopStateEvent('popstate')); window.history.replaceState({}, '', url); window.dispatchEvent(new PopStateEvent('popstate')); });
    publish(snapshot('first', true));
    expect(window.location.hash).toBe('#?view=overview'); expect(mocked.match).not.toHaveBeenCalled();
  });
  it('explicit removal clears the pending destination, including before any loaded pair', async () => {
    window.history.replaceState({}, '', '/#?view=code&location=qualified-file');
    const { result } = renderHook(useBrowserWorkspace);
    await act(async () => { await result.current.removeArchive('empty'); });
    publish(snapshot('first', true));
    expect(window.location.hash).toBe('#?view=overview'); expect(mocked.match).not.toHaveBeenCalled();
  });
  it('cannot apply a late destination result over explicit navigation or a newer generation', async () => {
    let resolve!: (value: boolean) => void;
    mocked.match.mockImplementation(() => new Promise<boolean>(done => { resolve = done; }));
    window.history.replaceState({}, '', '/#?view=code&location=qualified-file');
    renderHook(useBrowserWorkspace); publish(snapshot('first', true));
    act(() => { window.history.replaceState({}, '', '/#?view=assessment&run=audit-fixture'); window.dispatchEvent(new PopStateEvent('popstate')); });
    await act(async () => { resolve(false); });
    expect(window.location.hash).toBe('#?view=assessment&run=audit-fixture');
    publish(snapshot('second', true)); expect(window.location.hash).toBe('#?view=overview');
  });
});
