// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest';
import { act, cleanup, render, renderHook, screen, waitFor } from '@testing-library/react';
import App from '../src/app/App';
import { useWorkspace } from '../src/app/useWorkspace';
import { ApiError, getJson } from '../src/app/state';
import type { WorkspaceResponse, WorkspaceSourceState } from '../src/domain/sources';

afterEach(() => { cleanup(); vi.unstubAllGlobals(); window.history.replaceState({}, '', '/'); localStorage.clear(); });
const pair = { ordinaryPath: '/reports/ordinary one', advantagePath: '/reports/advantage one' };
function sources(generation = 'one'): WorkspaceSourceState {
  return { generation, sources: [], savedPair: null, origin: 'empty', loading: false, lastLoad: null, persistence: { status: 'not_applicable' }, diagnostics: [] };
}
function summary(generation = 'one'): WorkspaceResponse {
  return { generation, assessments: [], findings: [], failures: [], conflicts: [], relations: [] };
}
function json(value: unknown, status = 200, generation?: string) {
  return new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json', ...(generation ? { 'X-Stake-Workspace': generation } : {}) } });
}
function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((done, fail) => { resolve = done; reject = fail; });
  return { promise, resolve, reject };
}
function server() {
  let state = sources();
  const fetcher = vi.fn(async (url: string, init?: RequestInit): Promise<Response> => {
    if (init?.method === 'POST') throw new Error('Unexpected POST');
    if (url === '/api/workspace') return json(summary(state.generation));
    if (url === '/api/workspace/sources') return json(state);
    if (url === '/api/workspace/version') return json({ generation: state.generation, loading: state.loading, lastLoadId: state.lastLoad?.id ?? null });
    throw new Error('Unexpected URL');
  });
  vi.stubGlobal('fetch', fetcher);
  return { fetcher, get state() { return state; }, set state(value: WorkspaceSourceState) { state = value; } };
}

describe('workspace browser lifetime', () => {
  it('preserves early keyboard focus while the first workspace finishes loading', async () => {
    const api = server();
    const bootstrap = deferred<Response>();
    api.fetcher.mockImplementationOnce(() => bootstrap.promise);
    render(<App />);
    const skip = screen.getByRole('link', { name: 'Skip to content' });
    skip.focus();
    await act(async () => { bootstrap.resolve(json(summary())); });
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Load your reports' })).toBeTruthy());
    expect(skip.isConnected).toBe(true);
    expect(document.activeElement).toBe(skip);
  });

  it('retries inconsistent bootstrap reads without exposing a mixed generation', async () => {
    const api = server();
    api.fetcher.mockImplementationOnce(async () => json(summary('old')));
    const { result } = renderHook(useWorkspace);
    await waitFor(() => expect(result.current.workspace?.generation).toBe('one'));
    expect(result.current.sources?.generation).toBe('one');
    expect(api.fetcher.mock.calls.filter(([url]) => url === '/api/workspace')).toHaveLength(2);
  });

  it('preserves an initial deep link, then clears all report parameters on a remote switch without changing theme', async () => {
    window.history.replaceState({}, '', '/?view=attacks&finding=old&run=old&entrySelected=old&q=query&panel=repair');
    localStorage.setItem('stake-theme', 'dark');
    const api = server();
    const { result } = renderHook(useWorkspace);
    await waitFor(() => expect(result.current.workspace).not.toBeNull());
    expect(window.location.search).toContain('finding=old');
    api.state = sources('two');
    act(() => window.dispatchEvent(new Event('focus')));
    await waitFor(() => expect(result.current.workspace?.generation).toBe('two'));
    expect(window.location.search).toBe('?view=overview');
    expect(result.current.ownCompletion).toBe(0);
    expect(result.current.notice).toBe('');
    expect(localStorage.getItem('stake-theme')).toBe('dark');
  });

  it('discards a delayed older refresh even if a transport ignores abort', async () => {
    const api = server();
    const { result } = renderHook(useWorkspace);
    await waitFor(() => expect(result.current.workspace).not.toBeNull());
    const oldRead = deferred<Response>();
    api.fetcher.mockImplementationOnce(() => oldRead.promise);
    let oldRefresh!: Promise<unknown>;
    act(() => { oldRefresh = result.current.refresh(); });
    api.state = sources('two');
    await act(async () => { await result.current.refresh(); });
    await act(async () => { oldRead.resolve(json(summary('one'))); await oldRefresh; });
    expect(result.current.workspace?.generation).toBe('two');
    expect(result.current.sources?.generation).toBe('two');
  });

  it('keeps a lost-response load busy until reconciliation and recovers its save warning without a second POST', async () => {
    const api = server();
    const { result } = renderHook(useWorkspace);
    await waitFor(() => expect(result.current.workspace).not.toBeNull());
    const original = api.fetcher.getMockImplementation()!;
    api.fetcher.mockImplementation(async (url, init) => {
      if (init?.method === 'POST') { api.state = { ...api.state, loading: true }; throw new TypeError('Network interrupted'); }
      return original(url, init);
    });
    await act(async () => { expect((await result.current.loadSources(pair, 'one')).status).toBe('pending'); });
    expect(result.current.busy).toBe(true);
    expect(result.current.notice).toBe('Connection interrupted. Checking whether the reports finished loading…');
    await act(async () => { await result.current.loadSources(pair, 'one'); });
    const warning = 'Loaded for this session; paths could not be remembered.';
    api.state = { ...sources('two'), persistence: { status: 'session_only', message: warning }, lastLoad: { id: 'load-two', status: 'success', generation: 'two', message: warning, persistence: { status: 'session_only', message: warning } } };
    act(() => window.dispatchEvent(new Event('focus')));
    await waitFor(() => expect(result.current.busy).toBe(false));
    expect(result.current.workspace?.generation).toBe('two');
    expect(result.current.sources?.persistence.message).toBe(warning);
    // Persistence warnings have their own source-state banner; no duplicate completion notice.
    expect(result.current.notice).toBe('');
    // A global completion proves current state, not which tab's request won.
    expect(result.current.ownCompletion).toBe(0);
    expect(api.fetcher.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(1);
  });

  it('does not close this tab’s draft when another tab wins before a delayed conflict response', async () => {
    const api = server();
    const { result } = renderHook(useWorkspace);
    await waitFor(() => expect(result.current.workspace).not.toBeNull());
    const response = deferred<Response>();
    const original = api.fetcher.getMockImplementation()!;
    api.fetcher.mockImplementation((url, init) => init?.method === 'POST' ? response.promise : original(url, init));
    let submission!: Promise<unknown>;
    act(() => { submission = result.current.loadSources(pair, 'one'); });
    api.state = { ...sources('remote'), lastLoad: { id: 'remote-load', status: 'success', generation: 'remote', message: 'Reports loaded', persistence: { status: 'remembered' } } };
    act(() => window.dispatchEvent(new Event('focus')));
    await waitFor(() => expect(result.current.workspace?.generation).toBe('remote'));
    expect(result.current.ownCompletion).toBe(0);
    await act(async () => { response.resolve(json({ error: 'The workspace changed', code: 'workspace_changed' }, 409)); await submission; });
    expect(result.current.ownCompletion).toBe(0);
    expect(result.current.busy).toBe(false);
  });

  it('attributes successful completion from its returned load ID even when a poll refreshed first', async () => {
    const api = server();
    const { result } = renderHook(useWorkspace);
    await waitFor(() => expect(result.current.workspace).not.toBeNull());
    const response = deferred<Response>();
    const original = api.fetcher.getMockImplementation()!;
    api.fetcher.mockImplementation((url, init) => init?.method === 'POST' ? response.promise : original(url, init));
    let submission!: Promise<unknown>;
    act(() => { submission = result.current.loadSources(pair, 'one'); });
    api.state = { ...sources('two'), lastLoad: { id: 'own-load', status: 'success', generation: 'two', message: 'Reports loaded', persistence: { status: 'remembered' } } };
    act(() => window.dispatchEvent(new Event('focus')));
    await waitFor(() => expect(result.current.workspace?.generation).toBe('two'));
    expect(result.current.ownCompletion).toBe(0);
    await act(async () => { response.resolve(json(api.state)); await submission; });
    expect(result.current.ownCompletion).toBe(1);
    expect(result.current.busy).toBe(false);
    expect(result.current.notice).toBe('');
  });

  it('clears the success notice when a committed load is recovered immediately after a dropped response', async () => {
    const api = server();
    const { result } = renderHook(useWorkspace);
    await waitFor(() => expect(result.current.workspace).not.toBeNull());
    const original = api.fetcher.getMockImplementation()!;
    api.fetcher.mockImplementation(async (url, init) => {
      if (init?.method === 'POST') {
        api.state = { ...sources('two'), persistence: { status: 'remembered' },
          lastLoad: { id: 'completed-load', status: 'success', generation: 'two', message: 'Reports loaded and paths remembered.', persistence: { status: 'remembered' } } };
        throw new TypeError('Response interrupted after commit');
      }
      return original(url, init);
    });
    await act(async () => { expect(await result.current.loadSources(pair, 'one')).toEqual({ status: 'loaded' }); });
    expect(result.current.workspace?.generation).toBe('two');
    expect(result.current.sources?.persistence.status).toBe('remembered');
    expect(result.current.busy).toBe(false);
    expect(result.current.notice).toBe('');
    expect(result.current.ownCompletion).toBe(0);
    expect(api.fetcher.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(1);
  });

  it('retains the active workspace on field errors and refuses a stale generation locally', async () => {
    const api = server();
    const { result } = renderHook(useWorkspace);
    await waitFor(() => expect(result.current.workspace).not.toBeNull());
    const original = api.fetcher.getMockImplementation()!;
    api.fetcher.mockImplementation(async (url, init) => init?.method === 'POST' ? json({ error: 'Invalid ordinary run', fieldErrors: { ordinaryPath: 'Wrong kind' } }, 422) : original(url, init));
    await act(async () => { expect(await result.current.loadSources(pair, 'one')).toEqual({ status: 'failed', message: 'Invalid ordinary run', fieldErrors: { ordinaryPath: 'Wrong kind' } }); });
    expect(result.current.workspace?.generation).toBe('one');
    expect(result.current.busy).toBe(false);
    expect(result.current.notice).toBe('Invalid ordinary run');
    expect((await result.current.loadSources(pair, 'stale')).status).toBe('failed');
    expect(api.fetcher.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(1);
  });

  it('does not poll hidden tabs and checks immediately when visibility returns', async () => {
    const api = server();
    const { result } = renderHook(useWorkspace);
    await waitFor(() => expect(result.current.workspace).not.toBeNull());
    const visibility = vi.spyOn(document, 'visibilityState', 'get');
    visibility.mockReturnValue('hidden');
    api.state = sources('two');
    act(() => document.dispatchEvent(new Event('visibilitychange')));
    expect(api.fetcher.mock.calls.some(([url]) => url.endsWith('/version'))).toBe(false);
    visibility.mockReturnValue('visible');
    act(() => document.dispatchEvent(new Event('visibilitychange')));
    await waitFor(() => expect(result.current.workspace?.generation).toBe('two'));
    visibility.mockRestore();
  });
});

describe('generation-aware data reads', () => {
  it('sends the expected generation and rejects a response from a different snapshot', async () => {
    const fetcher = vi.fn(async () => json({ id: 'old' }, 200, 'old'));
    vi.stubGlobal('fetch', fetcher);
    await expect(getJson('/api/findings/example', undefined, 'new')).rejects.toMatchObject({ code: 'workspace_changed' });
    expect(fetcher).toHaveBeenCalledWith('/api/findings/example', expect.objectContaining({ headers: expect.objectContaining({ 'X-Stake-Workspace': 'new' }) }));
  });
  it('retains reload codes and field errors without exposing raw responses', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => json({ error: 'Reload required', code: 'reload_required' }, 428)));
    await expect(getJson('/api/reference')).rejects.toEqual(new ApiError('Reload required', 428, 'reload_required'));
  });
});
