import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { openArchive, ARCHIVE_BUDGETS } from '../src/data/archive/client';

class LocalWorker {
  static instances: LocalWorker[] = [];
  onmessage: ((event: MessageEvent) => void) | null = null;
  onerror: ((event: ErrorEvent) => void) | null = null;
  messages: Array<{ id: number; operation: string; blob?: Blob; root?: string; path?: string }> = [];
  terminated = false;
  constructor(public url: URL, public options: WorkerOptions) { LocalWorker.instances.push(this); }
  postMessage(message: typeof this.messages[number]) { this.messages.push(message); }
  terminate() { this.terminated = true; }
  deliver(data: unknown) { this.onmessage?.({ data } as MessageEvent); }
}
const admitted = () => ({ bundles: [], workspace: { assessments: [], findings: [], failures: [], conflicts: [], relations: [] } });
beforeEach(() => { LocalWorker.instances = []; vi.stubGlobal('Worker', LocalWorker); });
afterEach(() => { vi.unstubAllGlobals(); vi.useRealTimers(); });

describe('dedicated archive worker lifecycle', () => {
  it('passes the Blob to one module worker and keeps lazy reads in that captured session', async () => {
    const blob = new Blob(['test']), progress = vi.fn();
    const opening = openArchive(blob, undefined, progress);
    const worker = LocalWorker.instances[0];
    expect(worker.options).toEqual({ type: 'module' });
    expect(worker.messages[0].blob).toBe(blob);
    worker.deliver({ id: 1, progress: { phase: 'validating', completed: 1, total: 2 } });
    expect(progress).toHaveBeenCalledWith({ phase: 'validating', completed: 1, total: 2 });
    worker.deliver({ id: 1, value: admitted() });
    const session = await opening;
    expect(Object.isFrozen(session.workspace)).toBe(true);
    const text = session.readText('root', 'sast/result.json');
    expect(worker.messages[1]).toMatchObject({ operation: 'read', root: 'root', path: 'sast/result.json' });
    worker.deliver({ id: 2, value: 'original text' });
    await expect(text).resolves.toBe('original text');
    session.dispose(); expect(worker.terminated).toBe(true);
  });
  it('cancels outstanding import and ignores late worker delivery', async () => {
    const controller = new AbortController(), opening = openArchive(new Blob(), controller.signal);
    const rejected = expect(opening).rejects.toMatchObject({ code: 'cancelled' });
    const worker = LocalWorker.instances[0]; controller.abort();
    worker.deliver({ id: 1, value: admitted() });
    await rejected; expect(worker.terminated).toBe(true);
  });
  it('detaches import cancellation after success and retires all outstanding reads on disposal', async () => {
    const controller = new AbortController(), opening = openArchive(new Blob(), controller.signal);
    const worker = LocalWorker.instances[0]; worker.deliver({ id: 1, value: admitted() });
    const session = await opening; controller.abort(); expect(worker.terminated).toBe(false);
    const read = session.readText('root', 'sast/result.json');
    const rejected = expect(read).rejects.toMatchObject({ code: 'retired_archive' });
    session.dispose(); worker.deliver({ id: 2, value: 'late text' }); await rejected;
    await expect(session.readText('root', 'sast/result.json')).rejects.toMatchObject({ code: 'retired_archive' });
  });
  it('terminates hung imports at the documented runtime boundary', async () => {
    vi.useFakeTimers();
    const opening = openArchive(new Blob()), rejected = expect(opening).rejects.toMatchObject({ code: 'timeout' });
    await vi.advanceTimersByTimeAsync(ARCHIVE_BUDGETS.timeoutMs);
    await rejected; expect(LocalWorker.instances[0].terminated).toBe(true);
  });
  it('keeps optional artifact failures local and allows the next registered read', async () => {
    const opening = openArchive(new Blob()), worker = LocalWorker.instances[0]; worker.deliver({ id: 1, value: admitted() });
    const session = await opening;
    const bad = session.readText('root', 'sast/missing.json');
    worker.deliver({ id: 2, error: { code: 'unavailable', message: 'Referenced artifact was not delivered.' } });
    await expect(bad).rejects.toMatchObject({ code: 'unavailable' });
    const good = session.readText('root', 'sast/present.json'); worker.deliver({ id: 3, value: '{}' });
    await expect(good).resolves.toBe('{}'); session.dispose();
  });
  it('reports worker startup and posting failures without exposing native diagnostics', async () => {
    vi.stubGlobal('Worker', class { constructor() { throw new Error('private native detail'); } });
    await expect(openArchive(new Blob())).rejects.toMatchObject({ code: 'worker_failed', message: 'The browser could not start its local archive reader.' });
    vi.stubGlobal('Worker', class extends LocalWorker { postMessage() { throw new Error('private native detail'); } });
    await expect(openArchive(new Blob())).rejects.toMatchObject({ code: 'worker_failed', message: 'The browser could not send data to its local archive reader.' });
    expect(LocalWorker.instances[0].terminated).toBe(true);
  });
});
