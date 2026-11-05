import 'fake-indexeddb/auto';
import { deleteDB, openDB } from 'idb';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { BrowserCoordinator, type BrowserCoordinatorOptions } from '../src/data/browser-coordinator';
import { BrowserWorkspaceStore, BrowserStoreError, type BrowserArchiveMetadata } from '../src/data/browser-store';
import { ArchiveError, type ArchiveSession } from '../src/data/archive/client';
import { normalizeWorkspace } from '../src/domain';
import { makeFinding, makePublication } from './fixtures/bundles';

function deferred<T>() { let resolve!: (value: T) => void, reject!: (error: unknown) => void; const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; }
function session(label: string): ArchiveSession {
  const bundles = [makePublication({ runId: 'ordinary', findings: [makeFinding({ title: label })] }),
    makePublication({ runId: 'advantage', kind: 'advantage', findings: [makeFinding({ id: 'F-060', title: `${label} Advantage` })] })]
    .map(bundle => ({ ...bundle, inputPath: bundle.run_id }));
  return { bundles, workspace: normalizeWorkspace(bundles), dispose: vi.fn(),
    readText: vi.fn(async () => JSON.stringify([{ id: 'C-001', explanation: `Synthetic ${label} support.` }])) };
}
const coordinators: BrowserCoordinator[] = [], stores: BrowserWorkspaceStore[] = [], databaseNames = new Set<string>();
function storage(name = `coordinator-${crypto.randomUUID()}`, options: ConstructorParameters<typeof BrowserWorkspaceStore>[0] = {}) {
  databaseNames.add(name); const value = new BrowserWorkspaceStore({ ...options, name }); stores.push(value); return { value, name };
}
function coordinator(options: BrowserCoordinatorOptions = {}) {
  const value = new BrowserCoordinator({ channel: false, openArchive: async blob => session(await blob.text()), ...options }); coordinators.push(value); return value;
}
async function imported(value: BrowserCoordinator, label: string) {
  await value.initialize(); await value.importArchive(new Blob([label]), `${label}.zip`, value.getSnapshot().generation); return value.getSnapshot().generation;
}
const metadata = (blob: Blob): BrowserArchiveMetadata => ({ name: 'synthetic.zip', importedAt: '2026-11-05T00:00:00Z', size: blob.size,
  roots: [{ root: 'ordinary', runId: 'ordinary', kind: 'audit' }, { root: 'advantage', runId: 'advantage', kind: 'advantage' }] });
afterEach(async () => { for (const value of coordinators.splice(0)) value.dispose(); for (const value of stores.splice(0)) value.close(); vi.useRealTimers(); vi.unstubAllGlobals(); await Promise.all([...databaseNames].map(name => deleteDB(name))); databaseNames.clear(); });

describe('browser workspace lifecycle', () => {
  it('restores saved original bytes through the current reader without recording an import completion', async () => {
    const db = storage(), first = coordinator({ store: db.value });
    const generation = await imported(first, 'Original'); first.dispose();
    const read = vi.fn(async (blob: Blob) => session(await blob.text()));
    const next = coordinator({ store: storage(db.name).value, openArchive: read });
    const pending = next.initialize(); expect(next.initialize()).toBe(pending); await pending;
    expect(read).toHaveBeenCalledOnce(); expect(await read.mock.calls[0][0].text()).toBe('Original');
    expect(next.getSnapshot()).toMatchObject({ phase: 'ready', generation, ownCompletion: 0, archive: { name: 'Original.zip' } });
    expect(next.getSnapshot().workspace!.findings[0].title).toBe('Original');
    expect(next.getSnapshot()).toBe(next.getSnapshot());
  });

  it('keeps the old workspace active during saving and activates only after the transaction commits', async () => {
    const db = storage(), gate = deferred<void>(); let hold = false;
    const commit = vi.fn(async (...args: Parameters<BrowserWorkspaceStore['commit']>) => { if (hold) await gate.promise; return db.value.commit(...args); });
    const value = coordinator({ store: { read: () => db.value.read(), revision: () => db.value.revision(), commit, remove: revision => db.value.remove(revision), close: () => db.value.close() } });
    const previous = await imported(value, 'Old'); hold = true;
    const replacement = value.importArchive(new Blob(['New']), 'New.zip', previous);
    await vi.waitFor(() => expect(value.getSnapshot().progress?.phase).toBe('saving'));
    expect(value.getSnapshot().generation).toBe(previous); expect(value.getSnapshot().workspace!.findings[0].title).toBe('Old');
    value.cancelImport(); expect(value.getSnapshot().progress?.phase).toBe('saving');
    expect(await db.value.revision()).toBe(previous);
    gate.resolve(); await replacement;
    expect(value.getSnapshot().workspace!.findings[0].title).toBe('New');
    expect(value.getSnapshot().generation).toBe(await db.value.revision());
    expect(value.getSnapshot().ownCompletion).toBe(2);
  });

  it('rejects a storage failure without any session-only replacement', async () => {
    let fail = false;
    const db = storage(undefined, { beforeCommit: () => { if (fail) throw new DOMException('quota', 'QuotaExceededError'); } });
    const prepared: ArchiveSession[] = [];
    const value = coordinator({ store: db.value, openArchive: async blob => { const candidate = session(await blob.text()); prepared.push(candidate); return candidate; } });
    const old = await imported(value, 'Old'); fail = true;
    await expect(value.importArchive(new Blob(['New']), 'New.zip', old)).rejects.toMatchObject({ code: 'quota' });
    expect(value.getSnapshot()).toMatchObject({ generation: old, phase: 'ready', ownCompletion: 1 });
    expect(value.getSnapshot().workspace!.findings[0].title).toBe('Old');
    expect(value.getSnapshot().error).toContain('storage is full');
    expect(await (await db.value.read()).snapshot!.blob.text()).toBe('Old');
    expect(prepared[1].dispose).toHaveBeenCalledOnce(); expect(prepared[0].dispose).not.toHaveBeenCalled();
  });

  it('treats persistence denial or synchronous storage-estimate failure as nonblocking after a successful save', async () => {
    const db = storage(), persist = vi.fn(async () => false);
    const value = coordinator({ store: db.value, storage: { estimate: () => { throw new DOMException('denied', 'SecurityError'); }, persist, persisted: async () => false } });
    await imported(value, 'Saved');
    await vi.waitFor(() => expect(value.getSnapshot().persisted).toBe(false));
    expect(value.getSnapshot().phase).toBe('ready'); expect(value.getSnapshot().error).toBe(''); expect(persist).toHaveBeenCalledOnce();
    expect(await (await db.value.read()).snapshot!.blob.text()).toBe('Saved');
  });

  it('preserves invalid saved archives in recovery and does not retry their admission on every poll', async () => {
    const db = storage(), blob = new Blob(['CORRUPT_ARCHIVE']);
    const saved = await db.value.commit(blob, metadata(blob), 'empty');
    const read = vi.fn(async () => { throw new ArchiveError('invalid_zip', 'The saved ZIP is not readable.'); });
    const value = coordinator({ store: db.value, openArchive: read }); await value.initialize();
    expect(value.getSnapshot()).toMatchObject({ phase: 'recovery', generation: saved.revision, workspace: null });
    expect(await (await db.value.read()).snapshot!.blob.text()).toBe('CORRUPT_ARCHIVE');
    await value.refresh(); expect(read).toHaveBeenCalledOnce();
    await value.remove(saved.revision);
    expect(value.getSnapshot()).toMatchObject({ phase: 'empty', workspace: null, ownCompletion: 1, lastOperation: 'remove' });
  });

  it('preserves an unsupported snapshot format without opening or deleting its Blob', async () => {
    const db = storage(), blob = new Blob(['FUTURE_ZIP']);
    const saved = await db.value.commit(blob, metadata(blob), 'empty');
    const raw = await openDB(db.name); await raw.put('snapshots', { ...saved.snapshot, formatVersion: 99 }, saved.snapshot.id);
    const read = vi.fn(async () => session('Wrong'));
    const value = coordinator({ store: db.value, openArchive: read }); await value.initialize();
    expect(value.getSnapshot()).toMatchObject({ phase: 'recovery', generation: saved.revision, workspace: null }); expect(read).not.toHaveBeenCalled();
    expect(await (await raw.get('snapshots', saved.snapshot.id)).blob.text()).toBe('FUTURE_ZIP'); raw.close();
  });

  it('finishes initialization with a recoverable diagnostic when IndexedDB access is unavailable', async () => {
    const deny = async () => { throw new BrowserStoreError('unavailable'); };
    const value = coordinator({ store: { read: deny, revision: deny, commit: deny, remove: deny, close: vi.fn() } });
    await value.initialize();
    expect(value.getSnapshot()).toMatchObject({ phase: 'recovery', workspace: null, progress: undefined });
    expect(value.getSnapshot().error).toContain('Browser storage is unavailable');
    await expect(value.importArchive(new Blob(['input']), 'input.zip', 'empty')).rejects.toMatchObject({ code: 'unavailable' });
  });

  it('cancels preparation, rejects duplicate submissions, and discards a late prepared session', async () => {
    const db = storage(), gate = deferred<ArchiveSession>(); let pending = false;
    const open = vi.fn(async (blob: Blob) => pending ? gate.promise : session(await blob.text()));
    const value = coordinator({ store: db.value, openArchive: open }); const old = await imported(value, 'Old'); pending = true;
    const work = value.importArchive(new Blob(['Slow']), 'Slow.zip', old);
    const outcome = expect(work).rejects.toMatchObject({ code: 'cancelled' });
    await vi.waitFor(() => expect(value.getSnapshot().progress?.phase).toBe('reading'));
    await expect(value.importArchive(new Blob(['Duplicate']), 'Duplicate.zip', old)).rejects.toMatchObject({ code: 'busy' });
    expect(open).toHaveBeenCalledTimes(2);
    value.cancelImport(); const late = session('Slow'); gate.resolve(late); await outcome;
    expect(late.dispose).toHaveBeenCalledOnce(); expect(value.getSnapshot()).toMatchObject({ generation: old, phase: 'ready', progress: undefined, error: '' });
    expect(await db.value.revision()).toBe(old);
  });

  it('reconciles another tab replacement and removal and rejects an open draft captured before the change', async () => {
    const db = storage(), first = coordinator({ store: db.value }), second = coordinator({ store: storage(db.name).value });
    const original = await imported(first, 'Old'); await second.initialize();
    const next = await imported(first, 'New'); await second.refresh();
    expect(second.getSnapshot()).toMatchObject({ phase: 'ready', generation: next, ownCompletion: 0 });
    expect(second.getSnapshot().workspace!.findings[0].title).toBe('New');
    await expect(second.importArchive(new Blob(['Stale']), 'Stale.zip', original)).rejects.toMatchObject({ code: 'stale' });
    expect(await db.value.revision()).toBe(next);
    await first.remove(next); await second.refresh();
    expect(second.getSnapshot()).toMatchObject({ phase: 'empty', workspace: null, ownCompletion: 0 });
    expect(second.getSnapshot().generation).toBe(first.getSnapshot().generation);
  });

  it('never returns late evidence from a retired generation even when execution and finding IDs are reused', async () => {
    const db = storage(), oldSession = session('Old'), gate = deferred<string>(); oldSession.readText = vi.fn(() => gate.promise);
    let first = true;
    const value = coordinator({ store: db.value, openArchive: async blob => { if (first) { first = false; return oldSession; } return session(await blob.text()); } });
    const generation = await imported(value, 'Old');
    const key = value.getSnapshot().workspace!.findings[0].key;
    const read = value.reference('ordinary', 'sast/verified-findings.json:C-001', generation);
    const rejected = expect(read).rejects.toMatchObject({ code: 'stale' });
    await imported(value, 'New'); gate.resolve(JSON.stringify([{ id: 'C-001', explanation: 'Late old support.' }])); await rejected;
    await expect(value.finding(key, generation)).rejects.toMatchObject({ code: 'stale' });
    expect((await value.finding(key, value.getSnapshot().generation)).title).toBe('New');
    expect(oldSession.dispose).toHaveBeenCalledOnce();
  });

  it('uses five-second visible polling and focus reconciliation when broadcast is unavailable', async () => {
    vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval'] });
    const document = Object.assign(new EventTarget(), { visibilityState: 'visible' }), window = new EventTarget();
    vi.stubGlobal('document', document); vi.stubGlobal('window', window);
    const db = storage(), first = coordinator({ store: db.value }), second = coordinator({ store: storage(db.name).value });
    await imported(first, 'Old'); await second.initialize(); const old = second.getSnapshot().generation;
    const next = await imported(first, 'New');
    expect(second.getSnapshot().generation).toBe(old);
    await vi.advanceTimersByTimeAsync(5000); await vi.waitFor(() => expect(second.getSnapshot().generation).toBe(next));
    await vi.waitFor(() => expect(second.getSnapshot().phase).toBe('ready'));
    document.visibilityState = 'hidden'; await first.remove(next);
    await vi.advanceTimersByTimeAsync(5000); expect(second.getSnapshot().generation).toBe(next);
    document.visibilityState = 'visible'; window.dispatchEvent(new Event('focus'));
    await vi.waitFor(() => expect(second.getSnapshot().phase).toBe('empty'));
  });

  it('treats broadcast messages as hints and always reconciles the authoritative stored revision', async () => {
    class HintChannel extends EventTarget { postMessage = vi.fn(); close = vi.fn(); }
    const channel = new HintChannel(), db = storage();
    const first = coordinator({ store: db.value }), second = coordinator({ store: storage(db.name).value, channel });
    await imported(first, 'Old'); await second.initialize();
    const before = second.getSnapshot();
    channel.dispatchEvent(new MessageEvent('message', { data: { revision: 'untrusted-revision-hint' } }));
    await second.refresh(); expect(second.getSnapshot()).toBe(before);
    const newer = await imported(first, 'New');
    channel.dispatchEvent(new MessageEvent('message', { data: { revision: 'still-not-authority' } }));
    await second.refresh(); expect(second.getSnapshot().generation).toBe(newer);
    expect(second.getSnapshot().workspace!.findings[0].title).toBe('New');
    expect(second.getSnapshot().ownCompletion).toBe(0);
  });
});
