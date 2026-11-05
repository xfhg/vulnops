import 'fake-indexeddb/auto';
import { deleteDB, openDB } from 'idb';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { BrowserWorkspaceStore, EMPTY_REVISION, type BrowserArchiveMetadata } from '../src/data/browser-store';

const stores: BrowserWorkspaceStore[] = [], names: string[] = [];
function store(options: ConstructorParameters<typeof BrowserWorkspaceStore>[0] = {}) {
  const name = options.name ?? `store-test-${crypto.randomUUID()}`;
  if (!names.includes(name)) names.push(name);
  const instance = new BrowserWorkspaceStore({ ...options, name }); stores.push(instance);
  return { instance, name };
}
function candidate(text = 'SYNTHETIC_ZIP_BYTES') {
  const blob = new Blob([text], { type: 'application/zip' });
  const metadata: BrowserArchiveMetadata = { name: 'synthetic.zip', size: blob.size, importedAt: '2026-11-05T00:00:00Z',
    roots: [{ root: 'ordinary', runId: 'same-ordinary-id', kind: 'audit' }, { root: 'advantage', runId: 'same-advantage-id', kind: 'advantage' }] };
  return { blob, metadata };
}
afterEach(async () => { vi.unstubAllGlobals(); for (const instance of stores.splice(0)) instance.close(); await Promise.all(names.splice(0).map(name => deleteDB(name))); });

describe('transactional browser workspace store', () => {
  it('stores the original Blob and descriptors together and restores them without derived caches', async () => {
    const { instance, name } = store();
    expect(await instance.read()).toEqual({ revision: EMPTY_REVISION });
    const input = candidate();
    const committed = await instance.commit(input.blob, input.metadata, EMPTY_REVISION);
    expect(committed.revision).not.toBe(EMPTY_REVISION);
    input.metadata.name = 'caller mutation.zip';
    instance.close();
    const restored = await store({ name }).instance.read();
    expect(restored.revision).toBe(committed.revision);
    expect(restored.snapshot!.metadata.name).toBe('synthetic.zip');
    expect(await restored.snapshot!.blob.text()).toBe('SYNTHETIC_ZIP_BYTES');
    expect(Object.keys(restored.snapshot!).sort()).toEqual(['blob', 'formatVersion', 'id', 'metadata']);
  });

  it('rolls back both bytes and active revision when a write aborts after all replacement requests', async () => {
    let abort = false;
    const { instance, name } = store({ beforeCommit: () => { if (abort) throw new DOMException('untrusted quota text', 'QuotaExceededError'); } });
    const old = candidate('PREVIOUS_ZIP');
    const committed = await instance.commit(old.blob, old.metadata, EMPTY_REVISION);
    const next = candidate('REPLACEMENT_ZIP'); abort = true;
    await expect(instance.commit(next.blob, next.metadata, committed.revision)).rejects.toMatchObject({ code: 'quota' });
    const restored = await instance.read();
    expect(restored.revision).toBe(committed.revision);
    expect(await restored.snapshot!.blob.text()).toBe('PREVIOUS_ZIP');
    const database = await openDB(name);
    expect(await database.count('snapshots')).toBe(1); database.close();
  });

  it('allows exactly one of two independently prepared replacements to commit', async () => {
    const first = store(), second = store({ name: first.name });
    expect(await first.instance.revision()).toBe(EMPTY_REVISION);
    expect(await second.instance.revision()).toBe(EMPTY_REVISION);
    const one = candidate('FIRST_ZIP'), two = candidate('SECOND_ZIP');
    const results = await Promise.allSettled([
      first.instance.commit(one.blob, one.metadata, EMPTY_REVISION), second.instance.commit(two.blob, two.metadata, EMPTY_REVISION),
    ]);
    expect(results.filter(result => result.status === 'fulfilled')).toHaveLength(1);
    expect(results.find(result => result.status === 'rejected')).toMatchObject({ reason: { code: 'stale' } });
    const winner = results[0].status === 'fulfilled' ? 'FIRST_ZIP' : 'SECOND_ZIP';
    expect(await (await first.instance.read()).snapshot!.blob.text()).toBe(winner);
    expect(await second.instance.revision()).toBe(await first.instance.revision());
  });

  it('writes a unique removal tombstone and rejects an import prepared before removal', async () => {
    const { instance } = store(); const input = candidate();
    const removedEmpty = await instance.remove(EMPTY_REVISION);
    expect(removedEmpty.revision).not.toBe(EMPTY_REVISION);
    await expect(instance.commit(input.blob, input.metadata, EMPTY_REVISION)).rejects.toMatchObject({ code: 'stale' });
    const saved = await instance.commit(input.blob, input.metadata, removedEmpty.revision);
    const removed = await instance.remove(saved.revision);
    expect(new Set([removedEmpty.revision, saved.revision, removed.revision]).size).toBe(3);
    expect(await instance.read()).toEqual(removed);
    await expect(instance.commit(input.blob, input.metadata, saved.revision)).rejects.toMatchObject({ code: 'stale' });
  });

  it('serializes simultaneous clear and import against the same captured revision', async () => {
    const first = store(), other = store({ name: first.name }), input = candidate();
    const saved = await first.instance.commit(input.blob, input.metadata, EMPTY_REVISION);
    await other.instance.revision();
    const next = candidate('NEXT_ZIP');
    const [removal, replacement] = await Promise.allSettled([
      first.instance.remove(saved.revision), other.instance.commit(next.blob, next.metadata, saved.revision),
    ]);
    expect([removal, replacement].filter(result => result.status === 'fulfilled')).toHaveLength(1);
    const read = await first.instance.read();
    if (removal.status === 'fulfilled') { expect(read).toEqual(removal.value); expect(replacement).toMatchObject({ reason: { code: 'stale' } }); }
    else { expect(removal).toMatchObject({ reason: { code: 'stale' } }); expect(await read.snapshot!.blob.text()).toBe('NEXT_ZIP'); }
  });

  it('restores a committed replacement after the original client closes before activating memory', async () => {
    const { instance, name } = store(), old = candidate('OLD');
    const previous = await instance.commit(old.blob, old.metadata, EMPTY_REVISION);
    const next = candidate('COMMITTED_NEW_ZIP');
    await instance.commit(next.blob, next.metadata, previous.revision);
    instance.close();
    const restored = await store({ name }).instance.read();
    expect(await restored.snapshot!.blob.text()).toBe('COMMITTED_NEW_ZIP');
    expect(restored.snapshot!.metadata).toEqual(next.metadata);
  });

  it('preserves unsupported saved bytes until explicit compare-and-remove recovery', async () => {
    const { instance, name } = store(), input = candidate();
    const saved = await instance.commit(input.blob, input.metadata, EMPTY_REVISION);
    const database = await openDB(name);
    await database.put('snapshots', { ...saved.snapshot, formatVersion: 99 }, saved.snapshot.id);
    await expect(instance.read()).rejects.toMatchObject({ code: 'unsupported', revision: saved.revision });
    expect(await instance.revision()).toBe(saved.revision);
    expect(await (await database.get('snapshots', saved.snapshot.id)).blob.text()).toBe('SYNTHETIC_ZIP_BYTES');
    await instance.remove(saved.revision);
    expect(await database.count('snapshots')).toBe(0); database.close();
  });

  it('preserves orphaned bytes when an active snapshot is missing and permits explicit replacement', async () => {
    const { instance, name } = store(), input = candidate();
    const saved = await instance.commit(input.blob, input.metadata, EMPTY_REVISION);
    const database = await openDB(name);
    await database.put('state', { formatVersion: 1, revision: saved.revision, snapshotId: 'missing-snapshot' }, 'active');
    await expect(instance.read()).rejects.toMatchObject({ code: 'corrupt', revision: saved.revision });
    expect(await database.count('snapshots')).toBe(1);
    expect(await (await database.get('snapshots', saved.snapshot.id)).blob.text()).toBe('SYNTHETIC_ZIP_BYTES');
    const next = candidate('RECOVERY_ZIP');
    await instance.commit(next.blob, next.metadata, saved.revision);
    expect(await (await instance.read()).snapshot!.blob.text()).toBe('RECOVERY_ZIP');
    expect(await database.count('snapshots')).toBe(1); database.close();
  });

  it('returns a bounded storage diagnostic when IndexedDB is denied', async () => {
    vi.stubGlobal('indexedDB', { open() { throw new DOMException('RAW_PRIVATE_BROWSER_ERROR', 'SecurityError'); } });
    const { instance } = store();
    await expect(instance.read()).rejects.toMatchObject({ code: 'unavailable' });
    await expect(instance.read()).rejects.not.toThrow('RAW_PRIVATE_BROWSER_ERROR');
  });

  it('preserves malformed active metadata and orphaned bytes until explicit recovery removal', async () => {
    const { instance, name } = store(), input = candidate();
    const saved = await instance.commit(input.blob, input.metadata, EMPTY_REVISION);
    const database = await openDB(name);
    await database.put('state', { broken: true }, 'active');
    const recovery = await instance.revision();
    expect(recovery).not.toBe(EMPTY_REVISION);
    await expect(instance.read()).rejects.toMatchObject({ code: 'corrupt', revision: recovery });
    expect(await database.count('snapshots')).toBe(1);
    expect(await (await database.get('snapshots', saved.snapshot.id)).blob.text()).toBe('SYNTHETIC_ZIP_BYTES');
    await instance.remove(recovery); expect(await database.count('snapshots')).toBe(0);
    expect((await instance.read()).snapshot).toBeUndefined(); database.close();
  });
});
