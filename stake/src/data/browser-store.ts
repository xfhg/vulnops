import { openDB, type DBSchema, type IDBPDatabase } from 'idb';

export const BROWSER_STORE_NAME = 'vulnops-stake-workspace';
export const BROWSER_STORE_VERSION = 1;
export const EMPTY_REVISION = 'empty';
export interface BrowserArchiveMetadata {
  name: string;
  size: number;
  importedAt: string;
  roots: Array<{ root: string; runId: string; kind: 'audit' | 'advantage' }>;
}
export interface StoredArchive { id: string; formatVersion: 1; blob: Blob; metadata: BrowserArchiveMetadata }
export interface StoredSelection { revision: string; snapshot?: StoredArchive }
export type BrowserStoreErrorCode = 'stale' | 'quota' | 'unavailable' | 'unsupported' | 'corrupt' | 'aborted';
const messages: Record<BrowserStoreErrorCode, string> = {
  stale: 'The saved assessment changed. Review the current selection before trying again.',
  quota: 'The browser could not save this archive because storage is full. The previous assessment was retained.',
  unavailable: 'Browser storage is unavailable. Allow site storage or try another browser, then retry.',
  unsupported: 'This saved assessment uses an unsupported storage version. Its archive has been preserved.',
  corrupt: 'The saved assessment is incomplete or cannot be read. Its stored data has been preserved.',
  aborted: 'The browser did not finish saving the change. The previous assessment was retained.',
};
export class BrowserStoreError extends Error {
  constructor(public readonly code: BrowserStoreErrorCode, public readonly revision?: string) {
    super(messages[code]); this.name = 'BrowserStoreError';
  }
}
interface ActiveRecord { formatVersion: number; revision: string; snapshotId: string | null }
interface StoreSchema extends DBSchema {
  state: { key: string; value: unknown };
  snapshots: { key: string; value: unknown };
}
export interface BrowserStoreOptions {
  name?: string;
  /** Synchronous fault injection; no parsing or asynchronous work belongs inside a transaction. */
  beforeCommit?: () => void;
  openTimeoutMs?: number;
}
function object(value: unknown): value is Record<string, unknown> { return !!value && typeof value === 'object' && !Array.isArray(value); }
function boundedString(value: unknown, maximum: number): value is string { return typeof value === 'string' && value.length > 0 && value.length <= maximum && !/[\u0000-\u001f\u007f]/.test(value); }
function revisionOf(value: unknown): string {
  if (value === undefined) return EMPTY_REVISION;
  return object(value) && boundedString(value.revision, 128) && value.revision !== EMPTY_REVISION ? value.revision : 'corrupt-active';
}
function activeRecord(value: unknown): ActiveRecord | undefined {
  if (value === undefined) return undefined;
  if (!object(value) || !boundedString(value.revision, 128) || value.revision === EMPTY_REVISION || typeof value.formatVersion !== 'number'
    || !(value.snapshotId === null || boundedString(value.snapshotId, 128))) throw new BrowserStoreError('corrupt', revisionOf(value));
  return value as unknown as ActiveRecord;
}
function metadataValid(value: unknown): value is BrowserArchiveMetadata {
  if (!object(value) || !boundedString(value.name, 1024) || !Number.isSafeInteger(value.size) || (value.size as number) < 0
    || typeof value.importedAt !== 'string' || !Number.isFinite(Date.parse(value.importedAt)) || !Array.isArray(value.roots) || value.roots.length !== 2) return false;
  return value.roots.every(root => object(root) && boundedString(root.root, 4096) && boundedString(root.runId, 1024) && ['audit', 'advantage'].includes(root.kind as string))
    && new Set(value.roots.map(root => root.kind)).size === 2 && new Set(value.roots.map(root => root.runId)).size === 2 && new Set(value.roots.map(root => root.root)).size === 2;
}
function archiveRecord(value: unknown, id: string, revision: string): StoredArchive {
  if (object(value) && Number.isSafeInteger(value.formatVersion) && value.formatVersion !== 1) throw new BrowserStoreError('unsupported', revision);
  if (!object(value) || value.formatVersion !== 1 || value.id !== id || !(value.blob instanceof Blob) || !metadataValid(value.metadata) || value.metadata.size !== value.blob.size) throw new BrowserStoreError('corrupt', revision);
  return value as unknown as StoredArchive;
}
export function storageError(error: unknown): BrowserStoreError {
  if (error instanceof BrowserStoreError) return error;
  const name = object(error) && typeof error.name === 'string' ? error.name : '';
  return new BrowserStoreError(name === 'QuotaExceededError' ? 'quota' : name === 'VersionError' ? 'unsupported' : name === 'AbortError' ? 'aborted' : 'unavailable');
}

/** The active pointer, ZIP bytes and tombstone share a single short transaction.
 * Callers activate a parsed candidate only after the returned promise resolves. */
export class BrowserWorkspaceStore {
  private dbPromise?: Promise<IDBPDatabase<StoreSchema>>;
  private readonly name: string;
  constructor(private readonly options: BrowserStoreOptions = {}) { this.name = options.name ?? BROWSER_STORE_NAME; }

  private db(): Promise<IDBPDatabase<StoreSchema>> {
    if (this.dbPromise) return this.dbPromise;
    this.dbPromise = new Promise<IDBPDatabase<StoreSchema>>((resolve, reject) => {
      let settled = false;
      const fail = (error: unknown) => { if (!settled) { settled = true; clearTimeout(timer); reject(storageError(error)); } };
      const timer = setTimeout(() => fail(new BrowserStoreError('unavailable')), this.options.openTimeoutMs ?? 8000);
      try {
        const pending = openDB<StoreSchema>(this.name, BROWSER_STORE_VERSION, {
          upgrade(db, oldVersion) { if (oldVersion === 0) { db.createObjectStore('state'); db.createObjectStore('snapshots'); } },
          blocked: () => fail(new BrowserStoreError('unavailable')),
          blocking: () => this.close(),
          terminated: () => { this.dbPromise = undefined; },
        });
        pending.then(db => {
          if (settled) { db.close(); return; }
          settled = true; clearTimeout(timer);
          if (!db.objectStoreNames.contains('state') || !db.objectStoreNames.contains('snapshots')) { db.close(); reject(new BrowserStoreError('corrupt')); }
          else resolve(db);
        }, fail);
      } catch (error) { fail(error); }
    }).catch(error => { this.dbPromise = undefined; throw storageError(error); });
    return this.dbPromise;
  }

  async revision(): Promise<string> {
    try { return revisionOf(await (await this.db()).get('state', 'active')); }
    catch (error) { throw storageError(error); }
  }

  async read(): Promise<StoredSelection> {
    try {
      const tx = (await this.db()).transaction(['state', 'snapshots'], 'readonly');
      const done = tx.done; void done.catch(() => undefined);
      const active = activeRecord(await tx.objectStore('state').get('active'));
      if (!active) {
        if (await tx.objectStore('snapshots').count()) throw new BrowserStoreError('corrupt', EMPTY_REVISION);
        await done; return { revision: EMPTY_REVISION };
      }
      if (active.formatVersion !== 1) throw new BrowserStoreError('unsupported', active.revision);
      const snapshot = active.snapshotId === null ? undefined : archiveRecord(await tx.objectStore('snapshots').get(active.snapshotId), active.snapshotId, active.revision);
      await done;
      return { revision: active.revision, ...(snapshot ? { snapshot } : {}) };
    } catch (error) { throw storageError(error); }
  }

  async commit(blob: Blob, metadata: BrowserArchiveMetadata, expectedRevision: string): Promise<StoredSelection & { snapshot: StoredArchive }> {
    if (!(blob instanceof Blob) || !metadataValid(metadata) || metadata.size !== blob.size) throw new BrowserStoreError('corrupt');
    const snapshot: StoredArchive = { id: `snapshot-${crypto.randomUUID()}`, formatVersion: 1, blob, metadata: structuredClone(metadata) };
    const revision = `r-${crypto.randomUUID()}`;
    await this.change(expectedRevision, revision, snapshot);
    return { revision, snapshot };
  }

  async remove(expectedRevision: string): Promise<StoredSelection> {
    const revision = `r-${crypto.randomUUID()}`;
    await this.change(expectedRevision, revision);
    return { revision };
  }

  private async change(expectedRevision: string, revision: string, snapshot?: StoredArchive): Promise<void> {
    try {
      const tx = (await this.db()).transaction(['state', 'snapshots'], 'readwrite');
      const done = tx.done; void done.catch(() => undefined);
      try {
        const previous = revisionOf(await tx.objectStore('state').get('active'));
        if (previous !== expectedRevision) throw new BrowserStoreError('stale', previous);
        // Explicit replacement/removal also removes orphaned snapshots left by corrupt storage.
        await tx.objectStore('snapshots').clear();
        if (snapshot) await tx.objectStore('snapshots').put(snapshot, snapshot.id);
        await tx.objectStore('state').put({ formatVersion: 1, revision, snapshotId: snapshot?.id ?? null }, 'active');
        this.options.beforeCommit?.();
        await done;
      } catch (error) {
        try { tx.abort(); } catch { /* It may already have aborted. */ }
        await done.catch(() => undefined);
        throw error;
      }
    } catch (error) { throw storageError(error); }
  }

  close(): void { const pending = this.dbPromise; this.dbPromise = undefined; void pending?.then(db => db.close(), () => undefined); }
}
