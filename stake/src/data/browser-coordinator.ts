import { summarizeWorkspace, type FindingRecord } from '../domain';
import type { WorkspaceResponse } from '../domain/sources';
import { ArchiveError, openArchive, type ArchiveProgress, type ArchiveSession } from './archive/client';
import { createBrowserEvidenceRegistry } from './references-browser';
import { BrowserWorkspaceStore, BrowserStoreError, EMPTY_REVISION, type BrowserArchiveMetadata } from './browser-store';
import type { DisplayEvidence, WorkspaceDataSource } from './types';

export interface BrowserSnapshot {
  workspace: WorkspaceResponse | null;
  generation: string;
  archive?: BrowserArchiveMetadata;
  phase: 'restoring' | 'empty' | 'ready' | 'recovery';
  progress?: ArchiveProgress | { phase: 'saving'; completed: number };
  error: string;
  ownCompletion: number;
  lastOperation?: 'import' | 'remove';
  storageEstimate?: { usage?: number; quota?: number };
  persisted?: boolean;
}
export class BrowserCoordinatorError extends Error {
  constructor(public readonly code: 'stale' | 'busy' | 'cancelled' | 'invalid' | 'unavailable', message: string) { super(message); this.name = 'BrowserCoordinatorError'; }
}
type Registry = ReturnType<typeof createBrowserEvidenceRegistry>;
interface ActiveArchive { session: ArchiveSession; registry: Registry; generation: string }
type ArchiveStore = Pick<BrowserWorkspaceStore, 'read' | 'revision' | 'commit' | 'remove' | 'close'>;
export interface BrowserCoordinatorOptions {
  store?: ArchiveStore;
  openArchive?: typeof openArchive;
  createRegistry?: typeof createBrowserEvidenceRegistry;
  storage?: Pick<StorageManager, 'estimate' | 'persist' | 'persisted'>;
  channel?: Pick<BroadcastChannel, 'postMessage' | 'addEventListener' | 'removeEventListener' | 'close'> | false;
  pollIntervalMs?: number;
}
interface Operation { controller: AbortController; phase: 'preparing' | 'saving' }
const stale = () => new BrowserCoordinatorError('stale', 'The saved assessment changed. Review the current selection before trying again.');
const aborted = () => new DOMException('The workspace read was cancelled.', 'AbortError');
function diagnostic(error: unknown): string {
  if (error instanceof BrowserStoreError || error instanceof BrowserCoordinatorError) return error.message;
  // Archive admission produces bounded diagnostics; never include arbitrary thrown values or file contents.
  const message = error instanceof ArchiveError ? error.message : '';
  return message && message.length <= 500 && !/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(message) ? message : 'The archive could not be opened. Choose a supported report ZIP and try again.';
}
function operationError(error: unknown): Error {
  return error instanceof BrowserStoreError || error instanceof BrowserCoordinatorError ? error
    : new BrowserCoordinatorError('invalid', diagnostic(error));
}
function abortable<T>(pending: Promise<T>, signal?: AbortSignal): Promise<T> {
  if (!signal) return pending;
  if (signal.aborted) return Promise.reject(aborted());
  return new Promise((resolve, reject) => {
    const cancel = () => reject(aborted());
    signal.addEventListener('abort', cancel, { once: true });
    pending.then(resolve, reject).finally(() => signal.removeEventListener('abort', cancel));
  });
}

/** Page-lifetime browser adapter. Durable revision changes, never run IDs, retire reads. */
export class BrowserCoordinator implements WorkspaceDataSource {
  private snapshot: BrowserSnapshot = { workspace: null, generation: EMPTY_REVISION, phase: 'restoring', error: '', ownCompletion: 0 };
  private readonly listeners = new Set<() => void>();
  private readonly store: ArchiveStore;
  private active?: ActiveArchive;
  private operation?: Operation;
  private restoring?: AbortController;
  private initialization?: Promise<void>;
  private refreshing?: Promise<void>;
  private failedRevision?: string;
  private disposed = false;
  private interval?: ReturnType<typeof setInterval>;
  private channel?: Exclude<BrowserCoordinatorOptions['channel'], false>;
  constructor(private readonly options: BrowserCoordinatorOptions = {}) { this.store = options.store ?? new BrowserWorkspaceStore(); }
  getSnapshot = (): BrowserSnapshot => this.snapshot;
  subscribe = (listener: () => void): (() => void) => { this.listeners.add(listener); return () => this.listeners.delete(listener); };
  private update(patch: Partial<BrowserSnapshot>): void {
    if (this.disposed) return;
    this.snapshot = { ...this.snapshot, ...patch };
    for (const listener of this.listeners) listener();
  }
  private onHint = () => { if (typeof document === 'undefined' || document.visibilityState !== 'hidden') void this.refresh(); };

  initialize(): Promise<void> {
    if (this.disposed) return Promise.resolve();
    if (this.initialization) return this.initialization;
    if (this.options.channel !== false) {
      try { this.channel = this.options.channel ?? (typeof BroadcastChannel === 'function' ? new BroadcastChannel('vulnops-stake-workspace') : undefined); } catch { /* Polling remains authoritative. */ }
      this.channel?.addEventListener('message', this.onHint);
    }
    if (typeof window !== 'undefined') window.addEventListener('focus', this.onHint);
    if (typeof document !== 'undefined') document.addEventListener('visibilitychange', this.onHint);
    this.interval = setInterval(this.onHint, this.options.pollIntervalMs ?? 5000);
    this.initialization = this.refresh();
    return this.initialization;
  }

  refresh(): Promise<void> {
    if (this.disposed || this.operation?.phase === 'saving') return Promise.resolve();
    if (this.refreshing) return this.refreshing;
    this.refreshing = this.reconcile().finally(() => { this.refreshing = undefined; });
    return this.refreshing;
  }
  private async reconcile(): Promise<void> {
    try {
      let revision = await this.store.revision();
      if (this.disposed || this.operation?.phase === 'saving') return;
      if (revision === this.snapshot.generation && (['ready', 'empty'].includes(this.snapshot.phase) || this.failedRevision === revision)) return;
      const interrupted = !!this.operation;
      if (this.operation) { this.operation.controller.abort(); this.operation = undefined; }
      this.restoring?.abort();
      this.retire();
      this.update({ workspace: null, archive: undefined, generation: revision, phase: 'restoring', progress: undefined, error: interrupted ? stale().message : '' });
      while (!this.disposed) {
        const selection = await this.store.read(); revision = selection.revision;
        this.update({ generation: revision });
        if (!selection.snapshot) {
          this.failedRevision = undefined;
          this.update({ workspace: null, archive: undefined, phase: 'empty', progress: undefined });
          this.storageStatus(revision, false); return;
        }
        const controller = new AbortController(); this.restoring = controller;
        const session = await (this.options.openArchive ?? openArchive)(selection.snapshot.blob, controller.signal);
        if (this.disposed || controller.signal.aborted) { session.dispose(); return; }
        if (await this.store.revision() !== revision) { session.dispose(); continue; }
        this.restoring = undefined;
        this.activate(session, revision, selection.snapshot.metadata);
        this.storageStatus(revision, false); return;
      }
    } catch (error) {
      if (this.disposed) return;
      if (this.restoring?.signal.aborted) return;
      const revision = error instanceof BrowserStoreError ? error.revision : this.snapshot.generation;
      this.failedRevision = revision;
      this.update({ workspace: null, archive: undefined, ...(revision ? { generation: revision } : {}), phase: 'recovery', progress: undefined, error: diagnostic(error) });
    }
  }
  private retire(): void { this.active?.session.dispose(); this.active = undefined; }
  private activate(session: ArchiveSession, generation: string, archive: BrowserArchiveMetadata, own = false): void {
    const registry = (this.options.createRegistry ?? createBrowserEvidenceRegistry)(session.bundles, session.workspace, generation, (root, path, limit) => session.readText(root, path, limit));
    this.retire(); this.active = { session, registry, generation }; this.failedRevision = undefined;
    this.update({ workspace: { ...summarizeWorkspace(session.workspace), generation }, generation, archive, phase: 'ready', progress: undefined,
      error: own ? '' : this.snapshot.error, ...(own ? { ownCompletion: this.snapshot.ownCompletion + 1, lastOperation: 'import' as const } : {}) });
  }
  private async begin(expectedGeneration: string): Promise<Operation> {
    await this.initialize();
    if (this.refreshing) await this.refreshing;
    if (this.disposed) throw new BrowserCoordinatorError('unavailable', 'This workspace is closed.');
    if (this.operation) throw new BrowserCoordinatorError('busy', 'An import or save is already in progress.');
    const operation: Operation = { controller: new AbortController(), phase: 'preparing' };
    this.operation = operation;
    try {
      if (expectedGeneration !== this.snapshot.generation || await this.store.revision() !== expectedGeneration) {
        this.operation = undefined; await this.refresh(); throw stale();
      }
      if (operation.controller.signal.aborted || this.operation !== operation || this.disposed) throw new BrowserCoordinatorError('cancelled', 'Import cancelled.');
      return operation;
    } catch (error) { if (this.operation === operation) this.operation = undefined; this.update({ error: diagnostic(error) }); throw operationError(error); }
  }
  async importArchive(blob: Blob, name: string, expectedGeneration: string): Promise<void> {
    const operation = await this.begin(expectedGeneration);
    let session: ArchiveSession | undefined;
    this.update({ error: '', progress: { phase: 'reading', completed: 0 } });
    try {
      session = await (this.options.openArchive ?? openArchive)(blob, operation.controller.signal, progress => {
        if (this.operation === operation && !operation.controller.signal.aborted) this.update({ progress });
      });
      if (operation.controller.signal.aborted || this.operation !== operation || this.disposed) throw new BrowserCoordinatorError('cancelled', 'Import cancelled.');
      const metadata: BrowserArchiveMetadata = { name, size: blob.size, importedAt: new Date().toISOString(),
        roots: session.bundles.map(bundle => ({ root: bundle.inputPath, runId: bundle.run_id, kind: bundle.execution_kind })) };
      operation.phase = 'saving'; this.update({ progress: { phase: 'saving', completed: 0 } });
      const saved = await this.store.commit(blob, metadata, expectedGeneration);
      if (this.disposed) return;
      if (await this.store.revision().catch(() => saved.revision) !== saved.revision) { this.operation = undefined; await this.refresh(); throw stale(); }
      this.activate(session, saved.revision, metadata, true); session = undefined;
      this.broadcast(saved.revision); this.storageStatus(saved.revision, true);
    } catch (error) {
      if (this.operation === operation) {
        const cancelled = operation.controller.signal.aborted;
        this.update({ progress: undefined, error: cancelled ? '' : diagnostic(error) });
      }
      throw operation.controller.signal.aborted ? new BrowserCoordinatorError('cancelled', 'Import cancelled.') : operationError(error);
    } finally { session?.dispose(); if (this.operation === operation) this.operation = undefined; }
  }
  async remove(expectedGeneration: string): Promise<void> {
    const operation = await this.begin(expectedGeneration); operation.phase = 'saving';
    this.update({ progress: { phase: 'saving', completed: 0 }, error: '' });
    try {
      const removed = await this.store.remove(expectedGeneration);
      if (this.disposed) return;
      if (await this.store.revision().catch(() => removed.revision) !== removed.revision) { this.operation = undefined; await this.refresh(); throw stale(); }
      this.retire(); this.failedRevision = undefined;
      this.update({ workspace: null, archive: undefined, generation: removed.revision, phase: 'empty', progress: undefined, error: '', ownCompletion: this.snapshot.ownCompletion + 1, lastOperation: 'remove' });
      this.broadcast(removed.revision); this.storageStatus(removed.revision, false);
    } catch (error) { if (this.operation === operation) this.update({ progress: undefined, error: diagnostic(error) }); throw operationError(error); }
    finally { if (this.operation === operation) this.operation = undefined; }
  }
  cancelImport(): void {
    if (this.operation?.phase !== 'preparing') return;
    this.operation.controller.abort(); this.operation = undefined;
    this.update({ progress: undefined, error: '' });
  }
  private broadcast(revision: string): void { try { this.channel?.postMessage({ revision }); } catch { /* Poll/focus reconciliation remains available. */ } }
  private storageStatus(generation: string, requestPersistence: boolean): void {
    let storage: BrowserCoordinatorOptions['storage'];
    try { storage = this.options.storage ?? (typeof navigator !== 'undefined' ? navigator.storage : undefined); } catch { return; }
    if (!storage) return;
    void Promise.allSettled([Promise.resolve().then(() => storage!.estimate()), Promise.resolve().then(() => requestPersistence ? storage!.persist() : storage!.persisted())]).then(([estimate, persisted]) => {
      if (this.disposed || generation !== this.snapshot.generation) return;
      this.update({ ...(estimate.status === 'fulfilled' ? { storageEstimate: { usage: estimate.value.usage, quota: estimate.value.quota } } : {}),
        ...(persisted.status === 'fulfilled' ? { persisted: persisted.value } : {}) });
    });
  }
  private capture(generation: string, signal?: AbortSignal): ActiveArchive {
    if (signal?.aborted) throw aborted();
    if (this.disposed || !this.active || generation !== this.snapshot.generation || generation !== this.active.generation) throw stale();
    return this.active;
  }
  private finish<T>(active: ActiveArchive, value: T, signal?: AbortSignal): T {
    this.capture(active.generation, signal); if (this.active !== active) throw stale(); return value;
  }
  async finding(key: string, generation: string, signal?: AbortSignal): Promise<FindingRecord> {
    const active = this.capture(generation, signal), finding = active.session.workspace.findings.find(item => item.key === key);
    if (!finding) throw new BrowserCoordinatorError('unavailable', 'This finding is not available in the loaded assessment.');
    return this.finish(active, finding, signal);
  }
  async page(offset: number, limit: number, generation: string, signal?: AbortSignal): Promise<{ items: FindingRecord[]; total: number }> {
    const active = this.capture(generation, signal);
    if (!Number.isSafeInteger(offset) || offset < 0 || !Number.isSafeInteger(limit) || limit < 1) throw new BrowserCoordinatorError('invalid', 'The requested finding page is invalid.');
    const findings = active.session.workspace.findings;
    return this.finish(active, { items: findings.slice(offset, offset + limit), total: findings.length }, signal);
  }
  async reference(owner: string, reference: unknown, generation: string, signal?: AbortSignal): Promise<DisplayEvidence> {
    const active = this.capture(generation, signal), entry = active.registry.find(owner, reference);
    if (!entry) return this.finish(active, { status: 'unavailable', label: 'Unregistered reference', message: 'This reference is not registered for the owning execution.' }, signal);
    const evidence = await abortable(active.registry.read(entry.token), signal);
    return this.finish(active, evidence ?? { status: 'unavailable', label: entry.label, message: 'This reference is unavailable in the current workspace.' }, signal);
  }
  async evidence(token: string, generation: string, signal?: AbortSignal): Promise<DisplayEvidence> {
    const active = this.capture(generation, signal), evidence = await abortable(active.registry.read(token), signal);
    return this.finish(active, evidence ?? { status: 'unavailable', label: 'Unavailable evidence', message: 'This evidence handle does not belong to the current workspace.' }, signal);
  }
  dispose(): void {
    this.disposed = true; this.operation?.controller.abort(); this.operation = undefined; this.restoring?.abort();
    this.retire(); this.store.close(); clearInterval(this.interval); this.interval = undefined;
    this.channel?.removeEventListener('message', this.onHint); this.channel?.close(); this.channel = undefined;
    if (typeof window !== 'undefined') window.removeEventListener('focus', this.onHint);
    if (typeof document !== 'undefined') document.removeEventListener('visibilitychange', this.onHint);
    this.refreshing = undefined;
  }
}
