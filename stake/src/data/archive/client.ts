import { ARCHIVE_BUDGETS, ArchiveError, abortError, checkAborted, freezeArchiveValue, type ArchiveBundle, type ArchiveProgress, type ArchiveSession } from './types';
export type { ArchiveBundle, ArchiveProgress, ArchiveSession } from './types';
export { ARCHIVE_BUDGETS, ArchiveError } from './types';

/** Dedicated worker lifetime equals the captured archive generation. */
export async function openArchive(blob: Blob, signal?: AbortSignal, onProgress?: (progress: ArchiveProgress) => void): Promise<ArchiveSession> {
  checkAborted(signal);
  if (blob.size > ARCHIVE_BUDGETS.compressedBytes) throw new ArchiveError('archive_limit', 'The compressed ZIP exceeds the 256 MiB import budget.');
  let worker: Worker;
  try { worker = new Worker(new URL('./archive.worker.ts', import.meta.url), { type: 'module' }); }
  catch { throw new ArchiveError('worker_failed', 'The browser could not start its local archive reader.'); }
  let nextId = 0, disposed = false;
  const pending = new Map<number, { resolve(value: unknown): void; reject(error: Error): void; timer: ReturnType<typeof setTimeout> }>();
  function dispose(error = new ArchiveError('retired_archive', 'This archive is no longer active.')) {
    if (disposed) return;
    disposed = true; worker.terminate();
    for (const request of pending.values()) { clearTimeout(request.timer); request.reject(error); }
    pending.clear();
  }
  const abort = () => dispose(abortError());
  signal?.addEventListener('abort', abort, { once: true });
  worker.onerror = event => { event.preventDefault(); dispose(new ArchiveError('worker_failed', 'The archive reader could not complete. Try importing the ZIP again.')); };
  worker.onmessage = event => {
    const message = event.data as { id: number; progress?: ArchiveProgress; value?: unknown; error?: { code: string; message: string } };
    const request = pending.get(message.id);
    if (!request) return;
    if (message.progress) { onProgress?.(message.progress); return; }
    clearTimeout(request.timer); pending.delete(message.id);
    if (message.error) request.reject(new ArchiveError(message.error.code, message.error.message)); else request.resolve(message.value);
  };
  function call<T>(message: Record<string, unknown>): Promise<T> {
    if (disposed) return Promise.reject(new ArchiveError('retired_archive', 'This archive is no longer active.'));
    return new Promise((resolve, reject) => {
      const id = ++nextId;
      const timer = setTimeout(() => dispose(new ArchiveError('timeout', 'Archive reading exceeded its runtime allowance.')), ARCHIVE_BUDGETS.timeoutMs);
      pending.set(id, { resolve: value => resolve(value as T), reject, timer });
      try { worker.postMessage({ ...message, id }); }
      catch { dispose(new ArchiveError('worker_failed', 'The browser could not send data to its local archive reader.')); }
    });
  }
  try {
    const admitted = await call<{ bundles: ArchiveBundle[]; workspace: ArchiveSession['workspace'] }>({ operation: 'open', blob });
    checkAborted(signal);
    freezeArchiveValue(admitted);
    return { ...admitted, readText: (root, path, limit) => call<string>({ operation: 'read', root, path, limit }), dispose: () => dispose() };
  } catch (error) { dispose(); throw error; }
  finally { signal?.removeEventListener('abort', abort); }
}
