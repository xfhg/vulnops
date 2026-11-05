import type { AdmittedBundle, Workspace } from '../../domain/types';

export interface ArchiveBundle extends AdmittedBundle { inputPath: string; markdown: string }
export interface ArchiveProgress { phase: 'reading' | 'validating'; completed: number; total?: number }
export interface ArchiveSession {
  bundles: ArchiveBundle[];
  workspace: Workspace;
  readText(root: string, path: string, limit?: number): Promise<string>;
  dispose(): void;
}
export interface PublicationReader {
  has(root: string, path: string): boolean;
  readText(root: string, path: string, limit?: number): Promise<string>;
}
export class ArchiveError extends Error {
  constructor(public code: string, message: string) { super(message); this.name = 'ArchiveError'; }
}
export function abortError(): ArchiveError { return new ArchiveError('cancelled', 'Archive reading was cancelled.'); }
export function checkAborted(signal?: AbortSignal): void { if (signal?.aborted) throw abortError(); }
export function safeArchiveError(error: unknown): ArchiveError {
  return error instanceof ArchiveError ? error : new ArchiveError('invalid_archive', 'The ZIP structure or a consumed entry could not be read safely.');
}
export const ARCHIVE_BUDGETS = Object.freeze({
  compressedBytes: 256 * 1024 * 1024,
  entries: 20_000,
  expandedBytes: 1024 * 1024 * 1024,
  entryBytes: 128 * 1024 * 1024,
  timeoutMs: 120_000,
});

export function freezeArchiveValue(value: unknown): void {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) freezeArchiveValue(child);
  }
}
