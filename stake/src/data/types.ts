import type { FindingRecord } from '../domain/types';

export interface DisplayEvidence {
  status?: string; kind?: string; label?: string; message?: string; content?: unknown;
  format?: string; token?: string; reference?: unknown; executionId?: string;
}
/** Every asynchronous read belongs to one immutable workspace generation. */
export interface WorkspaceDataSource {
  finding(key: string, generation: string, signal?: AbortSignal): Promise<FindingRecord>;
  page(offset: number, limit: number, generation: string, signal?: AbortSignal): Promise<{ items: FindingRecord[]; total: number }>;
  reference(owner: string, reference: unknown, generation: string, signal?: AbortSignal): Promise<DisplayEvidence>;
  evidence(token: string, generation: string, signal?: AbortSignal): Promise<DisplayEvidence>;
}
