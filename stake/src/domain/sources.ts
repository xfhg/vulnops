import type { ExecutionKind, WorkspaceSummary } from './types';

export interface SourcePair { ordinaryPath: string; advantagePath: string }
export interface WorkspaceSource { inputPath: string; runId: string; kind: ExecutionKind }
export type SourceFieldErrors = Partial<Record<keyof SourcePair, string>>;
export interface PersistenceOutcome {
  status: 'remembered' | 'session_only' | 'not_applicable';
  message?: string;
}
export interface SourceLoadResult {
  id: string;
  status: 'success' | 'failed';
  generation: string;
  message: string;
  fieldErrors?: SourceFieldErrors;
  persistence: PersistenceOutcome;
}
export interface WorkspaceSourceState {
  generation: string;
  sources: WorkspaceSource[];
  savedPair: SourcePair | null;
  origin: 'cli' | 'saved' | 'settings' | 'empty';
  loading: boolean;
  lastLoad: SourceLoadResult | null;
  persistence: PersistenceOutcome;
  diagnostics: string[];
  fieldErrors?: SourceFieldErrors;
}
export interface WorkspaceVersion { generation: string; loading: boolean; lastLoadId: string | null }
export interface WorkspaceResponse extends WorkspaceSummary { generation: string }
export interface SourceLoadRequest extends SourcePair { expectedGeneration: string }
export interface SourceApiError { error: string; code?: string; fieldErrors?: SourceFieldErrors; generation?: string }
export interface SourceSubmissionResult {
  status: 'loaded' | 'failed' | 'pending';
  message?: string;
  fieldErrors?: SourceFieldErrors;
}
