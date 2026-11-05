import type { SourcePair, WorkspaceResponse, WorkspaceSourceState, WorkspaceVersion } from '../domain/sources';
import { getJson, readJson } from '../app/state';
import type { WorkspaceDataSource } from './types';

export const httpDataSource: WorkspaceDataSource & {
  workspace(signal?: AbortSignal): Promise<WorkspaceResponse>;
  sources(signal?: AbortSignal): Promise<WorkspaceSourceState>;
  version(signal?: AbortSignal): Promise<WorkspaceVersion>;
  loadSources(pair: SourcePair, expectedGeneration: string, signal?: AbortSignal): Promise<WorkspaceSourceState>;
} = {
  workspace: signal => getJson('/api/workspace', signal),
  sources: signal => getJson('/api/workspace/sources', signal),
  version: signal => getJson('/api/workspace/version', signal),
  loadSources: async (pair, expectedGeneration, signal) => readJson(await fetch('/api/workspace/sources', {
    method: 'POST', signal, headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
    body: JSON.stringify({ ...pair, expectedGeneration }),
  })),
  finding: (key, generation, signal) => getJson('/api/findings/' + encodeURIComponent(key), signal, generation),
  page: (offset, limit, generation, signal) => getJson(`/api/findings?detail=1&limit=${limit}&offset=${offset}`, signal, generation),
  reference: (owner, reference, generation, signal) => getJson('/api/reference?runId=' + encodeURIComponent(owner) + '&ref=' + encodeURIComponent(JSON.stringify(reference)), signal, generation),
  evidence: (token, generation, signal) => getJson('/api/evidence/' + encodeURIComponent(token), signal, generation),
};
