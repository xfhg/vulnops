import http, { type IncomingMessage, type ServerResponse } from 'node:http';
import { readFile, lstat, realpath } from 'node:fs/promises';
import { extname, relative, resolve, sep } from 'node:path';
import type { EvidenceReference, FindingFilters, Workspace } from '../src/domain/types.js';
import type { SourceLoadRequest, WorkspaceSourceState } from '../src/domain/sources.js';
import { filterFindings } from '../src/domain/index.js';
import { packageRoot } from './bridge.js';
import { SourceLoadError, StartupError, WorkspaceCoordinator, type CoordinatorOptions } from './workspace.js';
import { MAX_SETTINGS_BYTES, MAX_SOURCE_PATH_BYTES } from './settings.js';
export { StartupError } from './workspace.js';

export interface ServerOptions extends CoordinatorOptions { port?: number; staticRoot?: string }
export interface StakeServer { url: string; server: http.Server; readonly workspace: Workspace; readonly sourceState: WorkspaceSourceState; close(): Promise<void> }
const contentTypes: Record<string, string> = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.json': 'application/json; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png', '.woff2': 'font/woff2', '.ico': 'image/x-icon', '.map': 'application/json; charset=utf-8' };

function headers(response: ServerResponse): void {
  response.setHeader('Content-Security-Policy', "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; worker-src 'self' blob:; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'none'");
  response.setHeader('X-Content-Type-Options', 'nosniff');
  response.setHeader('Referrer-Policy', 'no-referrer');
  response.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  response.setHeader('Cache-Control', 'no-store');
}
function json(response: ServerResponse, status: number, value: unknown, head = false): void {
  response.statusCode = status;
  response.setHeader('Content-Type', 'application/json; charset=utf-8');
  response.end(head ? undefined : JSON.stringify(value));
}
function integer(value: string | null, fallback: number, min: number, max: number): number {
  if (value === null) return fallback;
  if (!/^\d+$/.test(value)) throw new Error('Invalid pagination');
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number < min || number > max) throw new Error('Invalid pagination');
  return number;
}

class RequestError extends Error { constructor(public status: number, message: string) { super(message); } }
async function sourceRequest(request: IncomingMessage): Promise<SourceLoadRequest> {
  if (request.headers['content-type']?.split(';')[0]?.trim().toLowerCase() !== 'application/json') throw new RequestError(415, 'Report-source requests require application/json.');
  if (Number(request.headers['content-length']) > MAX_SETTINGS_BYTES) { request.resume(); throw new RequestError(413, 'Report-source requests must not exceed 64 KiB.'); }
  const bytes = await new Promise<Buffer>((resolveBody, rejectBody) => {
    const chunks: Buffer[] = []; let length = 0;
    const cleanup = () => { request.off('data', data); request.off('end', end); request.off('error', error); request.off('aborted', error); };
    const error = () => { cleanup(); rejectBody(new RequestError(400, 'The report-source request was incomplete.')); };
    const data = (chunk: Buffer) => {
      length += chunk.length;
      if (length > MAX_SETTINGS_BYTES) { cleanup(); request.resume(); rejectBody(new RequestError(413, 'Report-source requests must not exceed 64 KiB.')); }
      else chunks.push(chunk);
    };
    const end = () => { cleanup(); resolveBody(Buffer.concat(chunks)); };
    request.on('data', data); request.once('end', end); request.once('error', error); request.once('aborted', error);
  });
  let body: unknown;
  try { body = JSON.parse(bytes.toString('utf8')); }
  catch { throw new RequestError(400, 'Supply a valid JSON report-source request.'); }
  if (!body || typeof body !== 'object' || Array.isArray(body) || Object.keys(body).sort().join(',') !== 'advantagePath,expectedGeneration,ordinaryPath') throw new RequestError(400, 'Supply exactly ordinaryPath, advantagePath and expectedGeneration.');
  const value = body as Record<string, unknown>;
  if (typeof value.ordinaryPath !== 'string' || typeof value.advantagePath !== 'string' || typeof value.expectedGeneration !== 'string' || !value.expectedGeneration || value.expectedGeneration.length > 128) throw new RequestError(400, 'Source paths and the expected workspace generation must be strings.');
  if (Buffer.byteLength(value.ordinaryPath) > MAX_SOURCE_PATH_BYTES || Buffer.byteLength(value.advantagePath) > MAX_SOURCE_PATH_BYTES) throw new RequestError(413, 'Each report-source path must not exceed 16 KiB.');
  return value as unknown as SourceLoadRequest;
}

async function staticFile(requestPath: string, root: string): Promise<{ bytes: Buffer; type: string } | null> {
  let decoded: string;
  try { decoded = decodeURIComponent(requestPath); } catch { return null; }
  if (/[\x00-\x1f\\]/.test(decoded) || decoded.split('/').some((part) => part === '..' || part === '.')) return null;
  const name = decoded === '/' ? 'index.html' : decoded.slice(1);
  // Router paths return the shell, while missing asset paths remain 404s.
  const selected = extname(name) ? name : 'index.html';
  const path = resolve(root, selected);
  if (relative(root, path).startsWith('..') || path === root) return null;
  let current = root;
  try {
    for (const part of relative(root, path).split(sep)) {
      current = resolve(current, part);
      const info = await lstat(current);
      if (info.isSymbolicLink()) return null;
    }
    if (!(await lstat(path)).isFile()) return null;
    return { bytes: await readFile(path), type: contentTypes[extname(path)] ?? 'application/octet-stream' };
  } catch { return null; }
}

export async function createStakeServer(options: ServerOptions): Promise<StakeServer> {
  const coordinator = await WorkspaceCoordinator.create(options);
  const staticRoot = await realpath(options.staticRoot ?? resolve(packageRoot, 'dist')).catch(() => resolve(options.staticRoot ?? resolve(packageRoot, 'dist')));
  let origin = '';
  const serve = async (request: IncomingMessage, response: ServerResponse) => {
    headers(response);
    const head = request.method === 'HEAD';
    const expectedHost = new URL(origin).host;
    if (request.headers.host !== expectedHost || (request.headers.origin !== undefined && request.headers.origin !== origin) || request.headers['sec-fetch-site'] === 'cross-site') {
      json(response, 403, { error: 'Only requests from this local workspace are allowed.' }, head); return;
    }
    const url = new URL(request.url ?? '/', origin);
    if (url.origin !== origin) { json(response, 403, { error: 'Invalid request origin.' }, head); return; }
    // Capture once: a read begun before a switch may finish afterward, but its
    // bytes and response generation always belong to this same snapshot.
    const snapshot = coordinator.snapshot;
    const { workspace, summary, references, byKey, summaries, generation } = snapshot;
    if (url.pathname.startsWith('/api/')) response.setHeader('X-Stake-Workspace', generation);
    if (request.method === 'POST' && url.pathname === '/api/workspace/sources') {
      if (request.headers.origin !== origin) { json(response, 403, { error: 'An explicit matching local Origin is required.' }); return; }
      try {
        const body = await sourceRequest(request);
        const state = await coordinator.load(body);
        response.setHeader('X-Stake-Workspace', state.generation);
        json(response, 200, state);
      } catch (error) {
        if (error instanceof SourceLoadError) {
          response.setHeader('X-Stake-Workspace', error.generation);
          json(response, error.status, { error: error.message, code: error.code, generation: error.generation, ...(error.fieldErrors ? { fieldErrors: error.fieldErrors } : {}) });
        } else if (error instanceof RequestError) {
          const current = coordinator.snapshot.generation;
          response.setHeader('X-Stake-Workspace', current);
          json(response, error.status, { error: error.message, generation: current });
        }
        else throw error;
      }
      return;
    }
    if (request.method !== 'GET' && !head) { response.setHeader('Allow', url.pathname === '/api/workspace/sources' ? 'GET, HEAD, POST' : 'GET, HEAD'); json(response, 405, { error: 'Only report-source configuration can be changed.' }); return; }
    if (url.pathname === '/api/workspace') { json(response, 200, { ...summary, generation }, head); return; }
    if (url.pathname === '/api/workspace/sources') { json(response, 200, coordinator.sources, head); return; }
    if (url.pathname === '/api/workspace/version') { json(response, 200, coordinator.version, head); return; }
    if (url.pathname.startsWith('/api/')) {
      const expected = request.headers['x-stake-workspace'];
      if (!expected || expected !== generation) {
        json(response, expected ? 409 : 428, { error: 'Reload the workspace before requesting report data.', code: expected ? 'workspace_changed' : 'reload_required', generation }, head); return;
      }
    }
    if (url.pathname === '/api/assessments') { json(response, 200, { items: summary.assessments, failures: summary.failures }, head); return; }
    if (url.pathname === '/api/relations') { json(response, 200, { items: workspace.relations }, head); return; }
    if (url.pathname === '/api/findings') {
      let offset: number, limit: number;
      try { offset = integer(url.searchParams.get('offset'), 0, 0, Number.MAX_SAFE_INTEGER); limit = integer(url.searchParams.get('limit'), 100, 1, 1000); }
      catch { json(response, 400, { error: 'Use nonnegative offset and limit between 1 and 1000.' }, head); return; }
      const filters: FindingFilters = {};
      for (const key of ['query', 'assessment', 'runId', 'repository', 'component', 'severity', 'disposition', 'cohort', 'kind', 'classification', 'origin', 'sort', 'direction'] as const) {
        const value = url.searchParams.get(key);
        if (value) (filters as Record<string, string>)[key] = value;
      }
      const matches = filterFindings(workspace.findings, filters);
      const items = matches.slice(offset, offset + limit).map((finding) => url.searchParams.get('detail') === '1' ? finding : summaries.get(finding.key));
      json(response, 200, { items, total: matches.length, offset, limit }, head); return;
    }
    if (url.pathname.startsWith('/api/findings/')) {
      let key: string;
      try { key = decodeURIComponent(url.pathname.slice('/api/findings/'.length)); }
      catch { json(response, 400, { error: 'Invalid finding selection.' }, head); return; }
      const finding = byKey.get(key);
      json(response, finding ? 200 : 404, finding ?? { error: 'The selected finding is unavailable.' }, head); return;
    }
    if (url.pathname === '/api/reference') {
      const runId = url.searchParams.get('runId');
      const serialized = url.searchParams.get('ref');
      if (!runId || !serialized || serialized.length > 16_384) { json(response, 400, { error: 'Supply an execution and registered reference.' }, head); return; }
      let ref: EvidenceReference;
      try { ref = JSON.parse(serialized) as EvidenceReference; }
      catch { json(response, 400, { error: 'Reference must be JSON encoded.' }, head); return; }
      const entry = references.find(runId, ref);
      json(response, entry ? 200 : 404, entry ?? { error: 'This reference is not registered by an admitted publication.' }, head); return;
    }
    if (url.pathname.startsWith('/api/evidence/')) {
      const token = url.pathname.slice('/api/evidence/'.length);
      if (!/^[a-zA-Z0-9_-]{43}$/.test(token)) { json(response, 404, { error: 'Unknown evidence selection.' }, head); return; }
      const result = await references.read(token);
      json(response, result ? 200 : 404, result ?? { error: 'Unknown evidence selection.' }, head); return;
    }
    if (url.pathname.startsWith('/api/')) { json(response, 404, { error: 'Unknown read endpoint.' }, head); return; }
    const file = await staticFile(url.pathname, staticRoot);
    if (!file) { json(response, 404, { error: 'Application asset is unavailable. Build Stake with npm run build in stake/.' }, head); return; }
    response.statusCode = 200;
    response.setHeader('Content-Type', file.type);
    response.end(head ? undefined : file.bytes);
  };
  const server = http.createServer((request, response) => {
    void serve(request, response).catch(() => {
      if (!response.headersSent) json(response, 500, { error: 'The requested publication data could not be served.' });
      else response.end();
    });
  });
  server.requestTimeout = 30_000;
  server.headersTimeout = 15_000;
  server.maxHeadersCount = 50;
  await new Promise<void>((resolveListen, reject) => {
    server.once('error', (error: NodeJS.ErrnoException) => reject(new StartupError(error.code === 'EADDRINUSE' ? 'The requested port is occupied. Choose another --port or omit it for an available port.' : 'The loopback server could not start.')));
    server.listen(options.port ?? 0, '127.0.0.1', () => {
      const address = server.address();
      if (!address || typeof address === 'string') return reject(new StartupError('Could not determine loopback address.'));
      origin = `http://127.0.0.1:${address.port}`;
      resolveListen();
    });
  });
  await coordinator.finishStartup();
  return { url: origin, server, get workspace() { return coordinator.workspace; }, get sourceState() { return coordinator.sources; }, close: () => new Promise((resolveClose, reject) => {
    server.closeIdleConnections();
    server.close((error) => error ? reject(error) : resolveClose());
  }) };
}
