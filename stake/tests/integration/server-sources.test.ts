import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cp, mkdir, mkdtemp, readFile, readdir, realpath, rm, symlink, unlink, writeFile } from 'node:fs/promises';
import { join, relative } from 'node:path';
import { tmpdir } from 'node:os';
import { createHash } from 'node:crypto';
import { createServer, request } from 'node:http';
import type { SourcePair, WorkspaceResponse, WorkspaceSourceState } from '../../src/domain/sources';
import type { FindingRecord } from '../../src/domain/types';
import { createStakeServer, type ServerOptions, type StakeServer } from '../../server/server';
import { SettingsStore } from '../../server/settings';
import { EvidenceRegistry } from '../../server/references';
import { runCli } from '../../server/cli';
import { makeFinding, writeBundle, writeJson, writePair } from '../fixtures/bundles';

let temporary: string, configDir: string;
let servers: StakeServer[], releases: (() => void)[];
beforeEach(async () => {
  temporary = await mkdtemp(join(tmpdir(), 'stake-sources-')); configDir = join(temporary, 'settings');
  servers = []; releases = []; vi.stubEnv('STAKE_CONFIG_DIR', configDir);
});
afterEach(async () => {
  releases.forEach((release) => release());
  await Promise.all(servers.map((server) => server.close()));
  vi.restoreAllMocks(); vi.unstubAllEnvs();
  await rm(temporary, { recursive: true, force: true });
});
function gate() {
  let release!: () => void;
  const pending = new Promise<void>((done) => { release = done; }); releases.push(release);
  return { pending, release };
}
async function pair(name = 'first'): Promise<SourcePair> {
  const ordinary = await writeBundle(join(temporary, name, 'ordinary run'), { runId: `audit-${name}`, findings: [makeFinding({ title: `Synthetic ${name} finding` })] });
  const advantage = await writeBundle(join(temporary, name, 'advantage run'), { kind: 'advantage', runId: `advantage-${name}`, baselineId: `audit-${name}` });
  return { ordinaryPath: ordinary.root, advantagePath: advantage.root };
}
async function serve(runs: string[] = [], extra: Partial<ServerOptions> = {}) {
  const server = await createStakeServer({ runs, configDir, ...extra }); servers.push(server); return server;
}
async function sources(server: StakeServer): Promise<WorkspaceSourceState> { return (await fetch(`${server.url}/api/workspace/sources`)).json(); }
async function post(server: StakeServer, selected: SourcePair, generation = server.sourceState.generation, extra: RequestInit = {}) {
  return fetch(`${server.url}/api/workspace/sources`, { method: 'POST', headers: { Origin: server.url, 'Content-Type': 'application/json' }, body: JSON.stringify({ ...selected, expectedGeneration: generation }), ...extra });
}
function data(server: StakeServer, path: string, generation = server.sourceState.generation) {
  return fetch(`${server.url}${path}`, { headers: { 'X-Stake-Workspace': generation } });
}
async function canonical(selected: SourcePair) { return { ordinaryPath: await realpath(selected.ordinaryPath), advantagePath: await realpath(selected.advantagePath) }; }
async function freePort() {
  const server = createServer();
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address(); if (!address || typeof address === 'string') throw new Error('No port');
  await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  return address.port;
}

describe('startup source precedence and remembering', () => {
  it('starts setup without creating settings, while still checking runtime prerequisites', async () => {
    const server = await serve();
    const state = await sources(server);
    expect(state).toMatchObject({ origin: 'empty', sources: [], savedPair: null, loading: false, diagnostics: [], persistence: { status: 'not_applicable' } });
    const response = await fetch(`${server.url}/api/workspace`);
    const workspace = await response.json();
    expect(workspace.assessments).toEqual([]); expect(workspace.generation).toBe(state.generation);
    expect(response.headers.get('x-stake-workspace')).toBe(state.generation);
    await expect(readFile(join(configDir, 'sources.json'))).rejects.toMatchObject({ code: 'ENOENT' });
    await expect(createStakeServer({ runs: [], configDir, python: join(temporary, 'missing-python') })).rejects.toThrow('Python');
  });

  it('remembers a complete CLI pair after canonical deduplication and reloads it without explicit roots', async () => {
    const selected = await pair();
    const alias = join(temporary, 'ordinary alias'); await symlink(selected.ordinaryPath, alias);
    const first = await serve([selected.ordinaryPath, selected.advantagePath, alias]);
    expect(first.sourceState).toMatchObject({ origin: 'cli', persistence: { status: 'remembered' }, savedPair: await canonical(selected) });
    const bytes = await readFile(join(configDir, 'sources.json'));
    const second = await serve([], { cwd: join(temporary, 'different-working-directory') });
    expect(second.workspace.assessments.map((assessment) => assessment.id)).toEqual(first.workspace.assessments.map((assessment) => assessment.id));
    expect(second.sourceState.origin).toBe('saved'); expect(second.sourceState.generation).not.toBe(first.sourceState.generation);
    expect(await readFile(join(configDir, 'sources.json'))).toEqual(bytes);
  });

  it('keeps explicit single, partial and arbitrary selections from overwriting or mixing with saved paths', async () => {
    const saved = await pair('saved'), next = await pair('next');
    await new SettingsStore({ directory: configDir }).save(saved);
    const before = await readFile(join(configDir, 'sources.json'));
    const one = await serve([next.ordinaryPath]);
    expect(one.sourceState.sources).toHaveLength(1); expect(one.sourceState.sources[0]!.runId).toBe('audit-next');
    const partial = await serve([next.advantagePath, join(temporary, 'missing')]);
    expect(partial.workspace.assessments).toHaveLength(1); expect(partial.workspace.failures).toHaveLength(1);
    const many = await serve([next.ordinaryPath, next.advantagePath, saved.ordinaryPath]);
    expect(many.workspace.assessments).toHaveLength(3);
    for (const server of [one, partial, many]) expect(server.sourceState.persistence.status).toBe('not_applicable');
    expect(await readFile(join(configDir, 'sources.json'))).toEqual(before);
    await expect(createStakeServer({ runs: [join(temporary, 'missing')], configDir })).rejects.toThrow('No supplied publication');
    expect(await readFile(join(configDir, 'sources.json'))).toEqual(before);
  });

  it('serves recovery without partial activation when a saved folder is missing', async () => {
    const saved = await pair(); await new SettingsStore({ directory: configDir }).save(saved);
    const before = await readFile(join(configDir, 'sources.json'));
    await rm(saved.advantagePath, { recursive: true });
    const server = await serve();
    expect(server.workspace.assessments).toHaveLength(0);
    const { version: _version, ...savedPair } = JSON.parse(before.toString());
    expect(server.sourceState).toMatchObject({ origin: 'empty', savedPair, fieldErrors: { advantagePath: expect.stringContaining('unavailable') } });
    expect(await readFile(join(configDir, 'sources.json'))).toEqual(before);
  });

  it('keeps malformed preferences recoverable and replaces them only after explicit successful loading', async () => {
    await mkdir(configDir); await writeFile(join(configDir, 'sources.json'), '{SYNTHETIC_DO_NOT_ECHO');
    const server = await serve();
    expect(server.sourceState.diagnostics.join()).not.toContain('SYNTHETIC');
    expect(server.sourceState.diagnostics).toHaveLength(1); expect(server.workspace.assessments).toHaveLength(0);
    const selected = await pair(); expect((await post(server, selected)).status).toBe(200);
    expect((await new SettingsStore({ directory: configDir }).read()).pair).toEqual(await canonical(selected));
  });

  it('retains one safe saved path in setup and clears obsolete diagnostics after CLI repair', async () => {
    const selected = await pair(); await mkdir(configDir);
    await writeFile(join(configDir, 'sources.json'), JSON.stringify({ version: 1, ordinaryPath: selected.ordinaryPath }));
    const recovery = await serve();
    expect(recovery.sourceState.savedPair).toEqual({ ordinaryPath: selected.ordinaryPath, advantagePath: '' });
    expect(recovery.workspace.assessments).toHaveLength(0); expect(recovery.sourceState.diagnostics).toHaveLength(1);
    const messages: string[] = [];
    const repaired = await runCli(['serve', '--run', selected.ordinaryPath, '--run', selected.advantagePath, '--no-open'], { log: (text) => messages.push(text), warn: (text) => messages.push(text), options: { configDir } }); servers.push(repaired!);
    expect(repaired!.sourceState.persistence.status).toBe('remembered'); expect(repaired!.sourceState.diagnostics).toEqual([]);
    expect(messages.join()).not.toContain('invalid format'); expect(messages.join()).not.toContain('replace them');
  });

  it('does not remember a new CLI pair if the requested port is occupied', async () => {
    const prior = await pair('prior'), next = await pair('next');
    const first = await serve(Object.values(prior)); const before = await readFile(join(configDir, 'sources.json'));
    const beforeSave = vi.fn(async () => {});
    await expect(createStakeServer({ runs: Object.values(next), configDir, port: Number(new URL(first.url).port), sourceHooks: { beforeSave } })).rejects.toThrow('occupied');
    expect(beforeSave).not.toHaveBeenCalled(); expect(await readFile(join(configDir, 'sources.json'))).toEqual(before);
  });

  it('holds the source lock between listening and initial CLI persistence', async () => {
    const selected = await pair(); const blocked = gate(); const entered = gate(); const port = await freePort();
    const starting = createStakeServer({ runs: Object.values(selected), configDir, port, sourceHooks: { beforeSave: async () => { entered.release(); await blocked.pending; } } });
    await entered.pending;
    const url = `http://127.0.0.1:${port}`;
    const state: WorkspaceSourceState = await (await fetch(`${url}/api/workspace/sources`)).json();
    expect(state.loading).toBe(true);
    const rejected = await fetch(`${url}/api/workspace/sources`, { method: 'POST', headers: { Origin: url, 'Content-Type': 'application/json' }, body: JSON.stringify({ ...selected, expectedGeneration: state.generation }) });
    expect(rejected.status).toBe(409); expect((await rejected.json()).code).toBe('load_in_progress');
    blocked.release(); const server = await starting; servers.push(server);
    expect(server.sourceState.loading).toBe(false); expect(server.sourceState.persistence.status).toBe('remembered');
  });

  it('reports setup and nonfatal session-only saving through CLI output', async () => {
    const messages: string[] = [], opener = vi.fn(async () => {});
    const setup = await runCli(['serve', '--no-open'], { log: (text) => messages.push(text), warn: (text) => messages.push(text), opener, options: { configDir } }); servers.push(setup!);
    expect(messages.join()).toContain('ready for report setup'); expect(opener).not.toHaveBeenCalled();
    const selected = await pair();
    const loaded = await runCli(['serve', '--run', selected.ordinaryPath, '--run', selected.advantagePath, '--no-open'], { log: (text) => messages.push(text), warn: (text) => messages.push(text), options: { configDir, sourceHooks: { beforeSave: async () => { throw new Error('synthetic disk failure'); } } } }); servers.push(loaded!);
    expect(loaded!.workspace.assessments).toHaveLength(2); expect(messages.join()).toContain('Loaded for this session');
  });
});

describe('strict source replacement and coherent snapshots', () => {
  it('loads and remembers an unknown service binding with a null name without rewriting either report bundle', async () => {
    const service = {
      name: null, binding: 'unknown',
      limitation: 'The source inventory identifies this repository component, but no service or deployment binding was established.',
      evidence_refs: [],
    };
    const finding = makeFinding(); finding.affected_components![0]!.service = service;
    const root = join(temporary, 'nullable-service');
    const ordinary = await writeBundle(join(root, 'ordinary run'), { runId: 'audit-nullable-service', findings: [finding] });
    const advantage = await writeBundle(join(root, 'advantage run'), { kind: 'advantage', runId: 'advantage-nullable-service', baselineId: 'audit-nullable-service' });
    const selected = { ordinaryPath: ordinary.root, advantagePath: advantage.root };
    async function reportInventory(): Promise<Record<string, string>> {
      const inventory: Record<string, string> = {};
      async function visit(directory: string) {
        for (const entry of await readdir(directory, { withFileTypes: true })) {
          const path = join(directory, entry.name);
          if (entry.isDirectory()) { inventory[`${relative(root, path)}/`] = 'directory'; await visit(path); }
          else inventory[relative(root, path)] = createHash('sha256').update(await readFile(path)).digest('hex');
        }
      }
      await visit(root); return inventory;
    }
    const before = await reportInventory();
    const server = await serve(); const generation = server.sourceState.generation;
    const response = await post(server, selected); const state: WorkspaceSourceState = await response.json();
    expect(response.status).toBe(200);
    expect(state.generation).not.toBe(generation);
    expect(state).toMatchObject({ origin: 'settings', savedPair: await canonical(selected), persistence: { status: 'remembered' }, lastLoad: { status: 'success' } });
    expect((await new SettingsStore({ directory: configDir }).read()).pair).toEqual(await canonical(selected));

    const workspaceResponse = await data(server, '/api/workspace');
    expect(workspaceResponse.status).toBe(200);
    const workspace: WorkspaceResponse = await workspaceResponse.json();
    expect(workspace.failures).toEqual([]); expect(workspace.assessments).toHaveLength(2);
    const summary = workspace.findings.find(row => row.runId === 'audit-nullable-service' && row.id === finding.id)!;
    expect(summary).toBeDefined();
    expect(summary.components[0]).toMatchObject({ id: 'component-1', serviceName: null, serviceBinding: 'unknown' });
    const detailResponse = await data(server, `/api/findings/${encodeURIComponent(summary.key)}`);
    expect(detailResponse.status).toBe(200);
    const detail: FindingRecord = await detailResponse.json();
    expect(detail.raw).toEqual(finding);
    expect(detail.raw.affected_components![0]!.service).toEqual(service);
    expect(await reportInventory()).toEqual(before);
  });

  it('replaces all data together, updates the public getter, and preserves a failed replacement', async () => {
    const initial = await pair('initial'), next = await pair('next');
    const server = await serve(Object.values(initial)); const generation = server.sourceState.generation;
    const original = server.workspace; const originalBytes = await readFile(join(initial.ordinaryPath, 'report/security-report.json'));
    const before = await readFile(join(configDir, 'sources.json'));
    const invalid = await post(server, { ...next, advantagePath: join(temporary, 'missing') });
    expect(invalid.status).toBe(422); expect((await invalid.json()).fieldErrors.advantagePath).toContain('unavailable');
    expect(server.workspace).toBe(original); expect(server.sourceState.generation).toBe(generation);
    expect(await readFile(join(configDir, 'sources.json'))).toEqual(before);
    expect((await data(server, '/api/findings?detail=1')).status).toBe(200);
    const loaded = await post(server, next); const state = await loaded.json();
    expect(loaded.status).toBe(200); expect(state.generation).not.toBe(generation);
    expect(loaded.headers.get('x-stake-workspace')).toBe(state.generation);
    expect(server.workspace).not.toBe(original); expect(server.workspace.assessments.map((assessment) => assessment.id)).toEqual(['audit-next', 'advantage-next']);
    const rows = await (await data(server, '/api/findings?detail=1')).json();
    expect(rows.items.some((finding: { runId: string }) => finding.runId === 'audit-initial')).toBe(false);
    expect(await readFile(join(initial.ordinaryPath, 'report/security-report.json'))).toEqual(originalBytes);
    expect((await new SettingsStore({ directory: configDir }).read()).pair).toEqual(await canonical(next));
  });

  it.each(['relative', 'controls', 'same-root', 'wrong-kind', 'execution-conflict', 'unsupported'])('rejects %s source fields without changing the workspace', async (kind) => {
    const selected = await pair(); const server = await serve(); const generation = server.sourceState.generation;
    let requestPair = { ...selected };
    if (kind === 'relative') requestPair.ordinaryPath = 'relative/path';
    if (kind === 'controls') requestPair.advantagePath += '\n';
    if (kind === 'same-root') { const alias = join(temporary, 'alias'); await symlink(selected.ordinaryPath, alias); requestPair.advantagePath = alias; }
    if (kind === 'wrong-kind') requestPair = { ordinaryPath: selected.advantagePath, advantagePath: selected.ordinaryPath };
    if (kind === 'execution-conflict') { await rm(selected.advantagePath, { recursive: true }); await cp(selected.ordinaryPath, selected.advantagePath, { recursive: true }); }
    if (kind === 'unsupported') {
      const file = join(selected.advantagePath, 'report/security-report.json');
      const report = JSON.parse(await readFile(file, 'utf8')); report.mode = 'actions'; await writeFile(file, JSON.stringify(report));
    }
    const response = await post(server, requestPair);
    expect(response.status).toBe(422); expect(Object.keys((await response.json()).fieldErrors).length).toBeGreaterThan(0);
    expect(server.sourceState.generation).toBe(generation); expect(server.workspace.assessments).toHaveLength(0);
    expect(server.sourceState.lastLoad?.status).toBe('failed');
  });

  it('allows an unrelated ordinary run without substituting it for unavailable baseline ownership', async () => {
    const ordinary = await writeBundle(join(temporary, 'ordinary'), { runId: 'unrelated-audit' });
    const inherited = { execution_id: 'recorded-baseline', artifact_ref: 'sast/verified-findings.json:C-001' };
    const finding = makeFinding(); finding.exploitation!.steps[0]!.evidence_refs = [inherited];
    const advantage = await writeBundle(join(temporary, 'advantage'), { kind: 'advantage', runId: 'advantage', baselineId: 'recorded-baseline', findings: [finding] });
    await unlink(join(ordinary.root, 'sast/verified-findings.json'));
    const server = await serve(); expect((await post(server, { ordinaryPath: ordinary.root, advantagePath: advantage.root })).status).toBe(200);
    const reference = await (await data(server, `/api/reference?${new URLSearchParams({ runId: 'advantage', ref: JSON.stringify(inherited) })}`)).json();
    const result = await (await data(server, `/api/evidence/${reference.token}`)).json();
    expect(result.status).toBe('unavailable'); expect(result.executionId).toBe('recorded-baseline');
  });

  it('keeps active reads available while preparing and rejects overlapping or stale submissions', async () => {
    const initial = await pair('initial'), next = await pair('next'), blocked = gate();
    const server = await serve(Object.values(initial), { sourceHooks: { beforeLoad: () => blocked.pending } });
    const generation = server.sourceState.generation; const pending = post(server, next);
    await vi.waitFor(async () => expect((await sources(server)).loading).toBe(true));
    expect((await data(server, '/api/findings', generation)).status).toBe(200);
    expect(server.workspace.assessments[0]!.id).toBe('audit-initial');
    const overlap = await post(server, initial); expect(overlap.status).toBe(409); expect((await overlap.json()).code).toBe('load_in_progress');
    blocked.release(); expect((await pending).status).toBe(200);
    const stale = await post(server, initial, generation); expect(stale.status).toBe(409); expect((await stale.json()).code).toBe('workspace_changed');
    expect(server.workspace.assessments[0]!.id).toBe('audit-next');
  });

  it('commits usable reports on a save failure and retains previous complete preferences', async () => {
    const initial = await pair('initial'), next = await pair('next');
    await new SettingsStore({ directory: configDir }).save(initial); const before = await readFile(join(configDir, 'sources.json'));
    const server = await serve([], { sourceHooks: { beforeSave: async () => { throw new Error('SYNTHETIC_DO_NOT_ECHO'); } } });
    const response = await post(server, next); const state = await response.json();
    expect(response.status).toBe(200); expect(state.persistence.status).toBe('session_only');
    expect(state.lastLoad.persistence.status).toBe('session_only'); expect(JSON.stringify(state)).not.toContain('SYNTHETIC_DO_NOT_ECHO');
    expect(server.workspace.assessments[0]!.id).toBe('audit-next'); expect(state.savedPair).toEqual(await canonical(initial));
    expect(await readFile(join(configDir, 'sources.json'))).toEqual(before);
  });

  it('recovers pending and session-only completion state after the client drops its response', async () => {
    const selected = await pair(), blocked = gate();
    const server = await serve([], { sourceHooks: { beforeSave: async () => { await blocked.pending; throw new Error('synthetic save failure'); } } });
    const generation = server.sourceState.generation, controller = new AbortController();
    const pending = post(server, selected, generation, { signal: controller.signal }).catch(() => null);
    await vi.waitFor(async () => expect((await sources(server)).loading).toBe(true));
    controller.abort(); await pending;
    const during = await (await fetch(`${server.url}/api/workspace/version`)).json();
    expect(during).toMatchObject({ generation, loading: true, lastLoadId: null });
    blocked.release();
    await vi.waitFor(async () => expect((await sources(server)).lastLoad?.status).toBe('success'));
    const recovered = await sources(server);
    expect(recovered.generation).not.toBe(generation); expect(recovered.loading).toBe(false);
    expect(recovered.lastLoad?.persistence.status).toBe('session_only');
    expect((await (await fetch(`${server.url}/api/workspace/version`)).json()).lastLoadId).toBe(recovered.lastLoad!.id);
  });

  it('changes generation and evidence tokens on same-path reload and rejects stale pagination', async () => {
    const fixture = await writePair(join(temporary, 'same-identities'));
    const selected = { ordinaryPath: fixture.ordinary.root, advantagePath: fixture.advantage.root };
    const server = await serve(Object.values(selected)); const old = server.sourceState.generation;
    const query = `/api/reference?${new URLSearchParams({ runId: 'audit-fixture', ref: JSON.stringify('sast/verified-findings.json:C-001') })}`;
    const previous = await (await data(server, query)).json();
    expect((await (await data(server, `/api/evidence/${previous.token}`)).json()).content.explanation).toBe('Synthetic canonical support.');
    expect((await (await data(server, '/api/findings?limit=1')).json()).items).toHaveLength(1);
    await writeJson(selected.ordinaryPath, 'sast/verified-findings.json', [{ id: 'C-001', explanation: 'Synthetic replacement support.' }]);
    expect((await post(server, selected)).status).toBe(200);
    expect((await data(server, '/api/findings?offset=1&limit=1', old)).status).toBe(409);
    expect((await data(server, `/api/evidence/${previous.token}`, old)).status).toBe(409);
    expect((await data(server, `/api/evidence/${previous.token}`)).status).toBe(404);
    const current = await (await data(server, query)).json(); expect(current.token).not.toBe(previous.token);
    expect((await (await data(server, `/api/evidence/${current.token}`)).json()).content.explanation).toBe('Synthetic replacement support.');
  });

  it('labels an old in-flight evidence response with its captured generation after replacement', async () => {
    const initial = await pair('initial'), next = await pair('next');
    const server = await serve(Object.values(initial)); const old = server.sourceState.generation;
    const query = `/api/reference?${new URLSearchParams({ runId: 'audit-initial', ref: JSON.stringify('sast/verified-findings.json:C-001') })}`;
    const previous = await (await data(server, query)).json();
    const blocked = gate(), entered = gate();
    const originalRead = EvidenceRegistry.prototype.read;
    vi.spyOn(EvidenceRegistry.prototype, 'read').mockImplementation(async function (this: EvidenceRegistry, token: string) {
      const captured = await originalRead.call(this, token); entered.release(); await blocked.pending; return captured;
    });
    const pending = data(server, `/api/evidence/${previous.token}`, old);
    await entered.pending;
    expect((await post(server, next)).status).toBe(200);
    blocked.release(); const response = await pending;
    expect(response.status).toBe(200); expect(response.headers.get('x-stake-workspace')).toBe(old);
    const result = await response.json(); expect(result.executionId).toBe('audit-initial'); expect(result.content.explanation).toBe('Synthetic canonical support.');
    expect((await data(server, `/api/evidence/${previous.token}`)).status).toBe(404);
  });

  it('loads without remembering when a newly selected report contains the configured settings location', async () => {
    const selected = await pair(); const inside = join(selected.ordinaryPath, 'viewer-settings');
    const server = await serve([], { configDir: inside });
    const response = await post(server, selected); expect(response.status).toBe(200);
    const state = await response.json(); expect(state.persistence.status).toBe('session_only'); expect(server.workspace.assessments).toHaveLength(2);
    await expect(readFile(join(inside, 'sources.json'))).rejects.toMatchObject({ code: 'ENOENT' });
  });
});

describe('bounded local configuration API', () => {
  it('requires a generation only on report data, with explicit reload or changed responses', async () => {
    const server = await serve();
    for (const path of ['/api/workspace', '/api/workspace/sources', '/api/workspace/version']) expect((await fetch(`${server.url}${path}`)).status).toBe(200);
    for (const path of ['/api/findings', '/api/assessments', '/api/relations', '/api/reference', '/api/evidence/unknown']) {
      const missing = await fetch(`${server.url}${path}`); expect(missing.status).toBe(428); expect((await missing.json()).code).toBe('reload_required');
      const stale = await data(server, path, 'old-generation'); expect(stale.status).toBe(409); expect((await stale.json()).code).toBe('workspace_changed');
    }
  });

  it('rejects foreign and malformed requests before admission and allows no other mutations', async () => {
    const selected = await pair(), beforeLoad = vi.fn(async () => {});
    const server = await serve([], { sourceHooks: { beforeLoad } });
    const body = JSON.stringify({ ...selected, expectedGeneration: server.sourceState.generation });
    const cases: { headers?: Record<string, string>; body?: string; status: number }[] = [
      { headers: { 'Content-Type': 'application/json' }, status: 403 },
      { headers: { Origin: 'https://foreign.example', 'Content-Type': 'application/json' }, status: 403 },
      { headers: { Origin: server.url, 'Content-Type': 'application/json', 'Sec-Fetch-Site': 'cross-site' }, status: 403 },
      { headers: { Origin: server.url, 'Content-Type': 'text/plain' }, status: 415 },
      { body: '{invalid', status: 400 },
      { body: JSON.stringify({ ...selected, expectedGeneration: server.sourceState.generation, extra: 'field' }), status: 400 },
      { body: JSON.stringify({ ...selected, expectedGeneration: null }), status: 400 },
      { body: 'x'.repeat(65_537), status: 413 },
      { body: JSON.stringify({ ...selected, ordinaryPath: '/' + 'x'.repeat(16_384), expectedGeneration: server.sourceState.generation }), status: 413 },
    ];
    for (const item of cases) {
      const response = await fetch(`${server.url}/api/workspace/sources`, { method: 'POST', headers: item.headers ?? { Origin: server.url, 'Content-Type': 'application/json' }, body: item.body ?? body });
      expect(response.status).toBe(item.status); expect(response.headers.get('access-control-allow-origin')).toBeNull();
    }
    const foreignHost = await new Promise<number>((resolveResponse, reject) => {
      const req = request(`${server.url}/api/workspace/sources`, { method: 'POST', headers: { Host: 'foreign.example', Origin: server.url, 'Content-Type': 'application/json' } }, (res) => { res.resume(); resolveResponse(res.statusCode!); });
      req.on('error', reject); req.end(body);
    });
    expect(foreignHost).toBe(403);
    for (const path of ['/api/workspace', '/api/findings', '/']) expect((await fetch(`${server.url}${path}`, { method: 'POST', headers: { Origin: server.url } })).status).toBe(405);
    expect((await fetch(`${server.url}/api/workspace/sources`, { method: 'DELETE', headers: { Origin: server.url } })).status).toBe(405);
    expect(beforeLoad).not.toHaveBeenCalled(); expect(server.sourceState.lastLoad).toBeNull();
    await expect(readFile(join(configDir, 'sources.json'))).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('bounds chunked bodies without trusting Content-Length', async () => {
    const beforeLoad = vi.fn(async () => {}); const server = await serve([], { sourceHooks: { beforeLoad } });
    const response = await new Promise<{ status: number; body: string }>((resolveResponse, reject) => {
      const req = request(`${server.url}/api/workspace/sources`, { method: 'POST', headers: { Origin: server.url, 'Content-Type': 'application/json', 'Transfer-Encoding': 'chunked' } }, (res) => {
        let body = ''; res.on('data', (chunk) => { body += chunk; }); res.on('end', () => resolveResponse({ status: res.statusCode!, body }));
      });
      req.on('error', reject); req.write('x'.repeat(40_000)); req.end('x'.repeat(40_000));
    });
    expect(response.status).toBe(413); expect(response.body).toContain('64 KiB'); expect(beforeLoad).not.toHaveBeenCalled();
  });
});
