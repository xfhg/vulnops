import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cp, mkdir, mkdtemp, readFile, readdir, rm, symlink, unlink, writeFile } from 'node:fs/promises';
import { join, relative } from 'node:path';
import { tmpdir } from 'node:os';
import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { request } from 'node:http';
import { importBundles } from '../../server/admission';
import { bridgeCall, checkPrerequisites } from '../../server/bridge';
import { createStakeServer, StartupError, type StakeServer } from '../../server/server';
import { parseArgs, runCli } from '../../server/cli';
import { makeFinding, makeMixedObservationFinding, writeBundle, writeJson, writePair } from '../fixtures/bundles';

let temporary: string;
let servers: StakeServer[];
beforeEach(async () => { temporary = await mkdtemp(join(tmpdir(), 'stake-server-')); servers = []; vi.stubEnv('STAKE_CONFIG_DIR', join(temporary, 'settings')); });
afterEach(async () => { vi.unstubAllEnvs(); await Promise.all(servers.map((server) => server.close())); await rm(temporary, { recursive: true, force: true }); });

async function serve(runs: string[], extra: Partial<Parameters<typeof createStakeServer>[0]> = {}) {
  const staticRoot = join(temporary, 'web');
  await mkdir(staticRoot, { recursive: true });
  await writeFile(join(staticRoot, 'index.html'), '<!doctype html><title>Stake fixture</title>');
  const server = await createStakeServer({ runs, staticRoot, ...extra });
  servers.push(server); return server;
}
async function workspaceFetch(input: string, init: RequestInit = {}): Promise<Response> {
  const url = new URL(input);
  const headers = new Headers(init.headers);
  if (url.pathname.startsWith('/api/') && !['/api/workspace', '/api/workspace/sources', '/api/workspace/version'].includes(url.pathname)) {
    const bootstrap = await (await fetch(`${url.origin}/api/workspace`)).json();
    headers.set('X-Stake-Workspace', bootstrap.generation);
  }
  return fetch(input, { ...init, headers });
}
async function lookup(server: StakeServer, runId: string, ref: unknown) {
  const response = await workspaceFetch(`${server.url}/api/reference?${new URLSearchParams({ runId, ref: JSON.stringify(ref) })}`);
  return { response, entry: await response.json() };
}
async function evidence(server: StakeServer, runId: string, ref: unknown) {
  const { response, entry } = await lookup(server, runId, ref);
  expect(response.status).toBe(200);
  const result = await workspaceFetch(`${server.url}/api/evidence/${entry.token}`);
  return result.json();
}
async function inventory(root: string): Promise<Record<string, string>> {
  const output: Record<string, string> = {};
  async function visit(directory: string) {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) await visit(path);
      else output[relative(root, path)] = createHash('sha256').update(await readFile(path)).digest('hex');
    }
  }
  await visit(root); return output;
}

describe('portable publication admission', () => {
  it('loads a relocated manifest-free pair, complete dossiers and recorded baseline relationships without mutation', async () => {
    const pair = await writePair(join(temporary, 'original'));
    const copied = join(temporary, 'relocated');
    await cp(join(temporary, 'original'), copied, { recursive: true });
    await rm(join(temporary, 'original'), { recursive: true });
    const before = await inventory(copied);
    const server = await serve([join(copied, 'ordinary run'), join(copied, 'advantage run')]);
    const workspace = await (await workspaceFetch(`${server.url}/api/workspace`)).json();
    expect(workspace.assessments).toHaveLength(2);
    expect(workspace.findings).toHaveLength(4);
    expect(workspace.assessments[0].counts.confirmed).toBe(2);
    expect(workspace.assessments[0].counts.needsEnvironment).toBe(1);
    expect(workspace.assessments[1].baselineLoaded).toBe(true);
    expect(workspace.relations).toHaveLength(1);
    expect(workspace.findings.every((finding: object) => !('raw' in finding))).toBe(true);
    const detail = await (await workspaceFetch(`${server.url}/api/findings/${encodeURIComponent(workspace.findings[0].key)}`)).json();
    expect(detail.raw.exploitation.steps).toHaveLength(2);
    expect(detail.raw.trace).toHaveLength(8);
    const result = await evidence(server, 'audit-fixture', 'sast/verified-findings.json:C-001');
    expect(result.status).toBe('available');
    expect(result.content.id).toBe('C-001');
    expect(await inventory(copied)).toEqual(before);
    expect(pair.ordinary.root).not.toBe(join(copied, 'ordinary run'));
  });

  it('ignores corrupt retired controls and accepts compatible legacy completed metadata', async () => {
    const current = await writeBundle(join(temporary, 'current'));
    await writeFile(join(current.root, 'run-manifest.json'), '{ broken old controls');
    await writeFile(join(current.root, 'task-ledger.json'), '{ broken old controls');
    const legacy = await writeBundle(join(temporary, 'legacy'), { runId: 'legacy-fixture', legacy: true });
    const imported = await importBundles([current.root, legacy.root]);
    expect(imported.workspace.assessments).toHaveLength(2);
    expect(imported.workspace.failures).toEqual([]);
  });

  it.each(['report/security-report.md', 'final-verification/findings.json'])('names missing required companion %s', async (companion) => {
    const bundle = await writeBundle(join(temporary, 'missing'));
    await unlink(join(bundle.root, companion));
    const imported = await importBundles([bundle.root]);
    expect(imported.workspace.assessments).toEqual([]);
    expect(imported.workspace.failures[0]?.message).toContain(companion);
  });

  it('rejects differing canonical findings including a legacy publication', async () => {
    const bundle = await writeBundle(join(temporary, 'mismatch'), { legacy: true });
    (bundle.final.findings as Array<{ title: string }>)[0]!.title = 'An earlier unaccepted title';
    await writeJson(bundle.root, 'final-verification/findings.json', bundle.final);
    const imported = await importBundles([bundle.root]);
    expect(imported.workspace.failures[0]?.code).toBe('invalid_authority');
  });

  it('rejects wrong final execution ownership and unsupported actions-only mode', async () => {
    const foreign = await writeBundle(join(temporary, 'foreign'));
    await writeJson(foreign.root, 'final-verification/findings.json', { ...foreign.final, run_id: 'another-execution' });
    const actions = await writeBundle(join(temporary, 'actions'), { kind: 'advantage', runId: 'actions-fixture', reportOverrides: { mode: 'actions' } });
    const imported = await importBundles([foreign.root, actions.root]);
    expect(imported.workspace.assessments).toHaveLength(0);
    expect(imported.workspace.failures.map((failure) => failure.code)).toEqual(expect.arrayContaining(['invalid_publication', 'unsupported']));
  });

  it('keeps a valid input beside invalid inputs and fails all-invalid startup', async () => {
    const valid = await writeBundle(join(temporary, 'valid'));
    const missing = join(temporary, 'absent');
    const server = await serve([valid.root, missing]);
    expect(server.workspace.assessments).toHaveLength(1);
    expect(server.workspace.failures).toHaveLength(1);
    await expect(createStakeServer({ runs: [missing] })).rejects.toBeInstanceOf(StartupError);
  });

  it('imports repeated canonical roots once and rejects distinct roots claiming one execution', async () => {
    const original = await writeBundle(join(temporary, 'one'));
    const repeated = await importBundles([original.root, join(original.root, '.')]);
    expect(repeated.workspace.assessments).toHaveLength(1);
    const copy = join(temporary, 'two');
    await cp(original.root, copy, { recursive: true });
    const conflicting = await importBundles([original.root, copy]);
    expect(conflicting.workspace.assessments).toHaveLength(0);
    expect(conflicting.workspace.failures).toHaveLength(2);
    expect(conflicting.workspace.failures.every((failure) => failure.code === 'execution_conflict')).toBe(true);
  });

  it('serves the captured publication even if its on-disk report is later removed', async () => {
    const finding = makeFinding();
    finding.exploitation!.steps[0]!.evidence_refs!.push('final-verification/findings.json#/findings/0');
    const bundle = await writeBundle(join(temporary, 'snapshot'), { findings: [finding] });
    const server = await serve([bundle.root]);
    await unlink(join(bundle.root, 'report/security-report.json'));
    const result = await evidence(server, 'audit-fixture', 'report/security-report.json');
    expect(result.status).toBe('available');
    expect(result.content.findings[0].title).toBe(bundle.findings[0]!.title);
    await unlink(join(bundle.root, 'final-verification/findings.json'));
    const selected = await evidence(server, 'audit-fixture', 'final-verification/findings.json#/findings/0');
    expect(selected.status).toBe('available');
    expect(selected.content.title).toBe(finding.title);
  });

  it('loads a report above 16 MiB and keeps long finding detail complete', async () => {
    const finding = makeFinding();
    finding.technical_examples![0]!.content = 'SYNTHETIC EXAMPLE\n' + 'detail '.repeat(1000);
    const bundle = await writeBundle(join(temporary, 'large'), { findings: [finding], reportOverrides: { hardening_notes: ['context '.repeat(2_200_000)] } });
    expect((await readFile(join(bundle.root, 'report/security-report.json'))).length).toBeGreaterThan(16 * 1024 * 1024);
    const server = await serve([bundle.root]);
    const result = await (await workspaceFetch(`${server.url}/api/findings?detail=1`)).json();
    expect(result.total).toBe(1);
    expect(result.items[0].raw.technical_examples[0].content).toBe(finding.technical_examples![0]!.content);
  });

  it('retains a contained observation on its recorded step without promoting the other step', async () => {
    const bundle = await writeBundle(join(temporary, 'mixed-observation'), { findings: [makeMixedObservationFinding()] });
    const imported = await importBundles([bundle.root]);
    const steps = imported.workspace.findings[0]!.raw.exploitation!.steps;
    expect(steps[0]!.evidence_status).toBe('observed_contained');
    expect(steps[0]!.observed_result).not.toBeNull();
    expect(steps[1]!.evidence_status).toBe('source_established');
    expect(steps[1]!.observed_result).toBeNull();
  });
});

describe('read-only API and reference ownership', () => {
  it('paginates and combines filters without truncating full detail', async () => {
    const pair = await writePair(temporary);
    const server = await serve([pair.ordinary.root, pair.advantage.root]);
    const page = await (await workspaceFetch(`${server.url}/api/findings?limit=1`)).json();
    expect(page.items).toHaveLength(1); expect(page.total).toBe(4);
    const filter = await (await workspaceFetch(`${server.url}/api/findings?assessment=audit-fixture&severity=medium&query=callback`)).json();
    expect(filter.total).toBe(1); expect(filter.items[0].id).toBe('F-002');
    expect((await workspaceFetch(`${server.url}/api/findings?limit=-1`)).status).toBe(400);
    expect((await workspaceFetch(`${server.url}/api/findings/not-a-finding`)).status).toBe(404);
  });

  it('resolves explicit cross-execution JSON pointers without substituting same-named local artifacts', async () => {
    const ordinary = await writeBundle(join(temporary, 'ordinary'));
    const inherited = { execution_id: 'audit-fixture', artifact_ref: 'sast/verified-findings.json#/0' };
    const finding = makeFinding({ id: 'F-060' });
    finding.exploitation!.steps[0]!.evidence_refs = [inherited];
    const advantage = await writeBundle(join(temporary, 'advantage'), { kind: 'advantage', runId: 'advantage-fixture', findings: [finding] });
    await writeJson(advantage.root, 'sast/verified-findings.json', [{ id: 'C-001', explanation: 'Different local support.' }]);
    const server = await serve([ordinary.root, advantage.root]);
    const result = await evidence(server, 'advantage-fixture', inherited);
    expect(result.executionId).toBe('audit-fixture');
    expect(result.content.explanation).toBe('Synthetic canonical support.');
  });

  it('keeps unavailable optional support local and source coordinates inert', async () => {
    const finding = makeFinding();
    finding.exploitation!.steps[0]!.evidence_refs!.push('campaign-planning/discovery.json#missing-question', 'Dockerfile:10', 'storefront/src/orders.ts:10-20,30-40');
    const bundle = await writeBundle(join(temporary, 'optional'), { findings: [finding] });
    const server = await serve([bundle.root]);
    expect((await evidence(server, 'audit-fixture', 'campaign-planning/discovery.json#missing-question')).status).toBe('unavailable');
    expect((await evidence(server, 'audit-fixture', 'storefront/src/orders.ts:42')).status).toBe('source');
    expect((await evidence(server, 'audit-fixture', 'Dockerfile:10')).status).toBe('source');
    expect((await evidence(server, 'audit-fixture', 'storefront/src/orders.ts:30-40')).status).toBe('source');
    expect((await evidence(server, 'audit-fixture', { artifact_ref: 'sast/verified-findings.json', source_id: 'C-001' })).status).toBe('available');
    expect(server.workspace.assessments[0]!.counts.confirmed).toBe(1);
  });

  it('uses one optional-artifact snapshot across record and pointer selectors', async () => {
    const finding = makeFinding();
    finding.exploitation!.steps[0]!.evidence_refs!.push('sast/verified-findings.json#/0');
    const bundle = await writeBundle(join(temporary, 'optional-snapshot'), { findings: [finding] });
    const server = await serve([bundle.root]);
    expect((await evidence(server, 'audit-fixture', 'sast/verified-findings.json:C-001')).content.explanation).toBe('Synthetic canonical support.');
    await writeJson(bundle.root, 'sast/verified-findings.json', [{ id: 'C-001', explanation: 'Changed after first read.' }]);
    expect((await evidence(server, 'audit-fixture', 'sast/verified-findings.json#/0')).content.explanation).toBe('Synthetic canonical support.');
  });

  it('rejects ambiguous record selectors and invalid JSON pointer escapes', async () => {
    const finding = makeFinding();
    finding.exploitation!.steps[0]!.evidence_refs!.push('sast/verified-findings.json#/bad~2escape');
    const bundle = await writeBundle(join(temporary, 'selectors'), { findings: [finding] });
    await writeJson(bundle.root, 'sast/verified-findings.json', [{ id: 'C-001' }, { id: 'C-001' }]);
    const server = await serve([bundle.root]);
    expect((await evidence(server, 'audit-fixture', 'sast/verified-findings.json:C-001')).status).toBe('unavailable');
    expect((await evidence(server, 'audit-fixture', 'sast/verified-findings.json#/bad~2escape')).status).toBe('unavailable');
  });

  it('requires registered references and rejects traversal, symlinks and raw diagnostic paths', async () => {
    const finding = makeFinding();
    const malicious = ['../outside.json', '/private/outside.json', 'sast/drafts/raw.json', 'report/context.json', 'sast/link.json'];
    finding.exploitation!.steps[0]!.evidence_refs!.push(...malicious);
    const bundle = await writeBundle(join(temporary, 'safe'), { findings: [finding] });
    await symlink(join(bundle.root, 'report/security-report.json'), join(bundle.root, 'sast/link.json'));
    const server = await serve([bundle.root]);
    for (const ref of malicious) expect((await evidence(server, 'audit-fixture', ref)).status).toBe('denied');
    expect((await lookup(server, 'audit-fixture', 'sast/not-registered.json')).response.status).toBe(404);
    expect((await workspaceFetch(`${server.url}/api/evidence/not-an-admitted-token`)).status).toBe(404);
  });

  it('rejects nonregular files without reading or blocking on them', async () => {
    const finding = makeFinding();
    finding.exploitation!.steps[0]!.evidence_refs!.push('sast/directory.json');
    const bundle = await writeBundle(join(temporary, 'nonregular'), { findings: [finding] });
    await mkdir(join(bundle.root, 'sast/directory.json'));
    const server = await serve([bundle.root]);
    expect((await evidence(server, 'audit-fixture', 'sast/directory.json')).status).toBe('denied');
  });

  it('does not disclose prohibited publication material in error output', async () => {
    const bundle = await writeBundle(join(temporary, 'prohibited'));
    await writeJson(bundle.root, 'report/security-report.json', { ...bundle.report, unsafe: { raw_output: 'SYNTHETIC_VALUE_MUST_NOT_ECHO' } });
    const imported = await importBundles([bundle.root]);
    expect(imported.workspace.assessments).toHaveLength(0);
    expect(JSON.stringify(imported.workspace.failures)).not.toContain('SYNTHETIC_VALUE_MUST_NOT_ECHO');
    expect(imported.workspace.failures[0]?.message).toContain('hygiene');
  });

  it('rejects foreign origins and hosts, exposes no mutations and sets offline content policy', async () => {
    const bundle = await writeBundle(join(temporary, 'origin'));
    const server = await serve([bundle.root]);
    const response = await workspaceFetch(`${server.url}/`);
    expect(response.status).toBe(200);
    expect(response.headers.get('content-security-policy')).toContain("connect-src 'self'");
    expect(response.headers.get('content-security-policy')).toContain("script-src 'self'");
    expect(response.headers.get('access-control-allow-origin')).toBeNull();
    expect((await workspaceFetch(`${server.url}/api/workspace`, { headers: { Origin: 'https://foreign.example' } })).status).toBe(403);
    expect((await workspaceFetch(`${server.url}/api/workspace`, { method: 'POST' })).status).toBe(405);
    const status = await new Promise<number>((resolveResponse, reject) => {
      const req = request(`${server.url}/api/workspace`, { headers: { Host: 'foreign.example' } }, (res) => { res.resume(); resolveResponse(res.statusCode!); });
      req.on('error', reject); req.end();
    });
    expect(status).toBe(403);
    expect((await workspaceFetch(`${server.url}/%2e%2e%2foutside.json`)).status).toBe(404);
  });
});

describe('CLI and startup prerequisites', () => {
  it('parses repeated roots, explicit port, spaces and no-open without shell interpolation', () => {
    expect(parseArgs(['serve', '--run', 'a space', '--run', 'literal$(value)', '--port', '4321', '--no-open'])).toEqual({ runs: ['a space', 'literal$(value)'], port: 4321, open: false });
    expect(() => parseArgs(['serve', '--port', 'invalid'])).toThrow('integer');
    expect(parseArgs(['serve'])).toEqual({ runs: [], open: true });
  });

  it('starts with invocation-relative paths and remains serving after browser opener failure', async () => {
    const bundle = await writeBundle(join(temporary, 'folder with spaces'));
    const messages: string[] = [];
    const instance = await runCli(['serve', '--run', 'folder with spaces'], { log: (text) => messages.push(text), warn: (text) => messages.push(text), options: { cwd: temporary }, opener: async () => { throw new Error('Unavailable opener'); } });
    servers.push(instance!);
    expect(instance!.workspace.assessments).toHaveLength(1);
    expect(messages.join('\n')).toContain(instance!.url);
    expect(messages.join('\n')).toContain('could not open automatically');
    expect((await workspaceFetch(`${instance!.url}/api/workspace`)).status).toBe(200);
    expect(bundle.root).toContain('folder with spaces');
  });

  it('reports occupied explicit ports without silently switching ports', async () => {
    const bundle = await writeBundle(join(temporary, 'port'));
    const server = await serve([bundle.root]);
    await expect(createStakeServer({ runs: [bundle.root], port: Number(new URL(server.url).port) })).rejects.toThrow('occupied');
  });

  it('preserves the invocation directory when npm changes into the package', async () => {
    await writeBundle(join(temporary, 'npm relative run'));
    vi.stubEnv('npm_lifecycle_event', 'start');
    vi.stubEnv('INIT_CWD', temporary);
    const opener = vi.fn(async () => {});
    const instance = await runCli(['serve', '--run', 'npm relative run', '--no-open'], { log: () => {}, opener });
    servers.push(instance!);
    expect(instance!.workspace.assessments).toHaveLength(1);
    expect(opener).not.toHaveBeenCalled();
  });

  it('reports missing Python and missing bridge prerequisites without installing anything', async () => {
    await expect(checkPrerequisites({ python: join(temporary, 'absent-python') })).rejects.toThrow('Python');
    await expect(checkPrerequisites({ bridgePath: join(temporary, 'absent-bridge.py') })).rejects.toThrow('bridge');
  });

  it('exits nonzero when all CLI inputs are unavailable', async () => {
    const result = await new Promise<{ code: number | null; output: string }>((resolveResult, reject) => {
      const child = spawn(process.execPath, ['--import', 'tsx', 'server/cli.ts', 'serve', '--run', join(temporary, 'missing'), '--no-open'], { cwd: process.cwd(), stdio: ['ignore', 'pipe', 'pipe'] });
      let output = '';
      child.stdout.on('data', (chunk) => { output += chunk; }); child.stderr.on('data', (chunk) => { output += chunk; });
      child.once('error', reject); child.once('exit', (code) => resolveResult({ code, output }));
    });
    expect(result.code).toBe(1); expect(result.output).toContain('No supplied publication');
  });
});
