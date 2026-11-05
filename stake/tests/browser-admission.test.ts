import { afterEach, describe, expect, it } from 'vitest';
import { execFileSync } from 'node:child_process';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { importBundles } from '../server/admission';
import { artifactSizeLimit, parseArtifactJson, validatePublicationContent } from '../src/data/archive/hygiene';
import { validatePublicationMetadata } from '../src/data/archive/admission';
import { openArchiveInProcess } from '../src/data/archive/reader';
import { makeFinding } from './fixtures/bundles';
import { pairEntries, publicationEntries, zipFixture, type ZipFixtureEntry } from './browser-archive-fixtures';

const temporary: string[] = [];
afterEach(async () => { await Promise.all(temporary.splice(0).map(path => rm(path, { recursive: true, force: true }))); });
function edit(entries: ZipFixtureEntry[], suffix: string, update: (value: any) => void, root = 'renamed-a') {
  const entry = entries.find(item => item.name === `${root}/${suffix}`)!;
  const value = JSON.parse(entry.text!); update(value); entry.text = JSON.stringify(value);
}
async function native(entries: ZipFixtureEntry[]) {
  const parent = await mkdtemp(join(tmpdir(), 'stake-browser-parity-')); temporary.push(parent);
  for (const entry of entries) {
    const path = join(parent, entry.name); await mkdir(dirname(path), { recursive: true });
    await writeFile(path, entry.text ?? entry.bytes ?? '');
  }
  return importBundles([join(parent, 'renamed-a'), join(parent, 'renamed-b')]);
}
async function agree(entries: ZipFixtureEntry[], expected: boolean) {
  const existing = await native(entries);
  const admitted = existing.workspace.assessments.length === 2 && existing.workspace.failures.length === 0;
  expect(admitted).toBe(expected);
  if (!expected) { await expect(openArchiveInProcess(zipFixture(entries))).rejects.toBeDefined(); return; }
  const browser = await openArchiveInProcess(zipFixture(entries));
  expect(browser.bundles.map(bundle => bundle.run_id)).toEqual(existing.bundles.map(bundle => bundle.run_id));
  for (let index = 0; index < browser.bundles.length; index++) {
    expect(browser.bundles[index].report).toEqual(existing.bundles[index].report);
    expect(browser.bundles[index].final).toEqual(existing.bundles[index].final);
    expect(browser.bundles[index].markdown).toEqual(existing.bundles[index].markdown);
  }
  expect(browser.workspace.findings.map(item => ({ key: item.key, verdict: item.verdict, severity: item.severity, origin: item.origin, raw: item.raw })))
    .toEqual(existing.workspace.findings.map(item => ({ key: item.key, verdict: item.verdict, severity: item.severity, origin: item.origin, raw: item.raw })));
  browser.dispose();
}

describe('portable admission matches existing read_publication(validate_evidence=False)', () => {
  it('admits minimal current publications without reviewer files, source or retired controls', async () => {
    const entries = [...pairEntries(), { name: 'renamed-a/run-manifest.json', text: 'retired invalid JSON' }, { name: 'renamed-b/advantage-manifest.json', text: 'retired invalid JSON' }];
    edit(entries, 'report/security-report.json', report => { report.publication.markdown_sha256 = '0'.repeat(64); report.publication.retained_evidence = { ref: 'report/publication-receipt.json', sha256: '0'.repeat(64) }; });
    await agree(entries, true);
  });
  it('admits compatible completed legacy identities and absent optional run IDs', async () => {
    const entries = [...publicationEntries('renamed-a', { legacy: true }), ...publicationEntries('renamed-b', { legacy: true, kind: 'advantage', runId: 'advantage-fixture' })];
    edit(entries, 'report/security-report.json', report => { delete report.run_id; report.counts = report.summary; delete report.summary; });
    edit(entries, 'final-verification/findings.json', final => { delete final.run_id; });
    await agree(entries, true);
  });
  it('preserves nullable service names, observations, source variants, severity alias and extension fields', async () => {
    const finding = makeFinding({ severity: 'informational' });
    finding.affected_components![0].service!.name = null;
    const location = finding.root_causes![0]; delete location.line; location.start_line = 10; location.end_line = 15;
    finding.extension = { arbitrary: ['retained', null] };
    const entries = [...publicationEntries('renamed-a', { findings: [finding] }), ...publicationEntries('renamed-b', { kind: 'advantage', runId: 'advantage-fixture' })];
    await agree(entries, true);
  });
  it('keeps rich unconfirmed and historical dossiers with original owners and missing baseline diagnostics', async () => {
    const entries = pairEntries();
    edit(entries, 'report/security-report.json', report => {
      report.publication.source.source_run_id = 'not-delivered'; report.baseline.execution_id = 'not-delivered';
      const finding = makeFinding({ id: 'F-002', verdict: 'needs_environment' }); delete finding.verdict;
      report.unconfirmed_dossiers = [finding];
      report.historical_findings = [{ execution_id: 'audit-fixture', finding: makeFinding(), disposition: 'historical' }];
    }, 'renamed-b');
    await agree(entries, true);
  });
  it.each([
    'missing markdown', 'missing final', 'final mismatch', 'final owner', 'report owner', 'schema', 'bad metadata', 'null metadata', 'empty summary', 'invalid service', 'actions', 'same role', 'duplicate execution',
  ])('rejects %s in both readers without partially activating a pair', async kind => {
    let entries = pairEntries();
    if (kind === 'missing markdown') entries = entries.filter(entry => entry.name !== 'renamed-a/report/security-report.md');
    else if (kind === 'missing final') entries = entries.filter(entry => entry.name !== 'renamed-a/final-verification/findings.json');
    else if (kind === 'final mismatch') edit(entries, 'final-verification/findings.json', final => { final.findings = []; });
    else if (kind === 'final owner') edit(entries, 'final-verification/findings.json', final => { final.run_id = 'wrong-owner'; });
    else if (kind === 'report owner') edit(entries, 'report/security-report.json', report => { report.execution_kind = 'advantage'; });
    else if (kind === 'schema') edit(entries, 'report/security-report.json', report => { report.schema_version = '3.0'; });
    else if (kind === 'bad metadata') edit(entries, 'report/security-report.json', report => { report.publication.producer_routes = []; });
    else if (kind === 'null metadata') edit(entries, 'report/security-report.json', report => { report.publication = null; });
    else if (kind === 'empty summary') edit(entries, 'report/security-report.json', report => { report.summary = null; });
    else if (kind === 'invalid service') {
      for (const path of ['report/security-report.json', 'final-verification/findings.json']) edit(entries, path, value => { value.findings[0].affected_components[0].service.name = {}; });
    } else if (kind === 'actions') edit(entries, 'report/security-report.json', report => { report.mode = 'actions'; }, 'renamed-b');
    else if (kind === 'same role') entries = [...publicationEntries('renamed-a'), ...publicationEntries('renamed-b', { runId: 'second-audit' })];
    else if (kind === 'duplicate execution') entries = [...publicationEntries('renamed-a'), ...publicationEntries('renamed-b', { runId: 'audit-fixture', kind: 'advantage' })];
    // Generic CLI supports multiple ordinary reports; the browser adds exact-pair role admission.
    if (kind === 'same role') { await expect(openArchiveInProcess(zipFixture(entries))).rejects.toMatchObject({ code: 'invalid_roles' }); return; }
    await agree(entries, false);
  });
  it.each(['incomplete', 'mismatched', 'ambiguous'])('rejects %s legacy identity', async state => {
    const entries = [...publicationEntries('renamed-a', { legacy: true }), ...publicationEntries('renamed-b', { legacy: true, kind: 'advantage', runId: 'advantage-fixture' })];
    if (state === 'ambiguous') entries.push({ name: 'renamed-a/advantage-manifest.json', text: '{}' });
    else edit(entries, 'run-manifest.json', manifest => { if (state === 'incomplete') manifest.status = 'incomplete'; else manifest.run_id = 'wrong'; });
    await agree(entries, false);
  });
  it('rejects actions-only legacy metadata even when the report omits mode', async () => {
    const entries = [...publicationEntries('renamed-a'), ...publicationEntries('renamed-b', { legacy: true, kind: 'advantage', runId: 'advantage-fixture' })];
    edit(entries, 'report/security-report.json', report => { delete report.mode; }, 'renamed-b');
    edit(entries, 'advantage-manifest.json', manifest => { manifest.mode = 'actions'; }, 'renamed-b');
    await agree(entries, false);
  });
  it('admits a complete report above 16 MiB without widening final-artifact limits', async () => {
    const entries = pairEntries();
    edit(entries, 'report/security-report.json', report => { report.extended_narrative = 'x'.repeat(17 * 1024 * 1024); });
    entries.find(entry => entry.name === 'renamed-a/report/security-report.md')!.text = '# Complete large report\n' + 'x'.repeat(17 * 1024 * 1024);
    await agree(entries, true);
    edit(entries, 'final-verification/findings.json', final => { final.extended_narrative = 'x'.repeat(17 * 1024 * 1024); });
    await agree(entries, false);
  });
});

describe('portable publication hygiene and metadata contract', () => {
  it('matches Python artifact-specific limits and hygiene outcomes', () => {
    const paths = ['report/security-report.json', 'report/security-report.md', 'report/summary.json', 'campaign-planning/discovery.json', 'sast/task-receipt.json', 'context.json', 'sast/results.json'];
    const values: unknown[] = [{ safe: '<redacted>' }, { stdout: '' }, { nested: { proof_token: '<redacted>' } },
      { text: 'authorization: Bearer <redacted>' }, { text: 'authorization: Bearer FAKE_TEST_MATERIAL' }, { text: `ghp_${'a'.repeat(20)}` },
      { text: `AKIA${'A'.repeat(16)}` }, { text: `sk-${'a'.repeat(20)}` }, { text: '-----BEGIN RSA PRIVATE KEY-----' },
      { 'raw_scanner_output': null }, { extension: [null, 42, 'a:b,c', 'λ'] }];
    const script = 'import json,sys\nfrom pathlib import Path\nsys.path.insert(0,"scripts")\nfrom artifact_policy import artifact_size_limit,publication_content_error\nx=json.load(sys.stdin)\nprint(json.dumps({"limits":[artifact_size_limit(Path(p)) for p in x["paths"]],"allowed":[publication_content_error(v) is None for v in x["values"]]}))';
    const python = JSON.parse(execFileSync('python3', ['-B', '-c', script], { cwd: resolve('..'), input: JSON.stringify({ paths, values }), encoding: 'utf8', env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' } }));
    expect(paths.map(artifactSizeLimit)).toEqual(python.limits);
    expect(values.map(value => { try { validatePublicationContent(value); return true; } catch { return false; } })).toEqual(python.allowed);
  });
  it('denies malformed/deep/nonfinite text and does not expose rejected values', () => {
    for (const text of ['{"number":1e400}', '{"number":NaN}', '['.repeat(65) + '0' + ']'.repeat(65)])
      expect(() => parseArtifactJson(text, 'sast/result.json')).toThrow();
    const rejected = 'FAKE_REJECTED_BODY';
    try { parseArtifactJson(JSON.stringify({ stdout: rejected }), 'report/security-report.json'); throw new Error('not rejected'); }
    catch (error) { expect(String(error)).not.toContain(rejected); }
    expect(() => validatePublicationContent({ safe: 'x'.repeat(64 * 1024) }, artifactSizeLimit('task-receipt.json'))).toThrow();
  });
  it('matches the current publication metadata schema for optional fields and rejects added properties', () => {
    const base = { execution_kind: 'audit', repository: 'test', repositories: [], model_routing: {}, producer_routes: {} };
    const variants: unknown[] = [base, { ...base, source: { source_run_id: '', finding_source: null }, action_source: null, patch_binding: null },
      { ...base, target_fingerprint: 'a'.repeat(64), markdown_sha256: 'b'.repeat(64), published_at: 'date', publication_method: 'retained_evidence', retained_evidence: { ref: 'report/publication-receipt.json', sha256: '0'.repeat(64) }, gap_exploration: { ref: 'gap-exploration/results.json', sha256: '1'.repeat(64) } },
      { ...base, surprise: true }, { ...base, source: { extra: true } }, { ...base, repositories: [null] }, { ...base, producer_routes: { phase: [] } }, { ...base, target_fingerprint: 'A'.repeat(64) }];
    const script = 'import json,sys\nsys.path.insert(0,"scripts")\nfrom dossier_contract import validate_publication_schema\nresults=[]\nfor item in json.load(sys.stdin):\n try:\n  validate_publication_schema(item,"publication-metadata.schema.json");results.append(True)\n except Exception:\n  results.append(False)\nprint(json.dumps(results))';
    const expected = JSON.parse(execFileSync('python3', ['-B', '-c', script], { cwd: resolve('..'), input: JSON.stringify(variants), encoding: 'utf8', env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' } }));
    expect(variants.map(value => { try { validatePublicationMetadata(value); return true; } catch { return false; } })).toEqual(expected);
  });
});
