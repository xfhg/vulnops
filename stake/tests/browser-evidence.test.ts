import { afterEach, describe, expect, it, vi } from 'vitest';
import { createHash } from 'node:crypto';
import { normalizeWorkspace, type EvidenceReference } from '../src/domain';
import { createBrowserEvidenceRegistry, type EvidenceBundle } from '../src/data/references-browser';
import { ArchiveError } from '../src/data/archive/types';
import { EvidenceRegistry } from '../server/references';
import { makeFinding, makePublication } from './fixtures/bundles';

afterEach(() => vi.unstubAllGlobals());
function fixture(references: EvidenceReference[] = []) {
  const finding = makeFinding();
  finding.exploitation!.steps[0]!.evidence_refs!.push(...references);
  const ordinary: EvidenceBundle = { ...makePublication({ findings: [finding] }), inputPath: 'wrapped/ordinary' };
  const advantage: EvidenceBundle = { ...makePublication({ runId: 'advantage-fixture', kind: 'advantage', findings: [makeFinding({ id: 'F-060' })] }), inputPath: 'wrapped/advantage' };
  return [ordinary, advantage];
}
function registry(bundles: EvidenceBundle[], files: Record<string, unknown> = {}, generation = 'generation-one') {
  const workspace = normalizeWorkspace(bundles);
  expect(workspace.failures).toEqual([]);
  const readText = vi.fn(async (root: string, path: string, _limit?: number) => {
    const key = `${root}/${path}`;
    if (!Object.hasOwn(files, key)) throw new ArchiveError('missing_file', 'Referenced artifact was not delivered.');
    const value = files[key];
    if (value instanceof Error) throw value;
    return typeof value === 'string' ? value : JSON.stringify(value);
  });
  const reader = createBrowserEvidenceRegistry(bundles, workspace, generation, readText);
  async function read(reference: unknown, owner = 'audit-fixture') {
    const entry = reader.find(owner, reference);
    expect(entry, 'fixture reference must be explicitly registered').toBeDefined();
    return (await reader.read(entry!.token))!;
  }
  return { workspace, reader, read, readText };
}

describe('browser evidence registry', () => {
  it('keeps core publication snapshots complete and preserves the server registry interface and tokens', async () => {
    const bundles = fixture(['final-verification/findings.json#/findings/0']);
    const { reader, read, readText, workspace } = registry(bundles);
    expect((await read('report/security-report.json')).content).toEqual(bundles[0]!.report);
    expect((await read('report/security-report.md')).content).toBe(bundles[0]!.markdown);
    expect((await read('final-verification/findings.json#/findings/0')).content).toEqual((bundles[0]!.report.findings as unknown[])[0]);
    expect(readText).not.toHaveBeenCalled();
    const server = new EvidenceRegistry(bundles, workspace, {}, 'generation-one');
    const entry = server.find('audit-fixture', 'report/security-report.json')!;
    expect(entry.token).toBe(createHash('sha256').update(JSON.stringify(['generation-one', 'audit-fixture', 'report/security-report.json'])).digest('base64url'));
    expect(await server.read(entry.token)).toEqual({ ...entry, status: 'available', content: bundles[0]!.report, format: 'json' });
    expect(await server.read(server.find('audit-fixture', 'final-verification/findings.json#/findings/0')!.token)).toMatchObject({ status: 'available', content: (bundles[0]!.report.findings as unknown[])[0] });
    expect(reader.find('audit-fixture', 'report/security-report.json')!.token).not.toBe(entry.token);
  });

  it('resolves inherited references only in the recorded execution and never the similarly named local file', async () => {
    const inherited = { execution_id: 'audit-fixture', artifact_ref: 'sast/verified-findings.json#/0', record_id: 'ignored-metadata' };
    const absent = { execution_id: 'absent-baseline', artifact_ref: 'sast/verified-findings.json#/0' };
    const bundles = fixture();
    (bundles[1]!.report.findings as ReturnType<typeof makeFinding>[])[0]!.exploitation!.steps[0]!.evidence_refs!.push(inherited, absent);
    bundles[1]!.final!.findings = structuredClone(bundles[1]!.report.findings);
    const { read, readText } = registry(bundles, {
      'wrapped/ordinary/sast/verified-findings.json': [{ id: 'C-001', owner: 'ordinary' }],
      'wrapped/advantage/sast/verified-findings.json': [{ id: 'C-001', owner: 'advantage' }],
    });
    expect(await read(inherited, 'advantage-fixture')).toMatchObject({ status: 'available', executionId: 'audit-fixture', content: { owner: 'ordinary' } });
    expect(await read('sast/verified-findings.json:C-001', 'advantage-fixture')).toMatchObject({ status: 'available', executionId: 'advantage-fixture', content: { owner: 'advantage' } });
    expect(await read(absent, 'advantage-fixture')).toMatchObject({ status: 'unavailable', executionId: 'absent-baseline' });
    expect(readText).toHaveBeenCalledTimes(2);
  });

  it('registers historical wrapper references under their original owner even without that bundle', async () => {
    const bundles = fixture();
    const historical = makeFinding({ id: 'H-001' });
    historical.exploitation!.steps[0]!.evidence_refs!.push('sast/historical-only.json:H-1');
    bundles[1]!.report.historical_findings = [{ execution_id: 'audit-fixture', finding: historical, disposition: 'historical' }];
    const { reader, read, readText } = registry([bundles[1]!]);
    expect(reader.find('advantage-fixture', 'sast/historical-only.json:H-1')).toBeUndefined();
    expect(await read('sast/historical-only.json:H-1')).toMatchObject({ status: 'unavailable', executionId: 'audit-fixture' });
    expect(readText).not.toHaveBeenCalled();
  });

  it('shares one optional snapshot across exact selectors and admits nested references only after reading their owner', async () => {
    const bundles = fixture(['sast/verified-findings.json#/0']);
    const files = { 'wrapped/ordinary/sast/verified-findings.json': [{ id: 'C-001', evidence_refs: ['sast/support.json#support'] }] };
    const { reader, read, readText } = registry(bundles, files);
    expect(reader.find('audit-fixture', 'sast/support.json#support')).toBeUndefined();
    const [first, second] = await Promise.all([read('sast/verified-findings.json:C-001'), read('sast/verified-findings.json#/0')]);
    expect(first.content).toEqual(second.content);
    expect(reader.find('audit-fixture', 'sast/support.json#support')).toBeDefined();
    expect(await read({ artifact_ref: 'sast/verified-findings.json', source_id: 'C-001', record_id: 'C-001' })).toMatchObject({ content: files['wrapped/ordinary/sast/verified-findings.json'] });
    expect(readText).toHaveBeenCalledExactlyOnceWith('wrapped/ordinary', 'sast/verified-findings.json', 16 * 1024 * 1024);
  });

  it('keeps source coordinates inert, rejects unsafe references, and never fetches or resolves unregistered paths', async () => {
    const denied = ['../sast/secret.json', '/sast/secret.json', 'sast/../secret.json', 'sast\\secret.json', 'https://example.invalid/evidence.json', 'sast/raw/result.json', 'runtime/log.txt', 'sast/context.json', 'sast/executable.py', 'recovery-archives/log.json'];
    const bundles = fixture(['Dockerfile:10', 'storefront/src/orders.ts:10-20,30-40', ...denied]);
    const network = vi.fn(() => { throw new Error('Evidence must not fetch.'); });
    vi.stubGlobal('fetch', network);
    const { reader, read, readText } = registry(bundles);
    for (const ref of ['Dockerfile:10', 'storefront/src/orders.ts:42', 'storefront/src/orders.ts:10-20', 'storefront/src/orders.ts:30-40']) expect(await read(ref)).toMatchObject({ status: 'source', kind: 'source' });
    for (const ref of denied) expect(await read(ref)).toMatchObject({ status: 'denied', kind: 'denied' });
    expect(reader.find('audit-fixture', 'sast/unregistered.json')).toBeUndefined();
    expect(await reader.read('unregistered-token')).toBeUndefined();
    expect(readText).not.toHaveBeenCalled();
    expect(network).not.toHaveBeenCalled();
  });

  it('contains malformed, foreign-owned, unsafe, missing and unsupported optional evidence failures', async () => {
    const references = ['sast/foreign.json', 'sast/malformed.json', 'sast/unsafe.json', 'sast/missing.json', 'sast/unknown.json', 'sast/notes.txt', 'sast/notes.txt:entry', 'sast/ambiguous.json:C-1', 'sast/valid.json#/missing', 'sast/receipt.json'];
    const bundles = fixture(references);
    const { read, workspace, readText } = registry(bundles, {
      'wrapped/ordinary/sast/foreign.json': { run_id: 'advantage-fixture', id: 'foreign' },
      'wrapped/ordinary/sast/malformed.json': '{ synthetic invalid JSON',
      'wrapped/ordinary/sast/unsafe.json': { proof_token: 'SYNTHETIC_UNPUBLISHABLE_VALUE' },
      'wrapped/ordinary/sast/unknown.json': new Error('UNSAFE_ERROR_DETAILS'),
      'wrapped/ordinary/sast/notes.txt': 'Inert, recorded support.',
      'wrapped/ordinary/sast/ambiguous.json': [{ id: 'C-1' }, { id: 'C-1' }],
      'wrapped/ordinary/sast/valid.json': { id: 'valid' },
      'wrapped/ordinary/sast/receipt.json': { payload: 'x'.repeat(64 * 1024) },
    });
    for (const reference of references.slice(0, 3)) expect(await read(reference)).toMatchObject({ status: 'denied' });
    for (const reference of ['sast/missing.json', 'sast/unknown.json', 'sast/notes.txt:entry', 'sast/ambiguous.json:C-1', 'sast/valid.json#/missing']) expect(await read(reference)).toMatchObject({ status: 'unavailable' });
    expect(await read('sast/notes.txt')).toMatchObject({ status: 'available', format: 'text', content: 'Inert, recorded support.' });
    expect(await read('sast/receipt.json')).toMatchObject({ status: 'denied' });
    expect(readText).toHaveBeenCalledWith('wrapped/ordinary', 'sast/receipt.json', 64 * 1024);
    expect(JSON.stringify(await read('sast/unknown.json'))).not.toContain('UNSAFE_ERROR_DETAILS');
    expect(JSON.stringify(await read('sast/unsafe.json'))).not.toContain('SYNTHETIC_UNPUBLISHABLE_VALUE');
    expect((await read('report/security-report.json')).status).toBe('available');
    expect(workspace.assessments).toHaveLength(2);
  });

  it('keeps references opaque and stale handles unavailable after workspace replacement', async () => {
    const bundles = fixture();
    const old = registry(bundles, {}, 'generation-one');
    const next = registry(bundles, {}, 'generation-two');
    const oldEntry = old.reader.find('audit-fixture', 'report/security-report.json')!;
    const nextEntry = next.reader.find('audit-fixture', 'report/security-report.json')!;
    expect(oldEntry.token).not.toBe(nextEntry.token);
    expect(oldEntry.token).not.toContain('audit-fixture');
    expect(await next.reader.read(oldEntry.token)).toBeUndefined();
    expect(old.reader.find('audit-fixture', 'report/security-report.json')).toBe(oldEntry);
  });
});
