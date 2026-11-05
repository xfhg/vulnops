import { describe, expect, it, vi } from 'vitest';
import { matchesBrowserDestination } from '../src/app/browser-destination';
import { buildCodeIndex, normalizeWorkspace, summarizeWorkspace } from '../src/domain';
import type { WorkspaceDataSource } from '../src/data/types';
import { groupCodeLocations } from '../src/features/code-map/projection';
import { buildRepairEntries, projectRepair } from '../src/features/remediation/model';
import { projectFinding } from '../src/features/attack-explorer/projection';
import { connectedRecords } from '../src/features/attack-explorer/relationships';
import { buildCompositionOverview, buildEntrypointIndex, overviewChainId } from '../src/features/entrypoint-explorer/model';
import { makePublication } from './fixtures/bundles';

function fixture() {
  const all = normalizeWorkspace([makePublication(), makePublication({ kind: 'advantage', runId: 'advantage-fixture' })]);
  const workspace = { ...summarizeWorkspace(all), generation: 'generation-one' };
  const source: WorkspaceDataSource = { finding: vi.fn(async key => all.findings.find(item => item.key === key)!),
    page: vi.fn(async (offset, limit) => ({ items: all.findings.slice(offset, offset + limit), total: all.findings.length })),
    reference: vi.fn(), evidence: vi.fn() };
  return { all, workspace, source, match: (params: Record<string, string>, signal?: AbortSignal) => matchesBrowserDestination(new URLSearchParams(params), workspace, source, signal) };
}

describe('exact pending browser destinations', () => {
  it('retains run-qualified pages and exact finding IDs; never substitutes a repeated local ID or unknown owner', async () => {
    const { all, match } = fixture();
    expect(await match({ view: 'assessment', run: 'audit-fixture' })).toBe(true);
    expect(await match({ view: 'findings', finding: all.findings[0].key })).toBe(true);
    expect(await match({ view: 'findings', finding: 'F-001' })).toBe(false);
    expect(await match({ view: 'findings', finding: all.findings[0].key, run: 'advantage-fixture' })).toBe(false);
    expect(await match({ view: 'assessment', run: 'not-loaded' })).toBe(false);
    expect(await match({ view: 'not-a-view', run: 'audit-fixture' })).toBe(false);
  });
  it('requires the exact code-map file and current repository/scope identity', async () => {
    const { all, match } = fixture();
    const file = groupCodeLocations(buildCodeIndex(all.findings))[0];
    expect(await match({ view: 'code', location: file.key })).toBe(true);
    expect(await match({ view: 'code', location: JSON.stringify([file.runId, 'wrong-scope', file.sourceView, file.file]) })).toBe(false);
    expect(await match({ view: 'code', location: file.key, repo: 'not-delivered' })).toBe(false);
    expect(await match({ view: 'code', location: file.key, run: file.runId === 'audit-fixture' ? 'advantage-fixture' : 'audit-fixture' })).toBe(false);
  });
  it('resumes a repair map node or edge only within its qualified action', async () => {
    const { all, match } = fixture();
    const entries = buildRepairEntries(all.findings), [first, second] = entries;
    const graph = projectRepair(first);
    for (const selection of [graph.nodes.find(node => node.kind === 'location')!.id, graph.edges[0].id])
      expect(await match({ view: 'remediation', repairView: 'map', repairAction: first.key, repairSelected: selection })).toBe(true);
    expect(await match({ view: 'remediation', repairAction: second.key, repairSelected: graph.nodes[0].id })).toBe(false);
    expect(await match({ view: 'remediation', repairAction: 'action-1' })).toBe(false);
    expect(await match({ view: 'remediation', repairSelected: graph.nodes[0].id })).toBe(false);
    expect(await match({ view: 'remediation', repairView: 'invalid', repairAction: first.key })).toBe(false);
  });
  it('checks finding instruction ranges, record types, panel visibility and repair return context', async () => {
    const { all, match } = fixture();
    const finding = all.findings[0], entry = buildRepairEntries([finding])[0];
    const base = { view: 'remediation', finding: finding.key, panel: 'repair', repair: 'action-1', repairAction: entry.key, repairView: 'map' };
    expect(await match({ ...base, detailRecord: JSON.stringify(['repair-location', 'action-1', 0]) })).toBe(true);
    expect(await match({ ...base, detailRecord: JSON.stringify(['repair-location', 'action-1', 1]) })).toBe(false);
    expect(await match({ ...base, detailRecord: JSON.stringify(['repair-location', 'foreign-action', 0]) })).toBe(false);
    expect(await match({ ...base, panel: 'verify', detailRecord: JSON.stringify(['check', 'check-1']) })).toBe(true);
    expect(await match({ ...base, panel: 'repair', detailRecord: JSON.stringify(['check', 'check-1']) })).toBe(false);
    expect(await match({ ...base, panel: 'reproduce', detailRecord: JSON.stringify(['step', 'step-1']) })).toBe(true);
    expect(await match({ ...base, panel: 'reproduce', detailRecord: JSON.stringify(['example', 'example-1']) })).toBe(true);
    const other = buildRepairEntries([all.findings[1]])[0];
    expect(await match({ ...base, repairAction: other.key })).toBe(false);
  });
  it('validates procedure/composition and connected record selections by projection membership', async () => {
    const { all, match } = fixture();
    const finding = all.findings[0], procedure = projectFinding(finding, 'procedure'), graph = projectFinding(finding, 'composition');
    const connected = connectedRecords(finding, 'procedure', procedure, procedure.nodes[0].id);
    for (const selected of [procedure.nodes[0].id, procedure.edges[0].id, connected.nodes[0].id, connected.edges[0].id])
      expect(await match({ view: 'findings', finding: finding.key, mode: 'procedure', selected })).toBe(true);
    expect(await match({ view: 'findings', finding: finding.key, mode: 'composition', selected: graph.nodes[0].id })).toBe(true);
    expect(await match({ view: 'findings', finding: finding.key, mode: 'composition', selected: procedure.nodes[0].id })).toBe(false);
    expect(await match({ view: 'findings', finding: all.findings[1].key, mode: 'composition', selected: graph.nodes[0].id })).toBe(false);
  });
  it('validates global composition chains, primitives and transitions without guessing from owner ID alone', async () => {
    const { all, match } = fixture(), graph = buildCompositionOverview(all.findings);
    for (const selected of [overviewChainId(graph.chains[0].finding.key), graph.nodes[0].id, graph.edges[0].id])
      expect(await match({ view: 'attacks', entryMode: 'composed', entrySelected: selected })).toBe(true);
    expect(await match({ view: 'attacks', entryMode: 'composed', entrySelected: JSON.stringify(['entity', all.findings[0].key, 'composition', 'missing']) })).toBe(false);
    expect(await match({ view: 'attacks', entryMode: 'composed', entrySelected: graph.nodes[0].id, run: graph.nodes[0].finding.runId === 'audit-fixture' ? 'advantage-fixture' : 'audit-fixture' })).toBe(false);
  });
  it('resumes exact recorded entrypoints and association edges', async () => {
    const { all, match } = fixture(), index = buildEntrypointIndex(all.findings);
    expect(await match({ view: 'attacks', entrySelected: index.clusters[0].id })).toBe(true);
    expect(await match({ view: 'attacks', entrySelected: index.associations[0].id })).toBe(true);
    expect(await match({ view: 'attacks', entrySelected: 'POST /orders/approve' })).toBe(false);
    expect(await match({ view: 'attacks', entryMode: 'composed', entrySelected: index.clusters[0].id })).toBe(false);
  });
  it('does not retain orphan child selectors or routes with no report-bound destination', async () => {
    const { match } = fixture();
    expect(await match({ view: 'overview' })).toBe(false);
    expect(await match({ view: 'code', run: 'audit-fixture', selected: 'stale-node' })).toBe(false);
    expect(await match({ view: 'remediation', run: 'audit-fixture', detailRecord: 'orphan' })).toBe(false);
  });
  it('rejects incomplete page results and aborted generation work', async () => {
    const { all, source, match } = fixture();
    const file = groupCodeLocations(buildCodeIndex(all.findings))[0];
    vi.mocked(source.page).mockResolvedValue({ items: [], total: 2 });
    expect(await match({ view: 'code', location: file.key })).toBe(false);
    const controller = new AbortController(); controller.abort();
    expect(await match({ view: 'findings', finding: all.findings[0].key }, controller.signal)).toBe(false);
  });
});
