import { describe, expect, it } from 'vitest';
import { localEntityKey, normalizeWorkspace, type FindingRecord, type RawFinding } from '../src/domain';
import { buildCompositionOverview, buildEntrypointIndex, chainForSelection, compareFindings, compositionCounts, normalizeEntrypoint, overviewChainId, type CompositionSort, type EntrypointSort } from '../src/features/entrypoint-explorer/model';
import { makeFinding, makePublication } from './fixtures/bundles';
import { EvidenceRegistry } from '../server/references';

function finding(id: string, raw: Partial<RawFinding> = {}, metadata: Partial<FindingRecord> = {}): FindingRecord {
  const record = normalizeWorkspace([makePublication({ findings: [makeFinding({ id, ...raw })] })]).findings[0];
  return { ...record, ...metadata };
}
function component(entrypoints: string[], repository: string | undefined = 'storefront') {
  return { id: 'component-1', name: 'Storefront', repository, entrypoints, evidence_refs: ['storefront/src/orders.ts:42'] };
}

describe('scope-bound recorded entrypoint associations', () => {
  it('groups exact entrypoints, normalizes only outer whitespace, and preserves original citations', () => {
    const first = finding('F-A', { affected_components: [component([' POST /orders/approve '])] });
    const second = finding('F-B', { affected_components: [component(['POST /orders/approve'])] });
    const before = structuredClone([first, second]);
    const index = buildEntrypointIndex([first, second]);
    expect(index.clusters).toHaveLength(1);
    expect(index.clusters[0].findingKeys).toEqual([first.key, second.key]);
    expect(index.clusters[0].citations.map(citation => citation.recordedLabel)).toEqual([' POST /orders/approve ', 'POST /orders/approve']);
    expect(index.associations).toHaveLength(2);
    expect([first, second]).toEqual(before);
  });

  it('does not fuzzy-merge method, case, slash, parameter or internal whitespace variants', () => {
    const labels = ['POST /orders/approve', 'GET /orders/approve', 'post /orders/approve', 'POST /orders/approve/', 'POST /orders/:id', 'POST /orders/{id}', 'POST  /orders/approve'];
    const index = buildEntrypointIndex([finding('F-A', { affected_components: [component(labels)] })]);
    expect(index.clusters).toHaveLength(labels.length);
    expect(new Set(index.clusters.map(cluster => cluster.label))).toEqual(new Set(labels));
    expect(normalizeEntrypoint(' \tPOST /orders\n')).toBe('POST /orders');
  });

  it('preserves exact component source ranges as registered navigable references', () => {
    const originalReference = { execution_id: 'audit-fixture', artifact_ref: 'sast/verified-findings.json', record_id: 'C-001' };
    const workspace = normalizeWorkspace([makePublication({ findings: [makeFinding({ affected_components: [{
      ...component(['POST /orders/approve']), evidence_refs: [originalReference], locations: [
        { file: 'storefront/single.ts', line: 12 },
        { file: 'storefront/range.ts', line: 20, end_line: 25 },
        { file: 'storefront/legacy.ts', start_line: 30, end_line: 35 },
        { file: 'storefront/legacy-single.ts', start_line: 40 },
        { file: 'storefront/equal-range.ts', start_line: 50, end_line: 50 },
        { file: 'storefront/precedence.ts', line: 60, start_line: 59, end_line: 65 },
        { file: 'storefront/file-only.ts' },
        { file: 'storefront/end-only.ts', end_line: 75 },
      ],
    }] })] })]);
    const before = structuredClone(workspace.findings);
    const record = workspace.findings[0];
    const references = buildEntrypointIndex(workspace.findings).clusters[0].citations[0].evidence;
    expect(references).toEqual([originalReference, 'storefront/single.ts:12', 'storefront/range.ts:20-25',
      'storefront/legacy.ts:30-35', 'storefront/legacy-single.ts:40', 'storefront/equal-range.ts:50',
      'storefront/precedence.ts:60-65', 'storefront/file-only.ts', 'storefront/end-only.ts']);
    const registry = new EvidenceRegistry([], workspace);
    for (const reference of references.slice(1)) expect(registry.find(record.runId, reference as string)).toMatchObject({
      kind: 'source', executionId: record.runId, reference,
    });
    expect(workspace.findings).toEqual(before);
  });

  it('keeps execution, assessment, source view and repository boundaries separate', () => {
    const records = [finding('F-A'), finding('F-B', {}, { runId: 'other-run' }), finding('F-C', {}, { scopeId: 'other-scope' }),
      finding('F-D', {}, { sourceView: 'derived' }), finding('F-E', { affected_components: [component(['POST /orders/approve'], 'fulfillment')] })];
    const index = buildEntrypointIndex(records);
    expect(index.clusters).toHaveLength(5);
    expect(index.clusters.every(cluster => cluster.findingKeys.length === 1)).toBe(true);
    expect(new Set(index.clusters.map(cluster => cluster.id)).size).toBe(5);
  });

  it('isolates unknown scope metadata and never borrows a repository from another field', () => {
    const unknownRepository = [finding('F-A', { affected_components: [component(['route'], undefined)] }), finding('F-B', { affected_components: [component(['route'], undefined)] })];
    // Passing undefined uses the helper default; explicitly omit the recorded field.
    unknownRepository.forEach(record => { delete record.raw.affected_components![0].repository; });
    const repositoryIndex = buildEntrypointIndex(unknownRepository);
    expect(repositoryIndex.clusters).toHaveLength(2);
    expect(repositoryIndex.clusters.every(cluster => cluster.repository === null && cluster.incompleteScope)).toBe(true);
    expect(buildEntrypointIndex([finding('F-C', {}, { scopeId: null }), finding('F-D', {}, { scopeId: null })]).clusters).toHaveLength(2);
    expect(buildEntrypointIndex([finding('F-E', {}, { sourceView: null }), finding('F-F', {}, { sourceView: null })]).clusters).toHaveLength(2);
  });

  it('counts one finding association per scoped route while retaining each component citation', () => {
    const record = finding('F-A', { affected_components: [component(['route', 'route']), { ...component(['route']), id: 'component-2', name: 'Other component' }] });
    const index = buildEntrypointIndex([record, record]);
    expect(index.findings).toHaveLength(1);
    expect(index.clusters[0].findingKeys).toEqual([record.key]);
    expect(index.clusters[0].citations).toHaveLength(2);
    expect(index.associations).toHaveLength(1);
  });

  it('keeps findings with absent or blank entrypoints unassigned without inventing routes from source traces', () => {
    const record = finding('F-A', { affected_components: [component(['', '  '])], trace: [{ kind: 'entrypoint', file: 'storefront/routes.ts', line: 10, scope: 'approveOrder' }] });
    const index = buildEntrypointIndex([record]);
    expect(index.clusters).toEqual([]);
    expect(index.associations).toEqual([]);
    expect(index.unassigned).toEqual([record]);
  });

  it('does not turn a shared entrypoint or shared file into a composed attack', () => {
    const records = [finding('F-A', { finding_kind: 'code', primitive_steps: [], transitions: [] }), finding('F-B', { finding_kind: 'code', primitive_steps: [], transitions: [] })];
    expect(buildEntrypointIndex(records).clusters[0].findingKeys).toHaveLength(2);
    expect(buildEntrypointIndex(records).chains).toEqual([]);
    expect(buildCompositionOverview(records).edges).toEqual([]);
  });
});

describe('deterministic graph reading order', () => {
  it('orders priority by recorded cohort before severity, then uses natural finding IDs', () => {
    const records = [
      finding('F-4', {}, { cohort: 'rejected', severity: 'critical' }),
      finding('F-3', {}, { cohort: 'non_promoted', severity: 'low' }),
      finding('F-1', {}, { cohort: 'unconfirmed', severity: 'critical' }),
      finding('F-20', {}, { cohort: 'needs_environment', severity: 'critical' }),
      finding('F-90', {}, { cohort: 'confirmed', severity: 'low' }),
      finding('F-10', {}, { cohort: 'confirmed', severity: 'high' }),
      finding('F-2', {}, { cohort: 'confirmed', severity: 'high' }),
    ];
    expect([...records].sort(compareFindings).map(record => record.id)).toEqual(['F-2', 'F-10', 'F-90', 'F-20', 'F-1', 'F-3', 'F-4']);
    expect([...records].sort((a, b) => compareFindings(a, b, 'id')).map(record => record.id)).toEqual(['F-1', 'F-2', 'F-3', 'F-4', 'F-10', 'F-20', 'F-90']);
  });

  it('resolves repeated finding IDs by execution, scope, source view and qualified key', () => {
    const records = [
      finding('F-2', {}, { runId: 'run-10', scopeId: 'scope-1', sourceView: 'base', key: 'key-1' }),
      finding('F-2', {}, { runId: 'run-2', scopeId: 'scope-10', sourceView: 'base', key: 'key-2' }),
      finding('F-2', {}, { runId: 'run-2', scopeId: 'scope-2', sourceView: 'derived', key: 'key-3' }),
      finding('F-2', {}, { runId: 'run-2', scopeId: 'scope-2', sourceView: 'base', key: 'key-10' }),
      finding('F-2', {}, { runId: 'run-2', scopeId: 'scope-2', sourceView: 'base', key: 'key-2' }),
    ];
    const sorted = [...records].sort(compareFindings);
    expect(sorted).toEqual([records[4], records[3], records[2], records[1], records[0]]);
    expect([...records].reverse().sort(compareFindings)).toEqual(sorted);
  });

  it('offers distinct sharing, priority and repository/route cluster orders', () => {
    const records = [
      finding('F-30', { affected_components: [component(['POST /shared'], 'gamma')] }, { severity: 'low' }),
      finding('F-31', { affected_components: [component(['POST /shared'], 'gamma')] }, { severity: 'low' }),
      finding('F-32', { affected_components: [component(['POST /shared'], 'gamma')] }, { severity: 'low' }),
      finding('F-20', { affected_components: [component(['POST /medium'], 'alpha')] }, { severity: 'medium' }),
      finding('F-21', { affected_components: [component(['POST /medium'], 'alpha')] }, { severity: 'medium' }),
      finding('F-10', { affected_components: [component(['POST /critical'], 'beta')] }, { severity: 'critical' }),
    ];
    const labels = (sort: EntrypointSort) => buildEntrypointIndex(records, sort).clusters.map(cluster => cluster.label);
    expect(labels('shared')).toEqual(['POST /shared', 'POST /medium', 'POST /critical']);
    expect(labels('priority')).toEqual(['POST /critical', 'POST /medium', 'POST /shared']);
    expect(labels('route')).toEqual(['POST /medium', 'POST /critical', 'POST /shared']);
    for (const sort of ['shared', 'priority', 'route'] as const) {
      expect(buildEntrypointIndex(records, sort).findings.map(record => record.id)).toEqual(['F-10', 'F-20', 'F-21', 'F-30', 'F-31', 'F-32']);
    }
  });

  it('breaks shared-count ties by best associated priority, and priority ties by shared count', () => {
    const records = [
      finding('F-2', { affected_components: [component(['POST /one', 'POST /two'])] }, { severity: 'critical' }),
      finding('F-10', { affected_components: [component(['POST /two'])] }, { severity: 'low' }),
      finding('F-3', { affected_components: [component(['POST /three'])] }, { severity: 'high' }),
      finding('F-4', { affected_components: [component(['POST /three'])] }, { severity: 'high' }),
    ];
    expect(buildEntrypointIndex(records, 'shared').clusters.map(cluster => cluster.label)).toEqual(['POST /two', 'POST /three', 'POST /one']);
    expect(buildEntrypointIndex(records, 'priority').clusters.map(cluster => cluster.label)).toEqual(['POST /two', 'POST /one', 'POST /three']);
  });

  it('uses natural repository and route order without merging distinct run/scope/source identities', () => {
    const records = [
      finding('F-1', { affected_components: [component(['GET /route-2'], 'repo-10')] }),
      finding('F-2', { affected_components: [component(['GET /route-10'], 'repo-2')] }),
      finding('F-3', { affected_components: [component(['GET /route-2'], 'repo-2')] }, { runId: 'run-10', scopeId: 'scope-1' }),
      finding('F-4', { affected_components: [component(['GET /route-2'], 'repo-2')] }, { runId: 'run-2', scopeId: 'scope-10' }),
      finding('F-5', { affected_components: [component(['GET /route-2'], 'repo-2')] }, { runId: 'run-2', scopeId: 'scope-2', sourceView: 'derived' }),
      finding('F-6', { affected_components: [component(['GET /route-2'], 'repo-2')] }, { runId: 'run-2', scopeId: 'scope-2', sourceView: 'base' }),
    ];
    const index = buildEntrypointIndex(records, 'route');
    expect(index.clusters.map(cluster => cluster.findingKeys)).toEqual([5, 4, 3, 2, 1, 0].map(index => [records[index].key]));
    expect(new Set(index.clusters.map(cluster => cluster.id)).size).toBe(6);
  });

  it('keeps findings, citations, associations and compositions stable for shuffled input', () => {
    const records = [
      finding('F-10', { affected_components: [{ ...component(['POST /shared']), id: 'component-10' }, { ...component([' POST /shared ', 'GET /one']), id: 'component-2' }] }),
      finding('F-2', { affected_components: [component(['POST /shared'])] }),
      finding('F-3', { affected_components: [] }, { severity: 'critical' }),
      finding('F-4', { affected_components: [] }, { cohort: 'needs_environment' }),
      finding('F-5', { affected_components: [component(['GET /one'])] }, { scopeId: 'scope-2' }),
    ];
    const before = structuredClone(records);
    const permutations = [[...records].reverse(), [...records.slice(2), ...records.slice(0, 2)], [records[1], records[3], records[0], records[4], records[2]]];
    for (const sort of ['shared', 'priority', 'route'] as EntrypointSort[]) {
      for (const compositionSort of ['priority', 'id'] as CompositionSort[]) {
        const expected = buildEntrypointIndex(records, sort, compositionSort);
        for (const shuffled of permutations) expect(buildEntrypointIndex(shuffled, sort, compositionSort)).toEqual(expected);
        expect(expected.unassigned.map(record => record.id)).toEqual(['F-3', 'F-4']);
        const shared = expected.clusters.find(cluster => cluster.label === 'POST /shared')!;
        expect(shared.findingKeys).toEqual([records[1].key, records[0].key]);
        expect(shared.citations.filter(citation => citation.findingKey === records[0].key).map(citation => citation.componentId)).toEqual(['component-2', 'component-10']);
        expect(expected.associations.filter(association => association.entrypointId === shared.id).map(association => association.findingKey)).toEqual(shared.findingKeys);
      }
    }
    for (const sort of ['priority', 'id'] as const) {
      for (const shuffled of permutations) expect(buildCompositionOverview(shuffled, sort)).toEqual(buildCompositionOverview(records, sort));
    }
    expect(records).toEqual(before);
  });

  it('sorts chain groups while preserving their recorded primitive and transition order', () => {
    const low = finding('F-2', {}, { severity: 'low' }), critical = finding('F-10', {}, { severity: 'critical' });
    critical.raw.primitive_steps!.reverse();
    critical.raw.transitions!.push({ producer_id: 'P-2', consumer_id: 'P-1', resolution: { outcome: 'locally_unresolved' } });
    const before = structuredClone([low, critical]);
    for (const sort of ['priority', 'id'] as const) {
      const expected = sort === 'priority' ? ['F-10', 'F-2'] : ['F-2', 'F-10'];
      const overview = buildCompositionOverview([low, critical], sort);
      expect(overview.chains.map(chain => chain.finding.id)).toEqual(expected);
      expect(buildEntrypointIndex([low, critical], 'shared', sort).chains.map(chain => chain.id)).toEqual(expected);
      const projection = overview.chains.find(chain => chain.finding.id === 'F-10')!.projection;
      expect(projection.nodes.map(node => node.localId)).toEqual(['P-2', 'P-1']);
      expect(projection.edges.map(edge => [edge.source, edge.target])).toEqual([
        [localEntityKey(critical.key, 'composition', 'P-1'), localEntityKey(critical.key, 'composition', 'P-2')],
        [localEntityKey(critical.key, 'composition', 'P-2'), localEntityKey(critical.key, 'composition', 'P-1')],
      ]);
    }
    expect([low, critical]).toEqual(before);
  });
});

describe('all-compositions overview', () => {
  it('shows every recorded primitive and only within-finding explicit transitions despite repeated local IDs', () => {
    const records = [finding('F-A'), finding('F-B')];
    const overview = buildCompositionOverview(records);
    expect(overview.nodes).toHaveLength(4);
    expect(overview.edges).toHaveLength(2);
    expect(new Set(overview.nodes.map(node => node.id)).size).toBe(4);
    for (const edge of overview.edges) {
      expect(overview.nodes.find(node => node.id === edge.source)?.finding.key).toBe(edge.finding.key);
      expect(overview.nodes.find(node => node.id === edge.target)?.finding.key).toBe(edge.finding.key);
    }
  });

  it('preserves unresolved transition status and exposes missing endpoints without invented geometry', () => {
    const record = finding('F-A');
    record.raw.transitions![0].resolution = { outcome: 'locally_unresolved', missing_fact: 'Consumer authority is not established.' };
    const overview = buildCompositionOverview([record]);
    expect(overview.edges[0].status).toBe('locally_unresolved');
    expect(overview.edges[0].details.find(field => field.label === 'Resolution')?.value).toEqual(record.raw.transitions![0].resolution);
    expect(compositionCounts(record).unresolved).toBe(1);
    record.raw.transitions![0].consumer_id = 'missing';
    const missing = buildCompositionOverview([record]);
    expect(missing.edges).toEqual([]);
    expect(missing.chains[0].projection.diagnostics).toHaveLength(1);
  });

  it('keeps recorded chains with no primitive details discoverable', () => {
    const record = finding('F-A', { primitive_steps: [], transitions: [] });
    const overview = buildCompositionOverview([record]);
    expect(overview.chains).toHaveLength(1);
    expect(overview.unavailable).toEqual([record]);
    expect(overview.nodes).toEqual([]);
    expect(overview.edges).toEqual([]);
  });

  it('resolves card, primitive and transition selections to the owning chain without cross-finding substitution', () => {
    const records = [finding('F-A'), finding('F-B')];
    expect(chainForSelection(records, overviewChainId(records[1].key))).toBe(records[1]);
    expect(chainForSelection(records, localEntityKey(records[0].key, 'composition', 'P-1'))).toBe(records[0]);
    expect(chainForSelection(records, localEntityKey(records[1].key, 'transition', 0))).toBe(records[1]);
    expect(chainForSelection(records, localEntityKey('unavailable', 'composition', 'P-1'))).toBeUndefined();
    expect(chainForSelection(records, 'malformed')).toBeUndefined();
  });
});
