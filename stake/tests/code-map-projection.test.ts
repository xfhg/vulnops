import { describe, expect, it } from 'vitest';
import { buildCodeIndex, canonicalJson, normalizeWorkspace, type FindingRecord } from '../src/domain';
import { codeGraphWindow, evidenceForCodeRange, groupCodeLocations, projectCodeFile, type CodeFile } from '../src/features/code-map/projection';
import { makeFinding, makePublication } from './fixtures/bundles';

function findings(...ids: string[]): FindingRecord[] {
  return normalizeWorkspace([makePublication({ findings: ids.map(id => makeFinding({ id })) })]).findings;
}
function fileFor(rows: FindingRecord[], file = 'storefront/src/orders.ts'): CodeFile {
  return groupCodeLocations(buildCodeIndex(rows)).find(item => item.file === file)!;
}

describe('file-centered code relationship projection', () => {
  it('retains per-finding association provenance when findings share the same source range', () => {
    const rows = findings('F-1', 'F-2');
    rows[1].raw.remediation = { actions: [] };
    rows[1].raw.root_causes = [];
    const graph = projectCodeFile(fileFor(rows), rows);
    const range = graph.nodes.find(node => node.kind === 'location' && node.line === 42)!;
    expect(range.findingKeys).toEqual(rows.map(row => row.key));
    const associations = graph.edges.filter(edge => edge.kind === 'citation' && edge.target === range.id);
    expect(associations).toHaveLength(2);
    expect(associations.find(edge => edge.findingId === 'F-1')!.associations.some(item => item.role === 'repair')).toBe(true);
    expect(associations.find(edge => edge.findingId === 'F-2')!.associations.every(item => item.findingId === 'F-2' && item.role !== 'repair' && item.role !== 'root_cause')).toBe(true);
    expect(graph.edges.filter(edge => edge.kind === 'repair').map(edge => edge.findingId)).toEqual(['F-1']);
    expect(graph.nodes.filter(node => node.kind === 'repair')).toHaveLength(1);
  });

  it('separates a proposed change location from evidence cited to support that action', () => {
    const rows = findings('F-1');
    const action = rows[0].raw.remediation!.actions[0];
    action.locations = [{ file: 'storefront/src/policy.ts', line: 7 }];
    action.evidence_refs = ['storefront/src/orders.ts:42', 'storefront/src/policy.ts:7'];
    const graph = projectCodeFile(fileFor(rows), rows);
    expect(graph.edges.filter(edge => edge.kind === 'repair')).toHaveLength(0);
    expect(graph.edges.filter(edge => edge.kind === 'repair_evidence')).toHaveLength(1);
    expect(graph.edges.find(edge => edge.kind === 'repair_evidence')?.label).toBe('Supporting citation');
    const policy = projectCodeFile(fileFor(rows, 'storefront/src/policy.ts'), rows);
    expect(policy.edges.filter(edge => edge.kind === 'repair')).toHaveLength(1);
    expect(policy.edges.find(edge => edge.kind === 'repair')!.associations.map(item => item.role)).toEqual(['repair', 'citation']);
  });

  it('keeps reused action IDs in different findings separate and retains exact interruption targets', () => {
    const rows = findings('F-1', 'F-2');
    rows[1].raw.remediation!.actions[0].breaks_steps = ['step-2', 'missing-step'];
    rows[1].raw.remediation!.actions[0].component_ids = ['missing-component'];
    const graph = projectCodeFile(fileFor(rows), rows);
    const repairs = graph.nodes.filter(node => node.kind === 'repair');
    expect(new Set(repairs.map(node => node.id)).size).toBe(2);
    expect(repairs.map(node => node.label)).toEqual(['action-1', 'action-1']);
    expect(repairs.find(node => node.findingId === 'F-2')?.steps).toEqual([
      { id: 'step-2', title: rows[1].raw.exploitation!.steps[1].action }, { id: 'missing-step', title: null },
    ]);
    expect(repairs.find(node => node.findingId === 'F-2')?.components).toEqual([{ id: 'missing-component', title: null }]);
    expect(graph.diagnostics).toHaveLength(2);
    expect(graph.edges.every(edge => graph.nodes.some(node => node.id === edge.source) && graph.nodes.some(node => node.id === edge.target))).toBe(true);
    expect(graph.nodes.some(node => node.id === 'missing-step')).toBe(false);
  });

  it('keeps executions, assessment scopes and source views isolated', () => {
    const rows = findings('F-1');
    const original = rows[0];
    const otherRun = { ...original, key: 'other-run-finding', runId: 'another-run' };
    const otherScope = { ...original, key: 'other-scope-finding', scopeId: 'another-scope' };
    const otherView = { ...original, key: 'other-view-finding', sourceView: 'derived' };
    const graph = projectCodeFile(fileFor(rows), [original, otherRun, otherScope, otherView]);
    expect(graph.nodes.filter(node => node.kind === 'finding').map(node => node.findingKeys)).toEqual([[original.key]]);
    expect(graph.edges.every(edge => edge.findingKey === original.key)).toBe(true);
  });

  it('does not merge coordinates between findings when source attribution is unknown', () => {
    const rows = findings('F-1', 'F-2').map(row => ({ ...row, scopeId: null, sourceView: null }));
    const graph = projectCodeFile(fileFor(rows), rows);
    const sameCoordinate = graph.nodes.filter(node => node.kind === 'location' && node.line === 42);
    expect(sameCoordinate).toHaveLength(2);
    expect(sameCoordinate.every(node => node.findingKeys.length === 1)).toBe(true);
    expect(new Set(sameCoordinate.map(node => node.id)).size).toBe(2);
  });

  it('preserves original selectors and evidence ownership without turning artifacts into source', () => {
    const rows = findings('F-1');
    const inherited = { execution_id: 'earlier-audit', artifact_ref: 'final-verification/findings.json#/findings/0' };
    rows[0].raw.source_refs = [inherited];
    rows[0].raw.verification!.source_validation_refs = ['storefront/src/policy.ts:11-14,20', 'sast/results.json:1', '../outside.ts:4', { execution_id: 'earlier-audit', artifact_ref: 'storefront/src/policy.ts:99' }];
    const graph = projectCodeFile(fileFor(rows, 'storefront/src/policy.ts'), rows);
    const ranges = graph.nodes.filter(node => node.kind === 'location');
    expect(ranges.map(node => [node.line, node.endLine])).toEqual([[11, 14], [20, 20]]);
    expect(ranges.every(node => node.evidence.some(item => item.reference === 'storefront/src/policy.ts:11-14,20' && item.runId === rows[0].runId))).toBe(true);
    expect(evidenceForCodeRange(ranges[0], 'storefront/src/policy.ts')?.reference).toBe('storefront/src/policy.ts:11-14,20');
    expect(graph.nodes.find(node => node.kind === 'finding')!.evidence).toContainEqual({ reference: inherited, runId: rows[0].runId, label: 'Contributing finding record' });
    expect(graph.nodes.some(node => node.line === 99)).toBe(false);
    expect(groupCodeLocations(buildCodeIndex(rows)).some(file => file.file.startsWith('sast/') || file.file.startsWith('../'))).toBe(false);
  });

  it('opens the selected coordinate rather than an earlier support citation in the same file', () => {
    const rows = findings('F-1');
    rows[0].raw.remediation!.actions[0].evidence_refs = ['storefront/src/orders.ts:10', 'storefront/src/orders.ts:42'];
    const graph = projectCodeFile(fileFor(rows), rows);
    const range = graph.nodes.find(node => node.kind === 'location' && node.line === 42)!;
    expect(range.evidence.some(item => item.reference === 'storefront/src/orders.ts:10')).toBe(true);
    expect(evidenceForCodeRange(range, graph.file.file)).toMatchObject({ reference: 'storefront/src/orders.ts:42', runId: rows[0].runId });
  });

  it('is deterministic under shuffled finding input and does not mutate dossiers', () => {
    const rows = findings('F-10', 'F-2', 'F-1');
    const before = canonicalJson(rows);
    const file = fileFor(rows);
    const graph = projectCodeFile(file, rows);
    expect(graph.nodes.filter(node => node.kind === 'finding').map(node => node.label)).toEqual(['F-1', 'F-2', 'F-10']);
    expect(projectCodeFile(file, [rows[2], rows[0], rows[1]])).toEqual(graph);
    expect(canonicalJson(rows)).toBe(before);
  });

  it('windows all source ranges explicitly and retains only complete visible connections', () => {
    const rows = findings('F-1');
    const graph = projectCodeFile(fileFor(rows), rows);
    const locations = graph.nodes.filter(node => node.kind === 'location');
    const first = codeGraphWindow(graph, 0, 3);
    expect(first).toMatchObject({ page: 0, start: 1, end: 3, total: locations.length, pages: Math.ceil(locations.length / 3) });
    const shown = new Set<string>();
    for (let page = 0; page < first.pages; page++) {
      const window = codeGraphWindow(graph, page, 3);
      window.nodes.filter(node => node.kind === 'location').forEach(node => shown.add(node.id));
      expect(window.edges.every(edge => window.nodes.some(node => node.id === edge.source) && window.nodes.some(node => node.id === edge.target))).toBe(true);
    }
    expect(shown).toEqual(new Set(locations.map(node => node.id)));
    expect(codeGraphWindow(graph, 999, 3).page).toBe(first.pages - 1);
  });

  it('does not draw incomplete or conflicted records and invents no relationship when a file is unavailable', () => {
    const rows = findings('F-1', 'F-2');
    const file = fileFor(rows);
    const empty = projectCodeFile(file, [{ ...rows[0], conflicted: true }, { ...rows[1], hasDossier: false }]);
    expect(empty.nodes).toEqual([]);
    expect(empty.edges).toEqual([]);
    expect(projectCodeFile({ ...file, file: 'storefront/not-cited.ts' }, rows).nodes).toEqual([]);
    expect(codeGraphWindow(empty, 0)).toMatchObject({ start: 0, end: 0, total: 0, pages: 1 });
  });
});
