import { describe, expect, it } from 'vitest';
import { collapseProjection, graphId, locationReference, projectFinding } from '../src/features/attack-explorer/projection';
import type { RawFinding } from '../src/domain/index';

const fixture = (key = '["audit","F-1"]') => ({
  key,
  raw: {
    id: 'F-1', affected_components: [{ id: 'web', name: 'Web application', repository: 'web' }],
    exploitation: { steps: [
      { id: 'step-1', action: 'Select another tenant record', evidence_status: 'source_established', component_ids: ['web'], primitive_ids: ['read'],
        controlled_input: 'record_id', expected_result: 'The selected record is returned', observed_result: null, evidence_refs: ['web/lookup.ts:10'] },
      { id: 'step-2', action: 'Use the returned reference', evidence_status: 'environment_required', component_ids: ['web'], primitive_ids: ['write'],
        missing_fact: 'Deployment identity binding', expected_result: 'A dependent write may be admitted', observed_result: null, evidence_refs: ['web/save.ts:30'] },
    ] },
    trace: Array.from({ length: 8 }, (_, index) => ({ file: `web/${index === 0 ? 'lookup' : 'save'}.ts`, line: 10 + index,
      scope: `operation${index}`, kind: index === 0 ? 'entrypoint' : index === 7 ? 'sink' : 'propagation', description: `Recorded trace ${index}` })),
    primitive_steps: [
      { primitive_id: 'read', input_capability: 'Ordinary session', output_capability: 'Cross-tenant reference', boundary_crossed: 'Tenant ownership' },
      { primitive_id: 'write', input_capability: 'Cross-tenant reference', output_capability: 'Dependent write', boundary_crossed: 'Write authority' },
    ],
    transitions: [{ producer_id: 'read', consumer_id: 'write', resolution: { outcome: 'locally_unresolved', missing_fact: 'Consumer binding' },
      obligations: { consumer_authority: { outcome: 'locally_unresolved', reason: 'Deployment-dependent binding', evidence_refs: ['web/save.ts:30'] } } }],
    technical_examples: [{ id: 'example-1', kind: 'request', content: 'GET /record/SYNTHETIC_ID', execution_status: 'not_executed' }],
    remediation: { actions: [{ id: 'repair-1', change: 'Bind the selected record to the session tenant', breaks_steps: ['step-1'],
      locations: [{ file: 'web/lookup.ts', line: 10 }], component_ids: ['web'] }] },
  } as RawFinding,
});

describe('recorded attack graph projections', () => {
  it.each([
    [{ file: 'web/source.ts', line: 10, end_line: 14 }, 'web/source.ts:10-14'],
    [{ file: 'web/source.ts', start_line: 10, end_line: 15 }, 'web/source.ts:10-15'],
    [{ file: 'web/source.ts', line: 10, start_line: 30, end_line: 14 }, 'web/source.ts:10-14'],
    [{ file: 'web/source.ts', line: null, start_line: 11, end_line: 14 }, 'web/source.ts:11-14'],
    [{ file: 'web/source.ts', line: 10, end_line: 10 }, 'web/source.ts:10'],
    [{ file: 'web/source.ts', line: 10, end_line: null }, 'web/source.ts:10'],
    [{ file: 'web/source.ts', line: null, start_line: null, end_line: null }, 'web/source.ts'],
    [{ file: 'web/source.ts' }, 'web/source.ts'],
    [{ line: 10, end_line: 14 }, ''],
  ])('formats complete recorded source coordinates without dangling separators: %j', (record, expected) => {
    expect(locationReference(record as Record<string, unknown>)).toBe(expected);
  });

  it('compares the complete repair range and preserves that range in trace labels and evidence', () => {
    const finding = fixture();
    finding.raw.trace = [
      { file: 'web/lookup.ts', line: 10, end_line: 14, kind: 'entrypoint' },
      { file: 'web/lookup.ts', line: 10, end_line: 15, kind: 'propagation' },
      { file: 'web/lookup.ts', start_line: 11, end_line: 14, kind: 'sink' },
    ];
    finding.raw.remediation!.actions[0].locations = [{ file: 'web/lookup.ts', start_line: 10, end_line: 14 }];
    const before = structuredClone(finding);
    const trace = projectFinding(finding, 'trace', 'repair-1');
    expect(trace.nodes.map(node => node.caption)).toEqual(['web/lookup.ts:10-14', 'web/lookup.ts:10-15', 'web/lookup.ts:11-14']);
    expect(trace.nodes.filter(node => node.highlighted).map(node => node.localId)).toEqual(['trace-1']);
    expect(trace.nodes.map(node => node.evidence)).toEqual([['web/lookup.ts:10-14'], ['web/lookup.ts:10-15'], ['web/lookup.ts:11-14']]);
    expect(finding).toEqual(before);
  });

  it('keeps procedure steps and trace entries separate without positional associations', () => {
    const finding = fixture();
    const procedure = projectFinding(finding, 'procedure');
    const trace = projectFinding(finding, 'trace');
    expect(procedure.nodes.map(node => node.localId)).toEqual(['step-1', 'step-2']);
    expect(trace.nodes).toHaveLength(8);
    expect(procedure.edges).toHaveLength(1);
    expect(trace.edges).toHaveLength(7);
    expect(trace.nodes.every(node => !procedure.nodes.some(step => step.id === node.id))).toBe(true);
    expect(procedure.edges[0].status).toBe('recorded_sequence');
    expect(trace.edges[0].details[0].value).toContain('not an inferred call edge');
  });

  it('retains environment-required status despite unexecuted examples and no observations', () => {
    const graph = projectFinding(fixture(), 'procedure');
    expect(graph.nodes[1].status).toBe('environment_required');
    expect(graph.nodes[1].details).toContainEqual({ label: 'Missing prerequisite', value: 'Deployment identity binding' });
    expect(graph.nodes[0].status).toBe('source_established');
  });

  it('qualifies original local IDs by finding and run identity', () => {
    const first = projectFinding(fixture('["audit-a","F-1"]'), 'procedure');
    const other = projectFinding(fixture('["audit-b","F-1"]'), 'procedure');
    expect(first.nodes[0].localId).toBe(other.nodes[0].localId);
    expect(first.nodes[0].id).not.toBe(other.nodes[0].id);
    expect(graphId('a|b', 'c', 'd')).not.toBe(graphId('a', 'b|c', 'd'));
  });

  it('uses only explicit primitive transitions and preserves unresolved proof obligations', () => {
    const graph = projectFinding(fixture(), 'composition');
    expect(graph.nodes).toHaveLength(2);
    expect(graph.edges).toHaveLength(1);
    expect(graph.edges[0].source).toBe(graph.nodes[0].id);
    expect(graph.edges[0].target).toBe(graph.nodes[1].id);
    expect(graph.edges[0].status).toBe('locally_unresolved');
    expect(graph.edges[0].details.find(field => field.label === 'consumer authority')?.value).toMatchObject({ outcome: 'locally_unresolved' });
    const finding = fixture(); finding.raw.transitions = [];
    expect(projectFinding(finding, 'composition').edges).toEqual([]);
  });

  it('does not invent a composition when only a procedure and trace are recorded', () => {
    const finding = fixture(); finding.raw.primitive_steps = []; finding.raw.transitions = [];
    expect(projectFinding(finding, 'composition').nodes).toEqual([]);
    expect(projectFinding(finding, 'procedure').nodes).toHaveLength(2);
    expect(projectFinding(finding, 'trace').nodes).toHaveLength(8);
  });

  it('does not substitute missing transition endpoints', () => {
    const finding = fixture(); finding.raw.transitions![0].consumer_id = 'unavailable';
    const graph = projectFinding(finding, 'composition');
    expect(graph.edges).toEqual([]);
    expect(graph.diagnostics).toContain('Transition 1 has an unavailable primitive; no substitute edge was drawn.');
  });

  it('highlights only explicit interrupted steps and exact repair locations', () => {
    const finding = fixture();
    const before = structuredClone(finding);
    const procedure = projectFinding(finding, 'procedure', 'repair-1');
    expect(procedure.nodes.filter(node => node.highlighted).map(node => node.localId)).toEqual(['step-1']);
    const trace = projectFinding(finding, 'trace', 'repair-1');
    expect(trace.nodes.filter(node => node.highlighted).map(node => node.localId)).toEqual(['trace-1']);
    expect(projectFinding(finding, 'composition', 'repair-1').nodes.every(node => !node.highlighted)).toBe(true);
    expect(projectFinding(finding, 'procedure').nodes.every(node => !node.highlighted)).toBe(true);
    expect(finding).toEqual(before);
  });

  it('reports unavailable repair steps and never matches a record from another finding', () => {
    const finding = fixture(); finding.raw.remediation!.actions[0].breaks_steps = ['step-404'];
    const graph = projectFinding(finding, 'procedure', 'repair-1');
    expect(graph.nodes.every(node => !node.highlighted)).toBe(true);
    expect(graph.diagnostics).toEqual(['Proposed repair references unavailable step step-404.']);
    expect(projectFinding(finding, 'procedure', 'other-repair').diagnostics).toEqual(['The selected repair is unavailable in this finding.']);
  });

  it('collapses presentation groups without mutating the complete linear/inspector projection', () => {
    const graph = projectFinding(fixture(), 'procedure', 'repair-1');
    const before = structuredClone(graph);
    const collapsed = collapseProjection(graph, new Set(['web']));
    expect(collapsed.nodes).toHaveLength(1);
    expect(collapsed.nodes[0].hiddenCount).toBe(2);
    expect(collapsed.nodes[0].highlighted).toBe(true);
    expect(collapsed.edges).toHaveLength(0);
    expect(graph).toEqual(before);
    expect(collapseProjection(graph, new Set()).nodes).toEqual(graph.nodes);
  });

  it('supports incomplete unconfirmed records without synthesizing dossier evidence', () => {
    const finding = { key: 'unconfirmed', raw: { title: 'Unresolved possibility' } };
    expect(projectFinding(finding, 'procedure').nodes).toEqual([]);
    expect(projectFinding(finding, 'trace').nodes).toEqual([]);
    expect(projectFinding(finding, 'composition').edges).toEqual([]);
  });
});
