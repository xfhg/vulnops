import { describe, expect, it } from 'vitest';
import { normalizeWorkspace } from '../src/domain';
import { connectedAnchor, connectedRecords, neighborhood } from '../src/features/attack-explorer/relationships';
import { projectFinding } from '../src/features/attack-explorer/projection';
import { makeFinding, makePublication } from './fixtures/bundles';

function fixture() { return normalizeWorkspace([makePublication({ findings: [makeFinding()] })]).findings[0]; }

describe('selected attack record associations', () => {
  it.each([undefined, null, '', ' \n\t'])('labels absent output capability explicitly in primary and connected primitives: %j', value => {
    const finding = fixture();
    Object.assign(finding.raw.primitive_steps![0], { output_capability: value });
    const before = structuredClone(finding);
    const composition = projectFinding(finding, 'composition');
    expect(composition.nodes[0].label).toBe('Output capability not recorded');
    expect(composition.nodes[0].localId).toBe('P-1');
    expect(composition.nodes[0].preview).toContainEqual({ label: 'Output capability', value: 'Output capability not recorded' });
    const procedure = projectFinding(finding, 'procedure');
    const connected = connectedRecords(finding, 'procedure', procedure, procedure.nodes[0].id);
    expect(connected.nodes.find(node => node.kind === 'composition')).toMatchObject({ label: 'Output capability not recorded', localId: 'P-1' });
    expect(finding).toEqual(before);
  });

  it('exposes only explicit IDs and references without adding flow edges or modifying the primary projection', () => {
    const finding = fixture();
    const primary = projectFinding(finding, 'procedure');
    const before = structuredClone({ finding, primary });
    const related = connectedRecords(finding, 'procedure', primary, primary.nodes[0].id);
    expect(related.nodes.map(node => [node.kind, node.localId])).toEqual([
      ['component', 'component-1'], ['composition', 'P-1'], ['example', 'example-1'], ['repair', 'action-1'],
      ['evidence', 'storefront/src/orders.ts:42'], ['evidence', 'sast/verified-findings.json:C-001'],
    ]);
    expect(related.edges.map(edge => edge.label)).toEqual([
      'References component', 'References primitive', 'References example', 'Proposes interrupting step', 'Cites evidence', 'Cites evidence',
    ]);
    expect(related.edges.every(edge => edge.kind === 'association' && edge.source === primary.nodes[0].id)).toBe(true);
    expect(related.nodes.every(node => !node.highlighted)).toBe(true);
    expect(primary.edges).toHaveLength(1); expect(primary.edges[0].kind).toBe('sequence');
    expect({ finding, primary }).toEqual(before);
  });

  it('retains null service metadata, unexecuted examples and exact repair recommendations', () => {
    const finding = fixture();
    const service = { name: null, binding: 'unknown', limitation: 'No deployment binding was established.', evidence_refs: [] };
    finding.raw.affected_components![0].service = service;
    const primary = projectFinding(finding, 'procedure');
    const related = connectedRecords(finding, 'procedure', primary, primary.nodes[0].id);
    const component = related.nodes.find(node => node.kind === 'component')!;
    expect(component.raw.service).toEqual(service);
    expect(component.caption).toBe('storefront · Service not recorded');
    expect(component.preview).toContainEqual({ label: 'Service binding', value: 'unknown' });
    expect(related.nodes.find(node => node.kind === 'example')?.status).toBe('not_executed');
    expect(related.nodes.find(node => node.kind === 'repair')).toMatchObject({ status: 'proposed_repair', highlighted: false, repairIds: ['action-1'] });
  });

  it('keeps missing component, primitive and example references explicit instead of substituting another record', () => {
    const finding = fixture();
    finding.raw.exploitation!.steps[0].component_ids = ['component-missing'];
    finding.raw.exploitation!.steps[0].primitive_ids = ['primitive-missing'];
    finding.raw.exploitation!.steps[0].example_ids = ['example-missing'];
    const primary = projectFinding(finding, 'procedure');
    const related = connectedRecords(finding, 'procedure', primary, primary.nodes[0].id);
    expect(related.nodes.filter(node => node.status === 'unavailable').map(node => node.localId))
      .toEqual(['component-missing', 'primitive-missing', 'example-missing']);
    expect(related.diagnostics).toHaveLength(3);
    expect(related.nodes.some(node => node.localId === 'component-1' || node.localId === 'P-1' || node.localId === 'example-1')).toBe(false);
  });

  it('restores metadata and association selection from qualified identities and rejects another finding or mode', () => {
    const finding = fixture(); const primary = projectFinding(finding, 'procedure');
    const related = connectedRecords(finding, 'procedure', primary, primary.nodes[0].id);
    for (const item of [...related.nodes, ...related.edges]) {
      expect(connectedAnchor(finding.key, 'procedure', item.id)).toBe(primary.nodes[0].id);
      expect(connectedRecords(finding, 'procedure', primary, item.id)).toEqual(related);
      expect(connectedAnchor('another-finding', 'procedure', item.id)).toBeNull();
      expect(connectedAnchor(finding.key, 'trace', item.id)).toBeNull();
    }
    expect(connectedRecords(finding, 'procedure', primary, 'stale-selection').nodes).toEqual([]);
    expect(connectedRecords({ ...finding, key: 'other' }, 'procedure', primary, related.nodes[0].id).nodes).toEqual([]);
  });

  it('retains complete structured reference identity and ownership even when display labels coincide', () => {
    const finding = fixture();
    const first = { execution_id: 'baseline-run', artifact_ref: 'sast/verified-findings.json:C-001', source_view: 'base' };
    const other = { ...first, source_view: 'derived' };
    finding.raw.exploitation!.steps[0].evidence_refs = [first, other, first];
    finding.raw.exploitation!.steps[0].observation_refs = [];
    const primary = projectFinding(finding, 'procedure');
    const related = connectedRecords(finding, 'procedure', primary, primary.nodes[0].id);
    const refs = related.nodes.filter(node => node.kind === 'evidence');
    expect(refs).toHaveLength(2); expect(refs[0].id).not.toBe(refs[1].id);
    expect(refs[0].label).toBe(refs[1].label);
    expect(refs.map(node => node.evidence[0])).toEqual([first, other]);
    expect(related.edges.filter(edge => refs.some(node => node.id === edge.target))).toHaveLength(2);
  });

  it('shows reverse primitive references without claiming a referenced step repair neutralizes the primitive', () => {
    const finding = fixture(); const primary = projectFinding(finding, 'composition', 'action-1');
    const related = connectedRecords(finding, 'composition', primary, primary.nodes[0].id);
    expect(related.nodes.filter(node => node.kind === 'procedure').map(node => node.localId)).toEqual(['step-1']);
    expect(related.edges[0].label).toBe('Referenced by procedure step');
    expect(related.nodes.some(node => node.kind === 'repair' || node.kind === 'component')).toBe(false);
    expect(primary.nodes.every(node => !node.highlighted)).toBe(true);
  });

  it('links trace repairs only by the complete recorded coordinate and never by sequence position', () => {
    const finding = fixture();
    finding.raw.trace![0] = { file: 'storefront/src/orders.ts', line: 42, end_line: 45, kind: 'entrypoint' };
    const project = () => projectFinding(finding, 'trace');
    let primary = project();
    expect(connectedRecords(finding, 'trace', primary, primary.nodes[0].id).nodes.some(node => node.kind === 'repair')).toBe(false);
    finding.raw.remediation!.actions[0].locations = [{ file: 'storefront/src/orders.ts', line: 42, end_line: 45 }];
    primary = project();
    const related = connectedRecords(finding, 'trace', primary, primary.nodes[0].id);
    expect(related.edges.some(edge => edge.label === 'Repair cites same location')).toBe(true);
    expect(related.nodes.some(node => node.kind === 'procedure')).toBe(false);
    expect(related.nodes.find(node => node.kind === 'repair')?.highlighted).toBe(false);
  });

  it('exposes transition evidence through a separate association anchor without replacing the original edge', () => {
    const finding = fixture(); const primary = projectFinding(finding, 'composition');
    const before = structuredClone(primary);
    const related = connectedRecords(finding, 'composition', primary, primary.edges[0].id);
    expect(related.nodes[0].kind).toBe('transition');
    expect(related.edges.slice(0, 2).map(edge => [edge.label, edge.target])).toEqual([
      ['Recorded producer', primary.nodes[0].id], ['Recorded consumer', primary.nodes[1].id],
    ]);
    expect(related.nodes.filter(node => node.kind === 'evidence')).toHaveLength(2);
    expect(related.edges.every(edge => edge.kind === 'association')).toBe(true);
    expect(primary).toEqual(before);
  });

  it('retains typed inputs, outputs and non-established obligation counts without inventing observation status', () => {
    const finding = fixture();
    finding.raw.transitions![0].resolution = { outcome: 'contradicted', reason: 'Recorded consumer rejects this capability.' };
    finding.raw.transitions![0].obligations = { actor_control: { outcome: 'established' }, consumer_authority: { outcome: 'contradicted' }, external_binding: {} };
    const procedure = projectFinding(finding, 'procedure');
    expect(procedure.nodes[0].kind).toBe('procedure');
    expect(procedure.nodes[0].preview).toContainEqual({ label: 'Controlled input', value: 'Synthetic session selector' });
    expect(procedure.nodes[0].details).toContainEqual({ label: 'Observed effect', value: 'No observation recorded' });
    const composition = projectFinding(finding, 'composition');
    expect(composition.nodes[0].preview).toEqual([{ label: 'Input capability', value: 'Session selector' }, { label: 'Output capability', value: 'Approval identity' }]);
    expect(composition.edges[0]).toMatchObject({ kind: 'transition', status: 'contradicted', summary: '3 recorded obligations · 2 not established' });
  });

  it('focuses the existing one-hop neighborhood without adding shortcut edges or dropping the full projection', () => {
    const finding = fixture(); const primary = projectFinding(finding, 'trace');
    const before = structuredClone(primary);
    const focus = neighborhood(primary, primary.nodes[3].id);
    expect(focus.nodes.map(node => node.localId)).toEqual(['trace-3', 'trace-4', 'trace-5']);
    expect(focus.edges).toEqual(primary.edges.slice(2, 4));
    expect(neighborhood(primary, 'missing')).toBe(primary);
    expect(neighborhood(primary, primary.edges[3].id).nodes.map(node => node.localId)).toEqual(['trace-3', 'trace-4', 'trace-5', 'trace-6']);
    expect(primary).toEqual(before);
  });
});
