import { describe, expect, it } from 'vitest';
import { canonicalJson, normalizeWorkspace, type FindingRecord, type RawFinding, type RepairAction } from '../src/domain';
import { buildRepairEntries, projectRepair, type RepairEntry } from '../src/features/remediation/model';
import { makeFinding, makePublication } from './fixtures/bundles';

function finding(raw: RawFinding = makeFinding(), runId = 'repair-owner'): FindingRecord {
  const workspace = normalizeWorkspace([makePublication({ runId, findings: [raw] })]);
  expect(workspace.failures).toEqual([]);
  return workspace.findings[0];
}
function entry(raw: RawFinding = makeFinding(), runId = 'repair-owner'): RepairEntry {
  return buildRepairEntries([finding(raw, runId)])[0];
}

describe('repair queue identity and ordering', () => {
  it('sorts cohorts before severity and then natural finding/action IDs deterministically', () => {
    const rawTwo = makeFinding({ id: 'F-2' });
    const template = rawTwo.remediation!.actions[0];
    rawTwo.remediation!.actions = [{ ...template, id: 'action-10' }, { ...template, id: 'action-2' }];
    const confirmedTwo = finding(rawTwo);
    const confirmedTen = finding(makeFinding({ id: 'F-10' }));
    const critical = finding(makeFinding({ id: 'F-99', severity: 'critical' }));
    const environment = finding(makeFinding({ id: 'F-1', severity: 'critical', status: 'needs_environment', verdict: 'needs_environment' }));
    const unconfirmed = { ...finding(makeFinding({ id: 'F-3', severity: 'critical' })), cohort: 'unconfirmed' as const };
    const nonPromoted = { ...finding(makeFinding({ id: 'F-4', severity: 'critical' })), cohort: 'non_promoted' as const };
    const rejected = { ...finding(makeFinding({ id: 'F-5', severity: 'critical' })), cohort: 'rejected' as const };
    const input = [rejected, confirmedTen, environment, confirmedTwo, unconfirmed, critical, nonPromoted];
    const before = canonicalJson(input);
    const queue = buildRepairEntries(input);
    expect(queue.map(item => `${item.finding.id}/${item.action.id}`)).toEqual(['F-99/action-1', 'F-2/action-2', 'F-2/action-10', 'F-10/action-1', 'F-1/action-1', 'F-3/action-1', 'F-4/action-1', 'F-5/action-1']);
    expect(buildRepairEntries([...input].reverse()).map(item => item.key)).toEqual(queue.map(item => item.key));
    expect(canonicalJson(input)).toBe(before);
  });

  it('qualifies repeated local IDs by finding, execution and assessed source scope', () => {
    const one = finding(makeFinding({ id: 'F-1' }), 'run-a');
    const two = finding(makeFinding({ id: 'F-2' }), 'run-a');
    const anotherRun = finding(makeFinding({ id: 'F-1' }), 'run-b');
    const anotherScope = { ...one, scopeId: 'scope-2' };
    const anotherView = { ...one, sourceView: 'derived' };
    const queue = buildRepairEntries([one, two, anotherRun, anotherScope, anotherView, one]);
    expect(queue).toHaveLength(5);
    expect(new Set(queue.map(item => item.key)).size).toBe(5);
    const nodeIds = queue.flatMap(item => projectRepair(item).nodes.map(node => node.id));
    expect(new Set(nodeIds).size).toBe(nodeIds.length);
    expect(queue.every(item => item.action.id === 'action-1')).toBe(true);
  });

  it('does not merge similar recommendations and keeps historical recommendations attributed', () => {
    const raw = makeFinding();
    raw.remediation!.actions.push({ ...raw.remediation!.actions[0], id: 'action-2' });
    const historic = { ...finding(raw, 'owning-baseline'), origin: 'historical' as const, historicalIn: ['advantage-owner'] };
    const queue = buildRepairEntries([historic]);
    expect(queue).toHaveLength(2);
    expect(queue.every(item => item.finding.origin === 'historical' && item.finding.runId === 'owning-baseline')).toBe(true);
    expect(queue[0].action.change).toBe(queue[1].action.change);
  });

  it('omits conflicted/incomplete records and returns an honest empty queue', () => {
    const sample = finding();
    expect(buildRepairEntries([])).toEqual([]);
    expect(buildRepairEntries([{ ...sample, conflicted: true }, { ...sample, hasDossier: false }])).toEqual([]);
    const noActions = finding({ ...makeFinding(), remediation: { actions: [] } });
    expect(buildRepairEntries([noActions])).toEqual([]);
  });
});

describe('explicit repair relationship projection', () => {
  it('links only explicit action targets and keeps root causes/trace as finding context', () => {
    const selected = entry();
    const graph = projectRepair(selected);
    const action = graph.nodes.find(node => node.kind === 'action')!;
    const owner = graph.nodes.find(node => node.kind === 'finding')!;
    expect(graph.nodes.filter(node => node.kind === 'location')).toHaveLength(selected.action.locations!.length);
    expect(graph.nodes.filter(node => node.kind === 'location').map(node => node.line)).toEqual([42]);
    expect(owner.fields.find(item => item.label === 'Root causes — finding context')?.value).toBe(selected.finding.raw.root_causes);
    expect(owner.fields.find(item => item.label === 'Assessed trace — finding context')?.value).toBe(selected.finding.raw.trace);
    const targets = graph.edges.filter(edge => edge.source === action.id);
    expect(targets.filter(edge => edge.kind === 'interruption')).toHaveLength(2);
    expect(targets.filter(edge => edge.kind === 'evidence')).toHaveLength(1);
    expect(targets.filter(edge => edge.kind === 'target')).toHaveLength(2);
    expect(graph.edges.some(edge => edge.source === owner.id && edge.target === action.id && edge.kind === 'context')).toBe(true);
    expect(graph.nodes.filter(node => ['step', 'example', 'component', 'location'].includes(node.kind)).every(node => node.scope === 'action')).toBe(true);
  });

  it('keeps checks, containment, detection, limitations and unresolved decisions finding-level', () => {
    const raw = makeFinding();
    raw.remediation!.actions.push({ ...raw.remediation!.actions[0], id: 'action-2' });
    Object.assign(raw.remediation!, {
      containment: [{ description: 'Temporarily restrict the reviewed callback.', component_ids: ['component-1'], evidence_refs: [] }],
      detection: ['Monitor unexpected approval identities.'],
      limitations: ['Deployment ownership remains unknown.'],
      unresolved_decisions: [{ decision: 'Choose the authorization policy owner.', next_action: 'Review deployment ownership.' }],
    });
    for (const selected of buildRepairEntries([finding(raw)])) {
      const graph = projectRepair(selected);
      const owner = graph.nodes.find(node => node.kind === 'finding')!;
      const context = graph.nodes.filter(node => node.kind === 'check' || node.kind === 'guidance');
      expect(context.filter(node => node.kind === 'check')).toHaveLength(1);
      expect(context.filter(node => node.kind === 'guidance')).toHaveLength(4);
      expect(context.every(node => node.scope === 'finding')).toBe(true);
      expect(context.every(node => graph.edges.filter(edge => edge.target === node.id).every(edge => edge.source === owner.id && edge.kind === 'context'))).toBe(true);
      expect(graph.nodes.some(node => node.title === 'Deployment ownership remains unknown.')).toBe(true);
      expect(graph.nodes.some(node => node.title === 'Choose the authorization policy owner.')).toBe(true);
      expect(context.find(node => node.kind === 'check')!.fields.find(item => item.label === 'Association')?.value).toContain('no action-specific');
    }
  });

  it('retains exact source ranges and original typed evidence with the owning run', () => {
    const reference = { execution_id: 'original-baseline', artifact_ref: 'sast/verified-findings.json', record_id: 'C-19' };
    const raw = makeFinding();
    raw.remediation!.actions[0].locations = [
      { file: 'storefront/src/orders.ts', start_line: 42, end_line: 47, scope: 'approveOrder', mechanism: 'Establish object ownership.' },
      { file: 'storefront/src/policy.ts', line: 9, end_line: 11 },
      { file: 'storefront/src/config.ts' },
    ];
    raw.remediation!.actions[0].evidence_refs = [reference, 'sast/verified-findings.json:C-001'];
    raw.remediation!.verification_checks![0].evidence_refs = [reference];
    const graph = projectRepair(entry(raw, 'repair-owning-run'));
    const locations = graph.nodes.filter(node => node.kind === 'location');
    expect(locations.map(node => [node.line, node.endLine])).toEqual([[42, 47], [9, 11], [null, null]]);
    expect(locations.map(node => node.evidence[0])).toEqual([
      { reference: 'storefront/src/orders.ts:42-47', runId: 'repair-owning-run' },
      { reference: 'storefront/src/policy.ts:9-11', runId: 'repair-owning-run' },
      { reference: 'storefront/src/config.ts', runId: 'repair-owning-run' },
    ]);
    expect(graph.nodes.find(node => node.kind === 'action')!.evidence[0]).toEqual({ reference, runId: 'repair-owning-run' });
    expect(graph.nodes.find(node => node.kind === 'action')!.evidence[0].reference).toBe(reference);
    expect(graph.nodes.find(node => node.kind === 'check')!.evidence[0].reference).toBe(reference);
    expect(reference.execution_id).toBe('original-baseline');
  });

  it('shows missing component, step and example references without borrowing substitute targets', () => {
    const raw = makeFinding();
    Object.assign(raw.remediation!.actions[0], { component_ids: ['unknown-component'], breaks_steps: ['unknown-step'], example_ids: ['unknown-example'] });
    const graph = projectRepair(entry(raw));
    const missing = graph.nodes.filter(node => node.unavailable);
    expect(missing.map(node => [node.kind, node.localId])).toEqual([['component', 'unknown-component'], ['step', 'unknown-step'], ['example', 'unknown-example']]);
    expect(missing.every(node => node.status === 'unavailable' && node.scope === 'action' && node.evidence.length === 0)).toBe(true);
    expect(graph.diagnostics).toHaveLength(3);
    expect(graph.nodes.some(node => node.localId === 'component-1' || node.localId === 'step-1' || node.localId === 'example-1')).toBe(false);
    expect(graph.edges.every(edge => graph.nodes.some(node => node.id === edge.source) && graph.nodes.some(node => node.id === edge.target))).toBe(true);
  });

  it('does not infer applied or verified repair status from finding/check/example statuses', () => {
    const raw = makeFinding();
    raw.remediation!.verification_checks![0].status = 'executed';
    raw.exploitation!.steps[0].evidence_status = 'observed_contained';
    raw.technical_examples![0].execution_status = 'not_executed';
    let graph = projectRepair(entry(raw));
    expect(graph.nodes.find(node => node.kind === 'finding')!.status).toBe('verified');
    expect(graph.nodes.find(node => node.kind === 'action')!.status).toBe('not_recorded');
    expect(graph.nodes.find(node => node.kind === 'check')!.status).toBe('executed');
    expect(graph.nodes.find(node => node.kind === 'step' && node.localId === 'step-1')!.status).toBe('observed_contained');
    expect(graph.nodes.find(node => node.kind === 'example')!.status).toBe('not_executed');
    raw.remediation!.actions[0].status = 'owner_review_pending';
    graph = projectRepair(entry(raw));
    expect(graph.nodes.find(node => node.kind === 'action')!.status).toBe('owner_review_pending');
  });

  it('distinguishes absent optional arrays from explicit empty arrays without invented nodes', () => {
    const minimal: RepairAction = { id: 'action-minimal', change: 'Review the recorded ownership decision.' };
    const absent = projectRepair(entry({ ...makeFinding(), remediation: { actions: [minimal] } }));
    expect(absent.nodes.map(node => node.kind)).toEqual(['finding', 'action']);
    expect(absent.edges).toHaveLength(1);
    expect(absent.nodes[1].fields.find(item => item.label === 'Proposed locations')?.value).toBeUndefined();
    const empty = projectRepair(entry({ ...makeFinding(), remediation: { actions: [{ ...minimal, locations: [], component_ids: [], breaks_steps: [], example_ids: [] }], verification_checks: [], containment: [], detection: [], limitations: [], unresolved_decisions: [] } }));
    expect(empty.nodes).toHaveLength(2);
    expect(empty.nodes[1].fields.find(item => item.label === 'Proposed locations')?.value).toEqual([]);
    expect(empty.diagnostics).toEqual([]);
  });

  it('retains all records in large queues and graphs and never mutates input data or ordering', () => {
    const raw = makeFinding();
    const template = raw.remediation!.actions[0];
    raw.remediation!.actions = Array.from({ length: 64 }, (_, index) => ({ ...template, id: `action-${64 - index}`, locations: Array.from({ length: 64 }, (_, location) => ({ file: 'storefront/src/orders.ts', line: location + 1 })) }));
    raw.remediation!.verification_checks = Array.from({ length: 64 }, (_, index) => ({ id: `check-${index + 1}`, description: `Recorded check ${index + 1}`, status: 'proposed', evidence_refs: [] }));
    const owner = finding(raw);
    const before = canonicalJson(owner);
    const queue = buildRepairEntries([owner]);
    expect(queue).toHaveLength(64);
    expect(queue[0].action.id).toBe('action-1');
    expect(queue.at(-1)!.action.id).toBe('action-64');
    const graph = projectRepair(queue[0]);
    expect(graph.nodes.filter(node => node.kind === 'location')).toHaveLength(64);
    expect(graph.nodes.filter(node => node.kind === 'check')).toHaveLength(64);
    expect(new Set(graph.nodes.map(node => node.id)).size).toBe(graph.nodes.length);
    expect(new Set(graph.edges.map(edge => edge.id)).size).toBe(graph.edges.length);
    expect(graph.nodes.filter(node => node.kind === 'location').map(node => node.line)).toEqual(Array.from({ length: 64 }, (_, index) => index + 1));
    expect(canonicalJson(owner)).toBe(before);
  });

  it('retains malformed coordinates visibly but does not generate a misleading source reference', () => {
    const selected = entry();
    selected.action = { ...selected.action, locations: [{ file: '', line: 3 }, { file: 'storefront/src/orders.ts', line: 42, end_line: 20 }] };
    const graph = projectRepair(selected);
    const locations = graph.nodes.filter(node => node.kind === 'location');
    expect(locations).toHaveLength(2);
    expect(locations.every(node => node.unavailable && node.evidence.length === 0)).toBe(true);
    expect(locations[1].line).toBe(42);
    expect(locations[1].endLine).toBe(20);
    expect(graph.diagnostics).toHaveLength(2);
  });
});
