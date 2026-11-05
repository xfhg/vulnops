import { describe, expect, it } from 'vitest';
import { normalizeWorkspace } from '../src/domain';
import { repairGeometry, repairLayer } from '../src/features/remediation/RepairCanvas';
import { buildRepairEntries, projectRepair, type RepairNode } from '../src/features/remediation/model';
import { makeFinding, makePublication } from './fixtures/bundles';

function graph() {
  const finding = makeFinding();
  finding.remediation!.containment = [{ id: 'contain-1', description: 'Synthetic containment guidance.' }];
  const workspace = normalizeWorkspace([makePublication({ findings: [finding] })]);
  return projectRepair(buildRepairEntries(workspace.findings)[0]);
}

describe('repair canvas semantic geometry', () => {
  it('places exact targets left, action centrally, interruptions right, and finding-level context below without changing model edges', () => {
    const model = graph(), before = structuredClone(model);
    const geometry = repairGeometry(model.entry.key, model.nodes);
    const target = geometry.groups.find(group => group.group === 'targets')!;
    const action = geometry.groups.find(group => group.group === 'action')!;
    const interruption = geometry.groups.find(group => group.group === 'interruptions')!;
    const context = geometry.groups.find(group => group.group === 'context')!;
    expect(target.position.x + target.width).toBeLessThan(action.position.x);
    expect(action.position.x + action.width).toBeLessThan(interruption.position.x);
    expect(context.position.y).toBeGreaterThan(Math.max(...[target, action, interruption].map(group => group.position.y + group.height)));
    expect(target.records.map(record => record.item.kind)).toEqual(['location', 'component']);
    expect(interruption.records.map(record => record.item.kind)).toEqual(['step', 'step', 'example']);
    expect(context.records.map(record => record.item.kind)).toEqual(['finding', 'check', 'guidance', 'guidance']);
    expect(model).toEqual(before);
    expect(repairGeometry(model.entry.key, model.nodes)).toEqual(geometry);
    expect(model.edges.filter(edge => model.nodes.find(node => node.id === edge.target)?.kind === 'check')
      .every(edge => model.nodes.find(node => node.id === edge.source)?.kind === 'finding')).toBe(true);
  });

  it('keeps every child within its actual parent group and prevents sibling overlap for mixed record sizes', () => {
    const model = graph(); const geometry = repairGeometry(model.entry.key, model.nodes);
    expect(geometry.groups.flatMap(group => group.records.map(record => record.item.id)).sort()).toEqual(model.nodes.map(node => node.id).sort());
    for (const group of geometry.groups) {
      expect(group.position.x).toBeGreaterThanOrEqual(geometry.bounds.x);
      expect(group.position.x + group.width).toBeLessThanOrEqual(geometry.bounds.x + geometry.bounds.width);
      expect(group.position.y + group.height).toBeLessThanOrEqual(geometry.bounds.height);
      for (const record of group.records) {
        expect(record.position.x).toBeGreaterThanOrEqual(18);
        expect(record.position.y).toBeGreaterThanOrEqual(68);
        expect(record.position.x + record.width).toBeLessThanOrEqual(group.width - 18);
        expect(record.position.y + record.height).toBeLessThanOrEqual(group.height - 18);
      }
      for (let index = 0; index < group.records.length; index++) for (const other of group.records.slice(index + 1)) {
        const record = group.records[index];
        const xOverlap = Math.min(record.position.x + record.width, other.position.x + other.width) - Math.max(record.position.x, other.position.x);
        const yOverlap = Math.min(record.position.y + record.height, other.position.y + other.height) - Math.max(record.position.y, other.position.y);
        expect(xOverlap <= 0 || yOverlap <= 0).toBe(true);
      }
    }
  });

  it('honors finding scope even for a target-shaped record and keeps unavailable action references in their explicit layer', () => {
    const model = graph();
    const location = model.nodes.find(node => node.kind === 'location')!;
    expect(repairLayer({ ...location, scope: 'finding' })).toBe('context');
    expect(repairLayer({ ...location, unavailable: true })).toBe('targets');
    const step = model.nodes.find(node => node.kind === 'step')!;
    expect(repairLayer({ ...step, unavailable: true })).toBe('interruptions');
    const contextKinds: RepairNode['kind'][] = ['finding', 'check', 'guidance'];
    for (const kind of contextKinds) expect(repairLayer({ ...location, kind, scope: 'action' })).toBe('context');
  });

  it('frames an action-only window without blank space reserved for hidden target columns', () => {
    const model = graph(); const action = model.nodes.find(node => node.kind === 'action')!;
    const geometry = repairGeometry(model.entry.key, [action]);
    expect(geometry.groups).toHaveLength(1);
    expect(geometry.bounds.x).toBe(geometry.groups[0].position.x);
    expect(geometry.bounds.width).toBe(geometry.groups[0].width);
  });
});
