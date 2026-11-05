import { describe, expect, it } from 'vitest';
import type { Edge } from '@xyflow/react';
import { normalizeWorkspace, type FindingRecord } from '../src/domain';
import { entrypointLanes } from '../src/features/entrypoint-explorer/graph-groups';
import { buildEntrypointIndex, overviewFindingId, type EntrypointIndex } from '../src/features/entrypoint-explorer/model';
import type { OverviewGraphNode } from '../src/features/entrypoint-explorer/OverviewCanvas';
import { makeFinding, makePublication } from './fixtures/bundles';

function graph(index: EntrypointIndex): { nodes: OverviewGraphNode[]; edges: Edge[] } {
  return {
    nodes: [
      ...index.clusters.map(cluster => ({ id: cluster.id, laneId: '', column: 0 as const, data: { kind: 'entrypoint' as const, title: cluster.label, caption: '', label: '', status: 'Recorded' } })),
      ...index.findings.map(finding => ({ id: overviewFindingId(finding.key), laneId: '', column: 1 as const, data: { kind: 'finding' as const, title: finding.title, caption: '', label: finding.id, status: 'Recorded' } })),
    ],
    edges: index.associations.map(association => ({ id: association.id, source: association.entrypointId, target: overviewFindingId(association.findingKey) })),
  };
}

function withRoutes(finding: FindingRecord, routes: string[]) {
  finding.raw.affected_components![0].entrypoints = routes;
  return finding;
}

describe('visual association lanes', () => {
  it('unites only explicit connected associations and ignores dangling references without inventing links', () => {
    const findings = normalizeWorkspace([makePublication({ findings: [makeFinding(), makeFinding({ id: 'F-002' })] })]).findings;
    withRoutes(findings[0], ['POST /approve', 'GET /review']);
    withRoutes(findings[1], ['POST /fulfill']);
    const index = buildEntrypointIndex(findings);
    const { nodes, edges } = graph(index);
    const before = structuredClone({ nodes, edges, index });
    const grouped = entrypointLanes(nodes, edges, index);
    expect(grouped.lanes).toHaveLength(2);
    const bridgeLane = grouped.nodes.find(node => node.id === overviewFindingId(findings[0].key))!.laneId;
    expect(grouped.nodes.filter(node => node.laneId === bridgeLane)).toHaveLength(3);
    expect(grouped.lanes.find(lane => lane.id === bridgeLane)!.subtitle).toBe('2 entrypoints · 1 finding · recorded associations');
    expect({ nodes, edges, index }).toEqual(before);

    const removed = edges[0];
    const partialEdges = [...edges.slice(1), { id: 'dangling', source: removed.source, target: 'unavailable-finding' }];
    const disconnected = entrypointLanes(nodes, partialEdges, index);
    expect(disconnected.lanes).toHaveLength(3);
    expect(disconnected.nodes).toHaveLength(nodes.length);
    expect(disconnected.nodes.find(node => node.id === removed.source)!.laneId)
      .not.toBe(disconnected.nodes.find(node => node.id === removed.target)!.laneId);
  });

  it('retains separate lanes for identical routes and repeated local IDs across executions, scopes and source views', () => {
    const findings = normalizeWorkspace([
      makePublication({ runId: 'run-a', findings: [makeFinding(), makeFinding({ id: 'F-002' }), makeFinding({ id: 'F-003' })] }),
      makePublication({ runId: 'run-b', findings: [makeFinding()] }),
    ]).findings;
    findings.find(finding => finding.id === 'F-002')!.scopeId = 'separate-assessment';
    findings.find(finding => finding.id === 'F-003')!.sourceView = 'derived';
    const index = buildEntrypointIndex(findings);
    const { nodes, edges } = graph(index);
    const grouped = entrypointLanes(nodes, edges, index);
    expect(index.clusters).toHaveLength(4);
    expect(grouped.lanes).toHaveLength(4);
    expect(new Set(grouped.nodes.map(node => node.id)).size).toBe(8);
    for (const cluster of index.clusters) {
      const lane = grouped.nodes.find(node => node.id === cluster.id)!.laneId;
      expect(grouped.nodes.filter(node => node.laneId === lane).map(node => node.id))
        .toEqual([cluster.id, overviewFindingId(cluster.findingKeys[0])]);
      expect(grouped.lanes.find(candidate => candidate.id === lane)!.detail).toContain(cluster.runId);
    }
    const repeatedIds = findings.filter(finding => finding.id === 'F-001');
    expect(repeatedIds).toHaveLength(2);
    expect(new Set(repeatedIds.map(finding => grouped.nodes.find(node => node.id === overviewFindingId(finding.key))!.laneId)).size).toBe(2);
  });
});
