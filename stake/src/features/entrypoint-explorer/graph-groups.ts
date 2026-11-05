import type { Edge } from '@xyflow/react';
import type { EntrypointIndex } from './model';
import type { OverviewGraphNode, OverviewLane } from './OverviewCanvas';

/** Connected association groups are a visual partition, never additional evidence edges. */
export function entrypointLanes(nodes: OverviewGraphNode[], edges: Edge[], index: EntrypointIndex) {
  const neighbors = new Map(nodes.map(node => [node.id, new Set<string>()]));
  for (const edge of edges) {
    if (!neighbors.has(edge.source) || !neighbors.has(edge.target)) continue;
    neighbors.get(edge.source)!.add(edge.target);
    neighbors.get(edge.target)!.add(edge.source);
  }
  const laneIds = new Map<string, string>();
  const lanes: OverviewLane[] = [];
  for (const node of nodes) {
    if (laneIds.has(node.id)) continue;
    const pending = [node.id];
    while (pending.length) {
      const id = pending.pop()!;
      if (laneIds.has(id)) continue;
      laneIds.set(id, node.id);
      for (const neighbor of neighbors.get(id) ?? []) if (!laneIds.has(neighbor)) pending.push(neighbor);
    }
    const clusters = index.clusters.filter(cluster => laneIds.get(cluster.id) === node.id);
    const repositories = [...new Set(clusters.map(cluster => cluster.repository || 'Repository unknown'))];
    const findingCount = new Set(clusters.flatMap(cluster => cluster.findingKeys)).size;
    lanes.push({ id: node.id, selectionId: node.id,
      title: clusters.length ? repositories.join(' · ') : 'Unassigned entrypoints',
      subtitle: clusters.length ? `${clusters.length} entrypoint${clusters.length === 1 ? '' : 's'} · ${findingCount} finding${findingCount === 1 ? '' : 's'} · recorded associations` : `${index.unassigned.length} findings · no recorded entrypoint`,
      detail: clusters.length ? [...new Set(clusters.map(cluster => `${cluster.runId} · ${cluster.scopeId || 'Scope unknown'} · ${cluster.sourceView || 'Source view unknown'}`))].join('\n') : 'No explicit component entrypoint recorded' });
  }
  return { nodes: nodes.map(node => ({ ...node, laneId: laneIds.get(node.id)! })), lanes };
}
