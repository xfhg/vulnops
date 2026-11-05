import { describe, expect, it } from 'vitest';
import { LAYOUT, layoutGraph, type LayoutPosition, type LayoutRequest } from '../src/features/attack-explorer/layout';

const byId = (positions: LayoutPosition[]) => new Map(positions.map(position => [position.id, position]));
const link = (source: string, target: string) => ({ id: `${source}->${target}`, source, target });
function expectNoOverlap(positions: LayoutPosition[]) {
  for (let left = 0; left < positions.length; left++) for (let right = left + 1; right < positions.length; right++) {
    const a = positions[left]; const b = positions[right];
    expect(a.x + a.width <= b.x || b.x + b.width <= a.x || a.y + a.height <= b.y || b.y + b.height <= a.y,
      `${a.id} must not overlap ${b.id}`).toBe(true);
  }
}

describe('semantic graph placement', () => {
  it('keeps procedure/trace input order left-to-right instead of sorting opaque IDs or packing components', async () => {
    const request: LayoutRequest = { placement: 'sequence', nodes: [{ id: 'step-10' }, { id: 'step-2' }, { id: 'step-1' }], edges: [] };
    const layout = await layoutGraph(request);
    expect(layout.positions.map(position => position.id)).toEqual(['step-10', 'step-2', 'step-1']);
    expect(layout.positions[0].x).toBeLessThan(layout.positions[1].x);
    expect(layout.positions[1].x).toBeLessThan(layout.positions[2].x);
    expect(new Set(layout.positions.map(position => position.y)).size).toBe(1);
    expect(layout.lanes).toEqual([]);
    expect(layout.positions[0].x).toBe(0);
  });

  it('honors explicit priorities with input order for ties and preserves custom dimensions', async () => {
    const layout = await layoutGraph({ placement: 'sequence', nodes: [
      { id: 'late', order: 3, width: 310, height: 100 }, { id: 'first', order: 1, width: 220, height: 188 }, { id: 'tied', order: 1, width: 280, height: 155 },
    ], edges: [] });
    const positions = byId(layout.positions);
    expect(positions.get('first')!.x).toBeLessThan(positions.get('tied')!.x);
    expect(positions.get('tied')!.x).toBeLessThan(positions.get('late')!.x);
    expect(positions.get('first')!.width).toBe(220);
    expect(positions.get('first')!.height).toBe(188);
    expect(layout.height).toBe(188);
    expectNoOverlap(layout.positions);
  });

  it('keeps every record in a long sequence in its recorded order without generating edges', async () => {
    const nodes = Array.from({ length: 120 }, (_, index) => ({ id: `record-${index + 1}`, width: 280, height: 188 }));
    const request: LayoutRequest = { placement: 'sequence', nodes, edges: nodes.slice(1).map((node, index) => link(nodes[index].id, node.id)) };
    const before = structuredClone(request);
    const result = await layoutGraph(request);
    expect(result.positions).toHaveLength(120);
    expect(result.positions.map(position => position.id)).toEqual(nodes.map(node => node.id));
    for (let index = 1; index < result.positions.length; index++) expect(result.positions[index].x).toBeGreaterThan(result.positions[index - 1].x + 280);
    expect(request).toEqual(before);
    expect('edges' in result).toBe(false);
  });

  it('uses ordered entrypoint/finding columns regardless of association edge order', async () => {
    const request: LayoutRequest = { placement: 'bipartite', nodes: [
      { id: 'priority-route', column: 0, width: 280, height: 188 }, { id: 'other-route', column: 0, width: 250, height: 150 },
      { id: 'priority-finding', column: 1, width: 300, height: 200 }, { id: 'other-finding', column: 1, width: 280, height: 188 },
    ], edges: [link('priority-route', 'other-finding'), link('other-route', 'priority-finding')] };
    const layout = await layoutGraph(request);
    const positions = byId(layout.positions);
    expect(positions.get('priority-route')!.y).toBeLessThan(positions.get('other-route')!.y);
    expect(positions.get('priority-finding')!.y).toBeLessThan(positions.get('other-finding')!.y);
    expect(positions.get('priority-route')!.x).toBe(positions.get('other-route')!.x);
    expect(positions.get('priority-finding')!.x).toBe(positions.get('other-finding')!.x);
    expect(positions.get('priority-finding')!.x).toBeGreaterThan(positions.get('priority-route')!.x + 280);
    expect(await layoutGraph({ ...request, edges: request.edges.slice().reverse() })).toEqual(layout);
    expectNoOverlap(layout.positions);
  });

  it('stacks explicitly ordered lanes with reserved headers, padding and exact bounds', async () => {
    const result = await layoutGraph({ placement: 'sequence', lanes: [{ id: 'lower-priority', order: 2 }, { id: 'higher-priority', order: 1 }], nodes: [
      { id: 'B1', laneId: 'lower-priority', width: 280, height: 188 }, { id: 'A1', laneId: 'higher-priority', width: 280, height: 188 },
      { id: 'A2', laneId: 'higher-priority', width: 300, height: 200 },
    ], edges: [link('A1', 'A2')] });
    expect(result.lanes.map(lane => lane.id)).toEqual(['higher-priority', 'lower-priority']);
    expect(result.lanes[1].y).toBe(result.lanes[0].y + result.lanes[0].height + 28);
    for (const lane of result.lanes) {
      const members = result.positions.filter(position => position.laneId === lane.id);
      expect(Math.min(...members.map(position => position.y))).toBe(lane.y + 72 + 20);
      expect(Math.min(...members.map(position => position.x))).toBe(lane.x + 20);
      for (const node of members) {
        expect(node.x + node.width).toBeLessThanOrEqual(lane.x + lane.width - 20);
        expect(node.y + node.height).toBeLessThanOrEqual(lane.y + lane.height - 20);
      }
    }
    expect(result.height).toBe(result.lanes[1].y + result.lanes[1].height);
    expectNoOverlap(result.positions);
  });

  it('keeps a branching recorded topology left-to-right and sibling model order stable', async () => {
    const request: LayoutRequest = { nodes: [{ id: 'entry' }, { id: 'preferred-branch' }, { id: 'other-branch' }, { id: 'sink' }],
      edges: [link('entry', 'other-branch'), link('entry', 'preferred-branch'), link('other-branch', 'sink'), link('preferred-branch', 'sink')] };
    const result = await layoutGraph(request);
    const positions = byId(result.positions);
    for (const edge of request.edges) expect(positions.get(edge.source)!.x).toBeLessThan(positions.get(edge.target)!.x);
    expect(positions.get('preferred-branch')!.y).toBeLessThan(positions.get('other-branch')!.y);
    expect(await layoutGraph({ ...request, edges: request.edges.slice().reverse() })).toEqual(result);
    expectNoOverlap(result.positions);
  });

  it('respects actual producer/consumer direction even when input lists the consumer first', async () => {
    const result = await layoutGraph({ nodes: [{ id: 'sink' }, { id: 'source' }], edges: [link('source', 'sink')] });
    const positions = byId(result.positions);
    expect(positions.get('source')!.x).toBeLessThan(positions.get('sink')!.x);
  });

  it('lays out cycles deterministically without dropping records or changing their edges', async () => {
    const request: LayoutRequest = { nodes: [{ id: 'A' }, { id: 'B' }, { id: 'C' }], edges: [link('A', 'B'), link('B', 'C'), link('C', 'A')] };
    const before = structuredClone(request);
    const first = await layoutGraph(request);
    const second = await layoutGraph(request);
    expect(second).toEqual(first);
    expect(first.positions.map(position => position.id)).toEqual(['A', 'B', 'C']);
    expect(first.positions.every(position => Number.isFinite(position.x) && Number.isFinite(position.y))).toBe(true);
    expect(request).toEqual(before);
    expectNoOverlap(first.positions);
  });

  it('orders a cycle before its downstream consumer even when that consumer appears first', async () => {
    const result = await layoutGraph({ nodes: [{ id: 'downstream' }, { id: 'cycle-A' }, { id: 'cycle-B' }],
      edges: [link('cycle-A', 'cycle-B'), link('cycle-B', 'cycle-A'), link('cycle-B', 'downstream')] });
    const positions = byId(result.positions);
    expect(positions.get('downstream')!.x).toBeGreaterThan(positions.get('cycle-A')!.x);
    expect(positions.get('downstream')!.x).toBeGreaterThan(positions.get('cycle-B')!.x);
    expectNoOverlap(result.positions);
  });

  it('retains disconnected nodes/components in stable input order within a composition lane', async () => {
    const request: LayoutRequest = { nodes: [{ id: 'single-first' }, { id: 'branch-root' }, { id: 'branch-leaf' }, { id: 'single-last' }], edges: [link('branch-root', 'branch-leaf')] };
    const result = await layoutGraph(request);
    const positions = byId(result.positions);
    expect(positions.get('single-first')!.x).toBeLessThan(positions.get('branch-root')!.x);
    expect(positions.get('branch-leaf')!.x).toBeLessThan(positions.get('single-last')!.x);
    expect(result.positions).toHaveLength(4);
    expect(await layoutGraph(request)).toEqual(result);
    expectNoOverlap(result.positions);
  });

  it('keeps finding lanes independent with repeated local primitive labels and caller-owned cross-lane links', async () => {
    const request: LayoutRequest = { lanes: [{ id: 'finding-B' }, { id: 'finding-A' }], nodes: [
      { id: 'finding-A/P1', laneId: 'finding-A' }, { id: 'finding-A/P2', laneId: 'finding-A' },
      { id: 'finding-B/P1', laneId: 'finding-B' }, { id: 'finding-B/P2', laneId: 'finding-B' },
    ], edges: [link('finding-A/P1', 'finding-A/P2'), link('finding-B/P1', 'finding-B/P2'), link('finding-A/P2', 'finding-B/P1')] };
    const before = structuredClone(request);
    const result = await layoutGraph(request);
    expect(result.lanes.map(lane => lane.id)).toEqual(['finding-B', 'finding-A']);
    expect(result.positions).toHaveLength(4);
    expect(request).toEqual(before);
    const positions = byId(result.positions);
    expect(positions.get('finding-A/P1')!.x).toBeLessThan(positions.get('finding-A/P2')!.x);
    expect(positions.get('finding-B/P1')!.y).toBeLessThan(positions.get('finding-A/P1')!.y);
  });

  it('handles empty input, incomplete edges and invalid dimensions without substituting identities', async () => {
    expect(await layoutGraph({ nodes: [], edges: [] })).toEqual({ positions: [], lanes: [], width: 0, height: 0 });
    const result = await layoutGraph({ nodes: [{ id: 'only', width: -5, height: Number.NaN }], edges: [link('only', 'missing')] });
    expect(result.positions).toHaveLength(1);
    expect(result.positions[0]).toMatchObject({ id: 'only', width: LAYOUT.nodeWidth, height: LAYOUT.nodeHeight });
    await expect(layoutGraph({ nodes: [{ id: 'duplicate' }, { id: 'duplicate' }], edges: [] })).rejects.toThrow('Duplicate graph node identity');
  });
});
