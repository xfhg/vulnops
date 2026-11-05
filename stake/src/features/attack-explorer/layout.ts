import ELK, { type ELK as ElkInstance, type ElkNode } from 'elkjs/lib/elk.bundled.js';

export type Placement = 'sequence' | 'topology' | 'bipartite';
export interface LayoutNode {
  id: string;
  width?: number;
  height?: number;
  /** Explicit priority, with input position as the stable tie-breaker. */
  order?: number;
  laneId?: string;
  column?: 0 | 1;
}
export interface LayoutEdge { id: string; source: string; target: string }
export interface LayoutLane { id: string; order?: number }
export interface LayoutRequest {
  nodes: LayoutNode[];
  edges: LayoutEdge[];
  placement?: Placement;
  lanes?: LayoutLane[];
  requestId?: string;
}
export interface LayoutPosition { id: string; x: number; y: number; width: number; height: number; laneId?: string }
export interface LaneBounds { id: string; x: number; y: number; width: number; height: number }
export interface LayoutResult { positions: LayoutPosition[]; lanes: LaneBounds[]; width: number; height: number }

export const LAYOUT = {
  nodeWidth: 268, nodeHeight: 172, nodeGap: 32, layerGap: 96,
  laneHeader: 72, lanePadding: 20, laneGap: 28,
} as const;

type SizedNode = LayoutNode & { width: number; height: number; inputIndex: number };
type LocalLayout = { positions: LayoutPosition[]; width: number; height: number };
const positive = (value: number | undefined, fallback: number) => value !== undefined && Number.isFinite(value) && value > 0 ? value : fallback;
const priority = (value: number | undefined, fallback: number) => value !== undefined && Number.isFinite(value) ? value : fallback;
const compareText = (left: string, right: string) => left < right ? -1 : left > right ? 1 : 0;

/** Original procedure/trace order is geometric authority, independently of edge packing. */
function sequenceLayout(nodes: SizedNode[]): LocalLayout {
  let x = 0;
  const height = Math.max(0, ...nodes.map(node => node.height));
  const positions = nodes.map(node => {
    const position = { id: node.id, x, y: (height - node.height) / 2, width: node.width, height: node.height };
    x += node.width + LAYOUT.layerGap;
    return position;
  });
  return { positions, width: Math.max(0, x - LAYOUT.layerGap), height };
}

/** Association columns preserve the caller's semantic ordering; no edges are inferred. */
function bipartiteLayout(nodes: SizedNode[]): LocalLayout {
  const columns = [nodes.filter(node => node.column !== 1), nodes.filter(node => node.column === 1)];
  const widths = columns.map(column => Math.max(0, ...column.map(node => node.width)));
  const positions: LayoutPosition[] = [];
  const heights = columns.map((column, index) => {
    let y = 0;
    const x = index === 1 && columns[0].length ? widths[0] + LAYOUT.layerGap : 0;
    for (const node of column) {
      positions.push({ id: node.id, x, y, width: node.width, height: node.height });
      y += node.height + LAYOUT.nodeGap;
    }
    return Math.max(0, y - LAYOUT.nodeGap);
  });
  return { positions, width: widths[0] + widths[1] + (columns.every(column => column.length) ? LAYOUT.layerGap : 0), height: Math.max(...heights) };
}

/** Stable weak components keep disconnected records without allowing ELK to repack their order. */
function connectedParts(nodes: SizedNode[], edges: LayoutEdge[]): SizedNode[][] {
  const neighbors = new Map(nodes.map(node => [node.id, new Set<string>()]));
  for (const edge of edges) {
    if (!neighbors.has(edge.source) || !neighbors.has(edge.target)) continue;
    neighbors.get(edge.source)!.add(edge.target);
    neighbors.get(edge.target)!.add(edge.source);
  }
  const visited = new Set<string>();
  const parts: SizedNode[][] = [];
  for (const node of nodes) {
    if (visited.has(node.id)) continue;
    const queue = [node.id];
    const members = new Set<string>();
    for (let i = 0; i < queue.length; i++) {
      const id = queue[i];
      if (visited.has(id)) continue;
      visited.add(id); members.add(id);
      for (const neighbor of neighbors.get(id)!) if (!visited.has(neighbor)) queue.push(neighbor);
    }
    parts.push(nodes.filter(node => members.has(node.id)));
  }
  return parts;
}

/** Stable SCC ordering preserves real DAG direction even when model order lists consumers first. */
function topologicalModelOrder(nodes: SizedNode[], edges: LayoutEdge[]): SizedNode[] {
  const rank = new Map(nodes.map((node, index) => [node.id, index]));
  const outgoing = new Map(nodes.map(node => [node.id, new Set<string>()]));
  const incoming = new Map(nodes.map(node => [node.id, new Set<string>()]));
  for (const edge of edges) if (rank.has(edge.source) && rank.has(edge.target)) {
    outgoing.get(edge.source)!.add(edge.target);
    incoming.get(edge.target)!.add(edge.source);
  }
  const neighbors = new Map([...outgoing].map(([id, values]) => [id, [...values].sort((a, b) => rank.get(a)! - rank.get(b)!)]));
  const visited = new Set<string>();
  const finished: string[] = [];
  for (const node of nodes) {
    if (visited.has(node.id)) continue;
    const stack = [{ id: node.id, next: 0 }];
    visited.add(node.id);
    while (stack.length) {
      const frame = stack[stack.length - 1];
      const children = neighbors.get(frame.id)!;
      if (frame.next === children.length) { finished.push(frame.id); stack.pop(); continue; }
      const child = children[frame.next++];
      if (!visited.has(child)) { visited.add(child); stack.push({ id: child, next: 0 }); }
    }
  }
  const componentFor = new Map<string, number>();
  const components: string[][] = [];
  for (const id of finished.reverse()) {
    if (componentFor.has(id)) continue;
    const component = components.length;
    const members: string[] = [];
    const stack = [id];
    componentFor.set(id, component);
    while (stack.length) {
      const current = stack.pop()!;
      members.push(current);
      for (const previous of incoming.get(current)!) if (!componentFor.has(previous)) { componentFor.set(previous, component); stack.push(previous); }
    }
    components.push(members.sort((a, b) => rank.get(a)! - rank.get(b)!));
  }
  const dependencies = components.map(() => 0);
  const successors = components.map(() => new Set<number>());
  for (const edge of edges) {
    const source = componentFor.get(edge.source);
    const target = componentFor.get(edge.target);
    if (source === undefined || target === undefined || source === target || successors[source].has(target)) continue;
    successors[source].add(target); dependencies[target]++;
  }
  const byPriority = (a: number, b: number) => rank.get(components[a][0])! - rank.get(components[b][0])!;
  const pending = components.map((_, index) => index).filter(index => dependencies[index] === 0).sort(byPriority);
  const ordered: string[] = [];
  while (pending.length) {
    const component = pending.shift()!;
    ordered.push(...components[component]);
    for (const next of successors[component]) {
      dependencies[next]--;
      if (dependencies[next] === 0) pending.push(next);
    }
    pending.sort(byPriority);
  }
  const nodeMap = new Map(nodes.map(node => [node.id, node]));
  return ordered.map(id => nodeMap.get(id)!);
}

/** ELK handles actual branch/cycle topology; caller order fixes all model-order tie-breaks. */
async function topologyLayout(nodes: SizedNode[], edges: LayoutEdge[], elk: ElkInstance): Promise<LocalLayout> {
  const positions: LayoutPosition[] = [];
  const rank = new Map(nodes.map((node, index) => [node.id, index]));
  const orderedEdges = edges.filter(edge => rank.has(edge.source) && rank.has(edge.target)).slice().sort((left, right) =>
    rank.get(left.source)! - rank.get(right.source)! || rank.get(left.target)! - rank.get(right.target)! || compareText(left.id, right.id));
  let nextX = 0;
  let height = 0;
  for (const part of connectedParts(nodes, orderedEdges)) {
    const ids = new Set(part.map(node => node.id));
    const partEdges = orderedEdges.filter(edge => ids.has(edge.source) && ids.has(edge.target));
    const modelNodes = topologicalModelOrder(part, partEdges);
    const graph = await elk.layout<ElkNode>({
      id: 'recorded-topology',
      layoutOptions: {
        'elk.algorithm': 'layered', 'elk.direction': 'RIGHT', 'elk.randomSeed': '1',
        'elk.padding': '[top=0,left=0,bottom=0,right=0]',
        'elk.spacing.nodeNode': String(LAYOUT.nodeGap),
        'elk.layered.spacing.nodeNodeBetweenLayers': String(LAYOUT.layerGap),
        'elk.separateConnectedComponents': 'false',
        'elk.layered.considerModelOrder.strategy': 'NODES_AND_EDGES',
        'elk.layered.crossingMinimization.forceNodeModelOrder': 'true',
        'elk.layered.cycleBreaking.strategy': 'MODEL_ORDER',
      },
      children: modelNodes.map(node => ({ id: node.id, width: node.width, height: node.height })),
      edges: partEdges.map(edge => ({ id: edge.id, sources: [edge.source], targets: [edge.target] })),
    });
    const placed = new Map((graph.children ?? []).map(node => [node.id, node]));
    let partWidth = 0;
    let partHeight = 0;
    for (const node of part) {
      const position = placed.get(node.id);
      if (!position || !Number.isFinite(position.x) || !Number.isFinite(position.y)) throw new Error('Recorded graph node could not be placed.');
      const x = position.x!;
      const y = position.y!;
      positions.push({ id: node.id, x: nextX + x, y, width: node.width, height: node.height });
      partWidth = Math.max(partWidth, x + node.width);
      partHeight = Math.max(partHeight, y + node.height);
    }
    nextX += partWidth + LAYOUT.layerGap;
    height = Math.max(height, partHeight);
  }
  return { positions, width: Math.max(0, nextX - LAYOUT.layerGap), height };
}

/**
 * Produces geometry only: this helper never creates, removes or rewrites caller edges.
 * Explicit lanes are presentation groups. Their headers/padding have no evidence meaning.
 * Edges spanning lanes remain caller-owned and do not reorder the declared lanes.
 */
export async function layoutGraph(request: LayoutRequest, elk: ElkInstance = new ELK()): Promise<LayoutResult> {
  if (!request.nodes.length) return { positions: [], lanes: [], width: 0, height: 0 };
  const seen = new Set<string>();
  const nodes: SizedNode[] = request.nodes.map((node, inputIndex) => {
    if (seen.has(node.id)) throw new Error('Duplicate graph node identity.');
    seen.add(node.id);
    return { ...node, width: positive(node.width, LAYOUT.nodeWidth), height: positive(node.height, LAYOUT.nodeHeight), inputIndex };
  }).sort((left, right) => priority(left.order, left.inputIndex) - priority(right.order, right.inputIndex) || left.inputIndex - right.inputIndex);
  const explicitLanes = Boolean(request.lanes?.length || nodes.some(node => node.laneId !== undefined));
  const laneOrder = new Map<string, { id: string; order: number; index: number }>();
  for (const lane of request.lanes ?? []) if (!laneOrder.has(lane.id)) {
    const index = laneOrder.size;
    laneOrder.set(lane.id, { id: lane.id, order: priority(lane.order, index), index });
  }
  for (const node of nodes) {
    const id = node.laneId ?? '';
    if (!laneOrder.has(id)) { const index = laneOrder.size; laneOrder.set(id, { id, order: index, index }); }
  }
  const lanes = [...laneOrder.values()].sort((left, right) => left.order - right.order || left.index - right.index);
  const bounds: LaneBounds[] = [];
  const positions: LayoutPosition[] = [];
  const padding = explicitLanes ? LAYOUT.lanePadding : 0;
  const header = explicitLanes ? LAYOUT.laneHeader : 0;
  let nextY = 0;
  let width = 0;
  for (const lane of lanes) {
    const members = nodes.filter(node => (node.laneId ?? '') === lane.id);
    if (!members.length) continue;
    const ids = new Set(members.map(node => node.id));
    const edges = request.edges.filter(edge => ids.has(edge.source) && ids.has(edge.target));
    const layout = request.placement === 'sequence' ? sequenceLayout(members)
      : request.placement === 'bipartite' ? bipartiteLayout(members) : await topologyLayout(members, edges, elk);
    const laneWidth = layout.width + padding * 2;
    const laneHeight = layout.height + header + padding * 2;
    if (explicitLanes) bounds.push({ id: lane.id, x: 0, y: nextY, width: laneWidth, height: laneHeight });
    positions.push(...layout.positions.map(position => ({ ...position, x: position.x + padding, y: position.y + nextY + header + padding,
      ...(explicitLanes ? { laneId: lane.id } : {}) })));
    width = Math.max(width, laneWidth);
    nextY += laneHeight + LAYOUT.laneGap;
  }
  const positionMap = new Map(positions.map(position => [position.id, position]));
  return { positions: request.nodes.map(node => positionMap.get(node.id)!), lanes: bounds, width, height: Math.max(0, nextY - LAYOUT.laneGap) };
}
