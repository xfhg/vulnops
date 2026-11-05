import { useCallback, useEffect, useState } from 'react';
import { Background, BaseEdge, EdgeLabelRenderer, Handle, NodeToolbar, Panel, Position, ReactFlow, getSmoothStepPath, useReactFlow, useStore, type Edge, type EdgeProps, type Node, type NodeProps } from '@xyflow/react';
import { ArrowUpRight, Crosshair, GitBranch, Route, ShieldAlert } from 'lucide-react';
import GraphNavigator from '../../components/graph/GraphNavigator';
import { connectionContext } from './connections';

export type NodeData = {
  kind: 'entrypoint' | 'finding' | 'primitive'; title: string; caption: string; label: string; status: string;
  eyebrow?: string; shared?: boolean; unassigned?: boolean; input?: string;
  facts?: Array<{ label: string; value: number | string }>; onOpen?: () => void;
};
export type OverviewGraphNode = { id: string; data: NodeData; laneId: string; column?: 0 | 1 };
export type OverviewLane = { id: string; title: string; subtitle: string; detail: string; selectionId?: string };
type Layout = { positions: Array<{ id: string; x: number; y: number }>; lanes: Array<{ id: string; x: number; y: number; width: number; height: number }>; width: number; height: number };
const nodeWidth = 320;
const nodeHeight = 268;
const positionCache = new Map<string, Layout>();
const compactZoom = (state: { transform: [number, number, number] }) => state.transform[2] < .55;

function OverviewNode({ id, data, selected }: NodeProps) {
  const item = data as NodeData & { onFocus: (id: string) => void };
  const compact = useStore(compactZoom);
  const Icon = item.kind === 'entrypoint' ? Route : item.kind === 'primitive' ? GitBranch : ShieldAlert;
  return <><NodeToolbar isVisible={selected} position={Position.Top} className="ep-node-toolbar">
    <button onClick={() => item.onFocus(id)}><Crosshair size={13} />Focus connections</button>
    {item.onOpen && <button onClick={item.onOpen}>Open finding<ArrowUpRight size={13} /></button>}
  </NodeToolbar><div className={`ep-node ep-node-${item.kind} ${item.shared ? 'ep-node-shared' : ''} ${compact ? 'ep-node-compact' : ''}`}>
    {item.kind !== 'entrypoint' && <Handle type="target" position={Position.Left} id="in" />}
    <div className="ep-node-kicker"><span><Icon size={13} />{item.eyebrow || (item.kind === 'entrypoint' ? 'ENTRYPOINT' : item.unassigned ? 'UNASSIGNED' : 'FINDING')}</span><span>{item.label}</span></div>
    {item.kind === 'primitive' && <div className="ep-capability-input" title={item.input || 'Input capability not recorded'}><span>REQUIRES</span><p>{item.input || 'Input capability not recorded'}</p></div>}
    {item.kind === 'primitive' && <span className="ep-capability-label">GRANTS</span>}
    <strong className="ep-node-title" title={item.title}>{item.title}</strong>
    <p className="ep-node-caption" title={item.caption}>{item.caption}</p>
    {!!item.facts?.length && <div className="ep-node-facts">{item.facts.map(fact => <span key={fact.label}><b>{fact.value}</b>{fact.label}</span>)}</div>}
    <span className="ep-node-status" title={item.status}>{item.status}</span>
    {item.kind !== 'finding' && <Handle type="source" position={Position.Right} id="out" />}
  </div></>;
}
function ContextGroup({ data }: NodeProps) {
  const lane = data.lane as OverviewLane;
  return <div className={`ep-graph-lane ${data.active ? 'active' : ''}`} data-lane-id={lane.id}>
    <button type="button" className="ep-lane-heading nodrag nopan" title={lane.detail} onClick={() => (data.onFocus as () => void)()}>
      <span>{lane.subtitle}</span><strong>{lane.title}</strong><small>{lane.detail}</small>
    </button>
  </div>;
}
function RelationshipEdge(props: EdgeProps) {
  const [path, x, y] = getSmoothStepPath({ ...props, borderRadius: 14 });
  const compact = useStore(compactZoom);
  const data = props.data as { onSelect?: (id: string) => void; detail?: string; dimmed?: boolean } | undefined;
  return <><BaseEdge id={props.id} path={path} markerEnd={props.markerEnd} style={props.style} interactionWidth={24} />
    {(!compact || props.selected) && <EdgeLabelRenderer><button className={`ep-relation-label nodrag nopan ${props.selected ? 'active' : ''} ${data?.dimmed ? 'is-dimmed' : ''}`}
      style={{ transform: `translate(-50%, -50%) translate(${x}px,${y}px)` }} title={data?.detail || String(props.label)}
      onClick={() => data?.onSelect?.(props.id)} aria-label={`Inspect ${String(props.label)} relationship`}>
      {props.label}{props.selected && data?.detail && <small>{data.detail}</small>}
    </button></EdgeLabelRenderer>}</>;
}
const nodeTypes = { overview: OverviewNode, context: ContextGroup };
const edgeTypes = { relationship: RelationshipEdge };

export default function OverviewCanvas({ graphNodes, edges, lanes, placement = 'topology', selected, onSelect, label }: {
  graphNodes: OverviewGraphNode[]; edges: Edge[]; lanes: OverviewLane[]; placement?: 'topology' | 'bipartite';
  selected: string; onSelect: (id: string) => void; label: string;
}) {
  const { fitBounds, fitView, viewportInitialized } = useReactFlow();
  const [layout, setLayout] = useState<Layout | null>(null);
  const [layoutError, setLayoutError] = useState('');
  const [readyLayout, setReadyLayout] = useState('');
  const [spotlight, setSpotlight] = useState(false);
  const layoutKey = JSON.stringify([placement, graphNodes.map(node => [node.id, node.laneId, node.column]), lanes.map(lane => lane.id), edges.map(edge => [edge.id, edge.source, edge.target])]);
  useEffect(() => {
    setLayoutError('');
    const cached = positionCache.get(layoutKey);
    if (cached) { setLayout(cached); setReadyLayout(layoutKey); return; }
    let worker: Worker;
    try { worker = new Worker(new URL('../attack-explorer/layout.worker.ts', import.meta.url), { type: 'module' }); }
    catch { setLayoutError('Automatic layout is unavailable. Every relationship remains in the linear view.'); return; }
    worker.onmessage = event => {
      if (event.data.requestId !== layoutKey) return;
      if (event.data.error) { setLayoutError(String(event.data.error)); return; }
      const next = event.data as Layout;
      if (positionCache.size >= 12) positionCache.delete(positionCache.keys().next().value!);
      positionCache.set(layoutKey, next); setLayout(next); setReadyLayout(layoutKey);
    };
    worker.onerror = () => setLayoutError('Automatic layout is unavailable. Every relationship remains in the linear view.');
    worker.postMessage({ nodes: graphNodes.map(({ id, laneId, column }, order) => ({ id, laneId, column, order, width: nodeWidth, height: nodeHeight })),
      edges: edges.map(({ id, source, target }) => ({ id, source, target })), lanes: lanes.map(({ id }, order) => ({ id, order })), placement, requestId: layoutKey });
    return () => worker.terminate();
  }, [layoutKey]);
  const fitAll = useCallback(() => {
    if (layout && readyLayout === layoutKey) void fitBounds({ x: -25, y: -30, width: layout.width + 50, height: layout.height + 60 }, { padding: .09, duration: 0 });
  }, [layout, readyLayout, layoutKey, fitBounds]);
  useEffect(() => {
    if (!viewportInitialized) return;
    const frame = requestAnimationFrame(fitAll);
    return () => cancelAnimationFrame(frame);
  }, [fitAll, viewportInitialized]);
  const context = connectionContext(graphNodes.map(node => node.id), edges, selected);
  const focusConnections = (id: string) => {
    onSelect(id); setSpotlight(true);
    const related = connectionContext(graphNodes.map(node => node.id), edges, id);
    void fitView({ nodes: [...related.nodes].map(id => ({ id })), padding: .25, minZoom: .05, maxZoom: 1.1, duration: 0 });
  };
  const coordinates = new Map(layout?.positions.map(position => [position.id, position]));
  const boundsMap = new Map(layout?.lanes.map(bounds => [bounds.id, bounds]));
  const selectedEdge = edges.find(edge => edge.id === selected);
  const selectedLane = graphNodes.find(node => node.id === selected || node.id === selectedEdge?.source)?.laneId ?? lanes.find(lane => lane.selectionId === selected)?.id;
  const focusLane = layout?.lanes.find(lane => lane.id === selectedLane);
  // Parent nodes precede their children; display groups confer no additional evidence.
  const parents: Node[] = readyLayout === layoutKey ? (layout?.lanes ?? []).map(bounds => ({
    id: JSON.stringify(['display-context', bounds.id]), type: 'context', position: { x: bounds.x, y: bounds.y },
    width: bounds.width, height: bounds.height, style: { width: bounds.width, height: bounds.height }, selectable: false, focusable: false, zIndex: -1,
    data: { lane: lanes.find(lane => lane.id === bounds.id)!, active: selectedLane === bounds.id, onFocus: () => {
      const lane = lanes.find(lane => lane.id === bounds.id);
      if (lane?.selectionId) onSelect(lane.selectionId);
      void fitBounds(bounds, { padding: .12, duration: 0 });
    } },
  })) : [];
  const nodes: Node[] = graphNodes.map((node, index) => {
    const position = coordinates.get(node.id) ?? { x: (index % 3) * 400, y: Math.floor(index / 3) * 280 };
    const bounds = readyLayout === layoutKey ? boundsMap.get(node.laneId) : undefined;
    return { id: node.id, data: { ...node.data, onFocus: focusConnections }, type: 'overview', selected: node.id === selected,
      position: { x: position.x - (bounds?.x ?? 0), y: position.y - (bounds?.y ?? 0) },
      ...(bounds ? { parentId: JSON.stringify(['display-context', node.laneId]), extent: 'parent' as const } : {}),
      className: spotlight && context.nodes.size && !context.nodes.has(node.id) ? 'ep-context-muted' : '',
      width: nodeWidth, height: nodeHeight, ariaLabel: `${node.data.kind}: ${node.data.title}. ${node.data.label}. ${node.data.status}` };
  });
  const renderedEdges: Edge[] = edges.map(edge => ({ ...edge, type: 'relationship', sourceHandle: 'out', targetHandle: 'in', selected: edge.id === selected,
    data: { ...edge.data, onSelect, dimmed: !!(spotlight && context.nodes.size && !context.edges.has(edge.id)) },
    style: { ...edge.style, ...(context.edges.has(edge.id) ? { stroke: 'var(--primary-text)', strokeWidth: 2.4 } : {}),
      ...(spotlight && context.nodes.size && !context.edges.has(edge.id) ? { opacity: .18 } : {}) },
  }));
  return <div className="ep-canvas" aria-label={label} data-layout-status={layoutError ? 'unavailable' : readyLayout === layoutKey ? 'ready' : 'pending'}>
    {layoutError && <p role="status" className="ep-layout-message">{layoutError}</p>}
    {!layoutError && readyLayout !== layoutKey && <p role="status" className="ep-layout-progress">Arranging recorded relationships…</p>}
    <ReactFlow nodes={[...parents, ...nodes]} edges={renderedEdges} nodeTypes={nodeTypes} edgeTypes={edgeTypes} minZoom={.005} maxZoom={1.7}
      nodesDraggable={false} nodesConnectable={false} deleteKeyCode={null}
      onNodesChange={changes => { const change = changes.find(change => change.type === 'select' && change.selected); if (change?.type === 'select' && change.id !== selected) onSelect(change.id); }}
      onEdgesChange={changes => { const change = changes.find(change => change.type === 'select' && change.selected); if (change?.type === 'select' && change.id !== selected) onSelect(change.id); }}>
      <Background gap={24} size={1} color="var(--graph-grid)" />
      <GraphNavigator nodeCount={graphNodes.length} edgeCount={edges.length} selectedIds={[...context.nodes]} onFitAll={fitAll} label={label} />
      <Panel position="top-left" className="ep-context-controls"><span>{placement === 'bipartite' ? 'ENTRYPOINT → FINDING' : 'INPUT → CAPABILITY → IMPACT'}</span>
        {context.nodes.size > 0 && <button aria-pressed={spotlight} onClick={() => setSpotlight(value => !value)}>{spotlight ? 'Show all context' : 'Highlight connections'} <b>{context.edges.size}</b></button>}
        {focusLane && <button onClick={() => void fitBounds(focusLane, { padding: .12, duration: 0 })}>Focus selected group</button>}
      </Panel>
    </ReactFlow>
  </div>;
}
