import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { ArrowUpRight, FileCode2, Flag, Wrench } from 'lucide-react';
import { Background, Handle, NodeToolbar, Position, ReactFlow, getViewportForBounds, useReactFlow, useStore, type Edge, type Node, type NodeProps } from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import GraphNavigator from '../../components/graph/GraphNavigator';
import { codeRoleLabel, type CodeFile, type CodeGraphEdge, type CodeGraphNode } from './projection';

type EntityData = { item: CodeGraphNode; toolbarVisible: boolean; onInspect: (id: string) => void; onOpen: (item: CodeGraphNode) => void };
type EntityNode = Node<EntityData, 'codeEntity'>;
type SourceGroup = Node<{ file: CodeFile; count: number }, 'codeSourceGroup'>;
const NODE = { finding: { width: 252, height: 138 }, location: { width: 276, height: 90 }, repair: { width: 272, height: 154 } };

function CodeEntity({ data, selected }: NodeProps<EntityNode>) {
  const { item } = data;
  const compact = useStore(state => state.transform[2] < .7);
  const Icon = item.kind === 'finding' ? Flag : item.kind === 'repair' ? Wrench : FileCode2;
  return <div className={`cg-node cg-node-${item.kind}${compact ? ' cg-node-compact' : ''}${selected ? ' cg-node-selected' : ''}`}>
    {item.kind !== 'finding' && <Handle id="in" type="target" position={Position.Left} />}
    <div className="cg-node-kicker"><Icon size={13} aria-hidden="true"/><span>{item.label}</span>{item.kind === 'location' ? <small>{item.findingKeys.length} {item.findingKeys.length === 1 ? 'finding' : 'findings'}</small> : <small>{item.kind === 'finding' ? item.severity : item.findingId}</small>}</div>
    <strong className="cg-node-title" title={item.title}>{item.title}</strong>
    {item.kind === 'location' ? <div className="cg-node-roles">{item.roles.slice(0, 3).map(role => <span key={role} data-role={role}>{codeRoleLabel(role)}</span>)}{item.roles.length > 3 && <span>+{item.roles.length - 3}</span>}</div>
      : <div className="cg-node-caption">{item.caption}{item.kind === 'repair' && <span>{item.steps?.length ?? 0} recorded interruption links</span>}</div>}
    {item.kind !== 'repair' && <Handle id="out" type="source" position={Position.Right} />}
    <NodeToolbar isVisible={selected && data.toolbarVisible} position={Position.Top} offset={12}>
      <div className="cg-node-toolbar"><button type="button" onClick={() => data.onInspect(item.id)}>Inspect connections</button><button type="button" onClick={() => data.onOpen(item)}>{item.kind === 'location' ? 'Open citation' : 'Open finding'}<ArrowUpRight size={12}/></button></div>
    </NodeToolbar>
  </div>;
}
function FileGroup({ data }: NodeProps<SourceGroup>) {
  return <div className="cg-source-group"><div className="cg-source-heading"><span>SELECTED FILE · RECORDED RANGES</span><strong title={data.file.file}>{data.file.file.split('/').at(-1)}</strong><small>{data.count} {data.count === 1 ? 'range' : 'ranges'} in this window</small></div></div>;
}
const nodeTypes = { codeEntity: CodeEntity, codeSourceGroup: FileGroup };

/** Stable semantic columns; only the supplied explicit associations become edges. */
export function CodeCanvas({ file, graphNodes, graphEdges, selected, toolbarVisible, onSelect, onOpen }: {
  file: CodeFile; graphNodes: CodeGraphNode[]; graphEdges: CodeGraphEdge[]; selected: string;
  toolbarVisible: boolean;
  onSelect: (id: string) => void; onOpen: (node: CodeGraphNode) => void;
}) {
  const { setViewport, viewportInitialized } = useReactFlow();
  const paneWidth = useStore(state => state.width);
  const paneHeight = useStore(state => state.height);
  const [hoveredEdge, setHoveredEdge] = useState('');
  const [focusedEdge, setFocusedEdge] = useState('');
  const [rangeFraming, setRangeFraming] = useState(false);
  const layout = useMemo(() => {
    const groups = ['finding', 'location', 'repair'].map(kind => graphNodes.filter(node => node.kind === kind));
    const heights = groups.map((nodes, index) => nodes.length * (NODE[['finding', 'location', 'repair'][index] as keyof typeof NODE].height + 22) - (nodes.length ? 22 : 0));
    const height = Math.max(200, heights[0], heights[1] + 96, heights[2]);
    const groupY = (height - heights[1] - 96) / 2;
    const parentId = `code-file-group:${file.key}`;
    const nodes: Array<EntityNode | SourceGroup> = [{ id: parentId, type: 'codeSourceGroup', data: { file, count: groups[1].length },
      position: { x: 348, y: groupY }, style: { width: 324, height: heights[1] + 96 }, selectable: false, draggable: false, focusable: false, zIndex: -1 }];
    groups.forEach((items, column) => items.forEach((item, index) => {
      const size = NODE[item.kind];
      nodes.push({ id: item.id, type: 'codeEntity', data: { item, toolbarVisible, onInspect: onSelect, onOpen }, selected: item.id === selected,
        position: { x: column === 0 ? 0 : column === 1 ? 24 : 768, y: column === 1 ? 76 + index * (size.height + 22) : (height - heights[column]) / 2 + index * (size.height + 22) },
        ...(column === 1 ? { parentId, extent: 'parent' as const } : {}), width: size.width, height: size.height,
        ariaLabel: `${item.kind === 'repair' ? 'Proposed repair' : item.kind}: ${item.label}. ${item.title}. ${item.caption}` });
    }));
    return { nodes, width: groups[2].length ? 1040 : 692, height };
  }, [file, graphNodes, onOpen, onSelect, selected, toolbarVisible]);
  const layoutRef = useRef(layout);
  const selectionRef = useRef(selected);
  layoutRef.current = layout;
  selectionRef.current = selected;
  const geometryKey = JSON.stringify([file.key, graphNodes.map(node => node.id)]);
  const fitAll = useCallback(() => {
    if (!paneWidth || !paneHeight) return;
    // Keep the bottom navigation/minimap out of the graph's reading area.
    const availableHeight = Math.max(160, paneHeight - (paneWidth < 520 ? 76 : 176));
    const viewport = getViewportForBounds({ x: -20, y: -30, width: layout.width + 40, height: layout.height + 60 }, paneWidth, availableHeight, .08, 1, .08);
    setRangeFraming(false);
    void setViewport(viewport, { duration: 0 });
  }, [setViewport, layout.width, layout.height, paneWidth, paneHeight]);
  useEffect(() => {
    if (!viewportInitialized) return;
    const frame = requestAnimationFrame(() => {
      const geometry = layoutRef.current;
      const node = geometry.nodes.find(item => item.id === selectionRef.current && item.type === 'codeEntity');
      if (paneWidth < 520 && paneWidth > 0 && node) {
        const parent = node.parentId ? geometry.nodes.find(item => item.id === node.parentId) : undefined;
        const x = node.position.x + (parent?.position.x ?? 0), y = node.position.y + (parent?.position.y ?? 0);
        // A useful initial reading size on phones; Fit View still shows every connection.
        const viewport = getViewportForBounds({ x: x - 15, y: y - 25, width: (node.width ?? 276) + 30, height: (node.height ?? 90) + 50 }, paneWidth, Math.max(160, paneHeight - 76), .08, 1.1, .08);
        setRangeFraming(true);
        void setViewport(viewport, { duration: 0 });
      } else fitAll();
    });
    return () => cancelAnimationFrame(frame);
  }, [viewportInitialized, geometryKey, fitAll, paneWidth, paneHeight, setViewport]);
  const selectedEdge = graphEdges.find(edge => edge.id === selected);
  const selectedNode = graphNodes.some(node => node.id === selected);
  const labelledEdge = hoveredEdge || focusedEdge || selectedEdge?.id;
  const edges: Edge[] = graphEdges.map(edge => {
    const incident = edge.id === selected || edge.source === selected || edge.target === selected;
    return { id: edge.id, source: edge.source, target: edge.target, sourceHandle: 'out', targetHandle: 'in',
    type: 'smoothstep', selected: edge.id === selected, focusable: true, interactionWidth: 24,
    className: incident ? 'cg-edge-incident' : selectedNode || selectedEdge ? 'cg-edge-background' : '',
    label: edge.id === labelledEdge ? edge.kind === 'citation' ? edge.associations.some(item => item.role === 'root_cause') ? 'Root cause' : edge.associations.some(item => item.role === 'trace') ? 'Assessed trace' : 'Cites location' : edge.kind === 'repair' ? 'Change here' : 'Supports repair' : undefined,
    ariaLabel: `${edge.findingId}: ${edge.label}. Recorded association; select for original evidence.`,
    style: { stroke: incident ? 'var(--primary-text)' : edge.kind === 'repair' ? 'var(--graph-repair)' : 'var(--graph-edge)', strokeWidth: edge.id === selected ? 2.8 : incident ? 2 : 1.35,
      opacity: incident || (!selectedNode && !selectedEdge) ? 1 : .88,
      strokeDasharray: edge.kind === 'repair' ? '6 4' : edge.kind === 'repair_evidence' ? '2 4' : undefined },
    labelStyle: { fill: 'var(--text)', fontSize: 10, fontWeight: 500 }, labelBgStyle: { fill: 'var(--panel)' }, labelBgPadding: [6, 4], labelBgBorderRadius: 4,
  }; });
  const selectedIds = selectedEdge ? [selectedEdge.source, selectedEdge.target] : graphNodes.some(node => node.id === selected) ? [selected] : [];
  return <div className="cg-canvas" aria-label="Interactive code relationship graph" data-framing={rangeFraming ? 'range' : 'all'}
    onKeyDownCapture={event => {
      if (!['Enter', ' '].includes(event.key)) return;
      const target = event.target as Element;
      const node = target.closest?.('.react-flow__node-codeEntity');
      // React Flow need not emit a new selection when its default-selected node
      // is activated. Explicit keyboard activation still reveals its toolbar.
      const id = node?.getAttribute('data-id');
      if (target === node && id && graphNodes.some(item => item.id === id)) onSelect(id);
    }}
    onFocusCapture={event => setFocusedEdge((event.target as Element).closest?.('.react-flow__edge')?.getAttribute('data-id') ?? '')}
    onBlurCapture={event => { if ((event.target as Element).closest?.('.react-flow__edge')) setFocusedEdge(''); }}>
    {rangeFraming && <div className="cg-range-focus-note">Range detail <span>Use Fit View for all connections</span></div>}
    <ReactFlow nodes={layout.nodes} edges={edges} nodeTypes={nodeTypes} minZoom={.08} maxZoom={2}
      nodesDraggable={false} nodesConnectable={false} deleteKeyCode={null} edgesReconnectable={false}
      onNodeClick={(_, node) => { if (node.type === 'codeEntity') onSelect(node.id); }}
      onEdgeMouseEnter={(_, edge) => setHoveredEdge(edge.id)} onEdgeMouseLeave={() => setHoveredEdge('')}
      onNodesChange={changes => { const change = changes.find(change => change.type === 'select' && change.selected); if (change?.type === 'select' && change.id !== selected) onSelect(change.id); }}
      onEdgesChange={changes => { const change = changes.find(change => change.type === 'select' && change.selected); if (change?.type === 'select' && change.id !== selected) onSelect(change.id); }}>
      <Background color="var(--graph-grid)" gap={24} size={1}/>
      <GraphNavigator nodeCount={graphNodes.length} edgeCount={graphEdges.length} selectedIds={selectedIds} onFitAll={fitAll} label="Code map navigation"/>
    </ReactFlow>
  </div>;
}
