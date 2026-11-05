import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { ArrowUpRight, ChevronLeft, ChevronRight, FileCode2, FileText, Flag, GitBranch, Layers3, ListChecks, Wrench } from 'lucide-react';
import {
  Background, Handle, NodeToolbar, Position, ReactFlow, getViewportForBounds, useReactFlow, useStore,
  type Edge, type Node, type NodeProps,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import GraphNavigator from '../../components/graph/GraphNavigator';
import type { RepairGraph, RepairNode } from './model';
import './repair-canvas.css';

export interface RepairCanvasProps {
  graph: RepairGraph;
  selected: string;
  onSelect: (id: string) => void;
  onOpen: (node: RepairNode) => void;
}

type Layer = 'targets' | 'interruptions' | 'context';
type Group = Layer | 'action';
type RecordData = { item: RepairNode; toolbar: boolean; onSelect: (id: string) => void; onOpen: (node: RepairNode) => void };
type RecordNode = Node<RecordData, 'repairRecord'>;
type GroupNode = Node<{ title: string; description: string; count: string; group: Group }, 'context'>;
const PAGE_SIZE = 3;
const GAP = 22, PADDING = 18, HEADER = 68;
const layerOrder: Layer[] = ['targets', 'interruptions', 'context'];
const labels: Record<Group, string> = { action: 'Proposed change', targets: 'Repair targets', interruptions: 'Steps and examples', context: 'Finding context' };
const descriptions: Record<Group, string> = {
  action: 'Action scope · recommendation', targets: 'Recorded source and component links',
  interruptions: 'Explicit procedure and example IDs', context: 'Finding-level checks and guidance · not action-specific',
};
const kindLabels: Record<RepairNode['kind'], string> = {
  finding: 'Finding', action: 'Proposed repair', location: 'Source location', component: 'Component',
  step: 'Procedure step', example: 'Example', check: 'Finding-level check', guidance: 'Finding-level guidance',
};
const sizes: Record<RepairNode['kind'], { width: number; height: number }> = {
  action: { width: 292, height: 196 }, finding: { width: 264, height: 122 },
  location: { width: 264, height: 102 }, component: { width: 264, height: 116 },
  step: { width: 264, height: 140 }, example: { width: 264, height: 116 },
  check: { width: 264, height: 132 }, guidance: { width: 264, height: 132 },
};
const human = (value: string) => value.replaceAll('_', ' ').replaceAll('-', ' ');

export function repairLayer(item: RepairNode): Group {
  if (item.kind === 'action') return 'action';
  if (item.scope === 'finding' || ['finding', 'check', 'guidance'].includes(item.kind)) return 'context';
  return item.kind === 'location' || item.kind === 'component' ? 'targets' : 'interruptions';
}

function RepairRecord({ data, selected }: NodeProps<RecordNode>) {
  const { item } = data;
  const compact = useStore(state => state.transform[2] < .55);
  const sourcePath = item.kind === 'location' ? item.file || item.title : '';
  const sourceParts = sourcePath.split('/');
  const title = item.kind === 'location' && item.file ? sourceParts.at(-1) || sourcePath : item.title;
  const caption = item.kind === 'location' && item.file ? sourceParts.slice(0, -1).join('/') || 'Source root' : item.caption;
  const coordinate = item.line == null ? 'File-level target'
    : `${item.endLine != null && item.endLine !== item.line ? 'Lines' : 'Line'} ${item.line}${item.endLine != null && item.endLine !== item.line ? `–${item.endLine}` : ''}`;
  const Icon = item.kind === 'action' ? Wrench : item.kind === 'location' ? FileCode2 : item.kind === 'component' ? Layers3
    : item.kind === 'step' ? GitBranch : item.kind === 'check' ? ListChecks : item.kind === 'finding' ? Flag : FileText;
  return <div className={`rc-record rc-record-${item.kind}${selected ? ' rc-record-selected' : ''}${compact ? ' rc-record-compact' : ''}${item.unavailable ? ' rc-record-unavailable' : ''}`}>
    {(['Left', 'Right', 'Top', 'Bottom'] as const).flatMap(side => [
      <Handle key={`in-${side}`} id={`in-${side.toLowerCase()}`} type="target" position={Position[side]} />,
      <Handle key={`out-${side}`} id={`out-${side.toLowerCase()}`} type="source" position={Position[side]} />,
    ])}
    <div className="rc-record-kicker"><Icon size={13} aria-hidden="true" /><span>{kindLabels[item.kind]}</span><small>{item.localId}</small></div>
    <strong className="rc-record-title" title={item.title}>{title}</strong>
    <p className="rc-record-caption" title={item.kind === 'location' ? sourcePath : item.caption}>{caption}</p>
    <div className="rc-record-footer"><span>{item.unavailable ? 'Referenced record unavailable' : item.kind === 'location' ? coordinate : item.kind === 'action' ? 'Recommendation only' : item.status && item.status !== 'not_recorded' ? human(item.status) : 'Status not recorded'}</span>
      {item.evidence.length > 0 && <small>{item.evidence.length} {item.evidence.length === 1 ? 'reference' : 'references'}</small>}</div>
    <NodeToolbar isVisible={selected && data.toolbar} position={Position.Top} offset={10}>
      <div className="rc-record-toolbar"><button type="button" onClick={() => data.onSelect(item.id)}>Inspect details</button>
        <button type="button" onClick={() => data.onOpen(item)} disabled={item.unavailable}>{item.kind === 'location' ? 'Read implementation instructions' : 'Open record'}<ArrowUpRight size={12} aria-hidden="true" /></button></div>
    </NodeToolbar>
  </div>;
}

function RepairGroup({ data }: NodeProps<GroupNode>) {
  return <div className={`rc-group rc-group-${data.group}`}><div className="rc-group-heading"><div><strong>{data.title}</strong><span>{data.description}</span></div><small>{data.count}</small></div></div>;
}
const nodeTypes = { repairRecord: RepairRecord, context: RepairGroup };

/** Geometry groups are presentation only. Supplied model edges remain the sole
 * relationship authority, including finding→check rather than action→check. */
export function repairGeometry(entryKey: string, records: RepairNode[]) {
  const grouped = Object.fromEntries((['action', ...layerOrder] as Group[]).map(group => [group, records.filter(item => repairLayer(item) === group)])) as Record<Group, RepairNode[]>;
  const stackHeight = (items: RepairNode[]) => HEADER + PADDING + items.reduce((height, item) => height + sizes[item.kind].height, 0) + Math.max(0, items.length - 1) * GAP;
  const height = Math.max(stackHeight(grouped.action), stackHeight(grouped.targets), stackHeight(grouped.interruptions), 240);
  const groups: Array<{ id: string; group: Group; position: { x: number; y: number }; width: number; height: number; records: Array<{ item: RepairNode; position: { x: number; y: number }; width: number; height: number }> }> = [];
  const columns: Group[] = ['targets', 'action', 'interruptions'];
  columns.forEach((group, column) => {
    const items = grouped[group]; if (!items.length) return;
    const groupHeight = stackHeight(items);
    const width = Math.max(...items.map(item => sizes[item.kind].width)) + PADDING * 2;
    let y = HEADER;
    groups.push({ id: JSON.stringify(['repair-presentation-group', entryKey, group]), group,
      position: { x: column * 430, y: (height - groupHeight) / 2 }, width, height: groupHeight,
      records: items.map(item => { const position = { x: PADDING, y }; y += sizes[item.kind].height + GAP; return { item, position, ...sizes[item.kind] }; }),
    });
  });
  if (grouped.context.length) {
    let x = PADDING;
    const items = grouped.context.map(item => { const position = { x, y: HEADER }; x += sizes[item.kind].width + GAP; return { item, position, ...sizes[item.kind] }; });
    const width = x - GAP + PADDING;
    const contextHeight = HEADER + Math.max(...grouped.context.map(item => sizes[item.kind].height)) + PADDING;
    groups.push({ id: JSON.stringify(['repair-presentation-group', entryKey, 'context']), group: 'context', position: { x: 0, y: height + 62 }, width, height: contextHeight, records: items });
  }
  const minX = groups.length ? Math.min(...groups.map(group => group.position.x)) : 0;
  return { groups, bounds: { x: minX, y: 0,
    width: Math.max(1, ...groups.map(group => group.position.x + group.width)) - minX,
    height: Math.max(1, ...groups.map(group => group.position.y + group.height)),
  } };
}

export default function RepairCanvas({ graph, selected, onSelect, onOpen }: RepairCanvasProps) {
  const { setViewport, viewportInitialized } = useReactFlow();
  const paneWidth = useStore(state => state.width), paneHeight = useStore(state => state.height);
  const [enabled, setEnabled] = useState<Record<Layer, boolean>>({ targets: true, interruptions: true, context: false });
  const [pages, setPages] = useState<Record<Layer, number>>({ targets: 0, interruptions: 0, context: 0 });
  const [toolbarId, setToolbarId] = useState('');
  const [recordFraming, setRecordFraming] = useState(false);
  const layers = useMemo(() => Object.fromEntries(layerOrder.map(layer => [layer, graph.nodes.filter(node => repairLayer(node) === layer && node.kind !== 'finding')])) as Record<Layer, RepairNode[]>, [graph.nodes]);
  const findingContext = graph.nodes.filter(node => node.kind === 'finding');
  const reveal = useCallback((id: string) => {
    const edge = graph.edges.find(item => item.id === id);
    const ids = edge ? [edge.source, edge.target] : [id];
    const nextEnabled: Partial<Record<Layer, boolean>> = {}, nextPages: Partial<Record<Layer, number>> = {};
    for (const recordId of ids) {
      const record = graph.nodes.find(item => item.id === recordId); if (!record) continue;
      const layer = repairLayer(record); if (layer === 'action') continue;
      nextEnabled[layer] = true;
      const index = layers[layer].findIndex(item => item.id === recordId);
      if (index >= 0) nextPages[layer] = Math.floor(index / PAGE_SIZE);
    }
    setEnabled(previous => ({ ...previous, ...nextEnabled }));
    setPages(previous => ({ ...previous, ...nextPages }));
  }, [graph.edges, graph.nodes, layers]);
  useEffect(() => { if (selected) reveal(selected); }, [selected, graph.entry.key]);
  const visible = useMemo(() => graph.nodes.filter(item => {
    const layer = repairLayer(item); if (layer === 'action') return true;
    if (!enabled[layer]) return false;
    if (item.kind === 'finding') return true;
    const page = Math.min(pages[layer], Math.max(0, Math.ceil(layers[layer].length / PAGE_SIZE) - 1));
    return layers[layer].slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE).some(record => record.id === item.id);
  }), [graph.nodes, enabled, pages, layers]);
  const geometry = useMemo(() => repairGeometry(graph.entry.key, visible), [graph.entry.key, visible]);
  const visibleIds = new Set(visible.map(item => item.id));
  const visibleEdges = graph.edges.filter(edge => visibleIds.has(edge.source) && visibleIds.has(edge.target));
  const selectedEdge = graph.edges.find(edge => edge.id === selected);
  const selectionExists = graph.nodes.some(item => item.id === selected) || Boolean(selectedEdge);
  const selectionVisible = selectedEdge ? visibleEdges.some(edge => edge.id === selected) : visibleIds.has(selected);
  const activate = useCallback((id: string) => { setToolbarId(id); onSelect(id); }, [onSelect]);
  const flowNodes: Array<GroupNode | RecordNode> = [];
  const absolute = new Map<string, { x: number; y: number; width: number; height: number }>();
  for (const group of geometry.groups) {
    const total = group.group === 'action' ? graph.nodes.filter(item => item.kind === 'action').length
      : layers[group.group].length + (group.group === 'context' ? findingContext.length : 0);
    flowNodes.push({ id: group.id, type: 'context', position: group.position, data: { group: group.group, title: labels[group.group], description: descriptions[group.group], count: `${group.records.length} / ${total}` },
      style: { width: group.width, height: group.height }, width: group.width, height: group.height,
      selectable: false, draggable: false, focusable: false, zIndex: -1 });
    for (const { item, position, width, height } of group.records) {
      const size = { width, height };
      absolute.set(item.id, { x: position.x + group.position.x, y: position.y + group.position.y, ...size });
      flowNodes.push({ id: item.id, type: 'repairRecord', parentId: group.id, extent: 'parent', position, ...size,
        data: { item, toolbar: toolbarId === selected, onSelect: activate, onOpen }, selected: item.id === selected,
        ariaLabel: `${kindLabels[item.kind]} ${item.localId}: ${item.title}. ${item.caption}. ${item.unavailable ? 'Referenced record unavailable' : human(item.status || 'not_recorded')}` });
    }
  }
  const edges: Edge[] = visibleEdges.map(edge => {
    const source = absolute.get(edge.source)!, target = absolute.get(edge.target)!;
    const dx = target.x + target.width / 2 - source.x - source.width / 2;
    const dy = target.y + target.height / 2 - source.y - source.height / 2;
    const vertical = Math.abs(dy) > Math.abs(dx);
    const direction = vertical ? dy > 0 ? ['bottom', 'top'] : ['top', 'bottom'] : dx > 0 ? ['right', 'left'] : ['left', 'right'];
    const incident = selected === edge.id || selected === edge.source || selected === edge.target;
    return { id: edge.id, source: edge.source, target: edge.target, sourceHandle: `out-${direction[0]}`, targetHandle: `in-${direction[1]}`,
      type: 'smoothstep', selected: edge.id === selected, focusable: true, interactionWidth: 24,
      label: edge.id === selected ? edge.label : undefined,
      ariaLabel: `${edge.label}. ${edge.description}`,
      style: { stroke: selected === edge.id ? 'var(--primary-text)' : edge.kind === 'target' ? 'var(--graph-repair)' : edge.kind === 'context' ? 'var(--graph-unresolved)' : 'var(--graph-edge)',
        strokeWidth: selected === edge.id ? 2.8 : incident ? 2 : 1.4,
        strokeDasharray: edge.kind === 'interruption' ? '6 4' : edge.kind === 'context' ? '3 5' : edge.kind === 'evidence' ? '2 4' : undefined },
      labelStyle: { fill: 'var(--text)', fontSize: 10 }, labelBgStyle: { fill: 'var(--panel)' }, labelBgPadding: [7, 4], labelBgBorderRadius: 4,
    };
  });
  const layoutRef = useRef({ geometry, absolute }); layoutRef.current = { geometry, absolute };
  const selectionRef = useRef(selected); selectionRef.current = selected;
  const geometryKey = JSON.stringify([graph.entry.key, visible.map(item => item.id)]);
  const mobileSelectionKey = paneWidth < 520 ? selected : '';
  const fitAll = useCallback(() => {
    if (!paneWidth || !paneHeight) return;
    const { bounds } = layoutRef.current.geometry;
    const availableHeight = Math.max(180, paneHeight - (paneWidth < 520 ? 76 : 176));
    setRecordFraming(false);
    void setViewport(getViewportForBounds({ x: bounds.x - 18, y: -18, width: bounds.width + 36, height: bounds.height + 36 }, paneWidth, availableHeight, .03, 1, .08), { duration: 0 });
  }, [setViewport, paneWidth, paneHeight]);
  useEffect(() => {
    if (!viewportInitialized || !paneWidth || !paneHeight) return;
    const frame = requestAnimationFrame(() => {
      const bounds = layoutRef.current.absolute.get(selectionRef.current);
      if (paneWidth < 520 && bounds) {
        setRecordFraming(true);
        void setViewport(getViewportForBounds({ x: bounds.x - 16, y: bounds.y - 28, width: bounds.width + 32, height: bounds.height + 56 }, paneWidth, Math.max(180, paneHeight - 76), .03, 1.1, .08), { duration: 0 });
      } else fitAll();
    });
    return () => cancelAnimationFrame(frame);
  }, [viewportInitialized, geometryKey, mobileSelectionKey, paneWidth, paneHeight, fitAll, setViewport]);
  const selectedIds = selectedEdge ? [selectedEdge.source, selectedEdge.target].filter(id => visibleIds.has(id)) : visibleIds.has(selected) ? [selected] : [];
  return <section className="repair-map-canvas" aria-label="Repair relationship map">
    <div className="rc-map-controls">
      <div className="rc-layers" role="group" aria-label="Repair map layers"><span>Layers</span>{layerOrder.map(layer => {
        const total = layers[layer].length + (layer === 'context' ? findingContext.length : 0);
        return <button key={layer} type="button" aria-label={`Show ${labels[layer].toLowerCase()}`} aria-pressed={enabled[layer]} disabled={!total} onClick={() => setEnabled(previous => ({ ...previous, [layer]: !previous[layer] }))}>{labels[layer]}<strong>{total}</strong></button>;
      })}</div>
      <label className="rc-record-picker">Jump to record<select aria-label="Select repair map record" value={graph.nodes.some(item => item.id === selected) ? selected : ''} onChange={event => { reveal(event.target.value); activate(event.target.value); }}>
        <option value="" disabled>Choose a record</option>{(['action', ...layerOrder] as Group[]).map(group => <optgroup key={group} label={labels[group]}>{graph.nodes.filter(item => repairLayer(item) === group).map(item => <option key={item.id} value={item.id}>{kindLabels[item.kind]} · {item.localId} · {item.title}</option>)}</optgroup>)}
      </select></label>
    </div>
    <div className="rc-window-controls">{layerOrder.filter(layer => enabled[layer] && layers[layer].length > PAGE_SIZE).map(layer => {
      const count = layers[layer].length, last = Math.ceil(count / PAGE_SIZE) - 1, page = Math.min(pages[layer], last);
      return <div key={layer}><span>{labels[layer]} <strong>{page * PAGE_SIZE + 1}–{Math.min(count, (page + 1) * PAGE_SIZE)}</strong> of {count}{layer === 'context' && findingContext.length ? ' + finding' : ''}</span>
        <button type="button" aria-label={`Previous ${labels[layer].toLowerCase()} page`} disabled={page === 0} onClick={() => setPages(previous => ({ ...previous, [layer]: page - 1 }))}><ChevronLeft size={15} /></button>
        <button type="button" aria-label={`Next ${labels[layer].toLowerCase()} page`} disabled={page === last} onClick={() => setPages(previous => ({ ...previous, [layer]: page + 1 }))}><ChevronRight size={15} /></button></div>;
    })}<span className="rc-visible-count" role="status">{visible.length} of {graph.nodes.length} records · {visibleEdges.length} of {graph.edges.length} connections</span></div>
    {selectionExists && !selectionVisible && <div className="rc-hidden-selection" role="status">The selected record or connection is outside this window.<button type="button" onClick={() => reveal(selected)}>Show selected</button></div>}
    <div className="rc-canvas" aria-label="Interactive repair relationship graph" data-layout-status={viewportInitialized && paneWidth && paneHeight ? 'ready' : 'loading'} data-framing={recordFraming ? 'record' : 'all'}
      onKeyDownCapture={event => { if (!['Enter', ' '].includes(event.key)) return; const target = event.target as Element; const node = target.closest?.('.react-flow__node-repairRecord'); const id = node?.getAttribute('data-id'); if (target === node && id) activate(id); }}>
      {recordFraming && <div className="rc-focus-note">Record detail <span>Use Fit View for all visible connections</span></div>}
      <ReactFlow nodes={flowNodes} edges={edges} nodeTypes={nodeTypes} minZoom={.03} maxZoom={2} nodesDraggable={false} nodesConnectable={false} deleteKeyCode={null} edgesReconnectable={false}
        onNodeClick={(_, node) => { if (node.type === 'repairRecord') activate(node.id); }}
        onEdgeClick={(_, edge) => onSelect(edge.id)}
        onNodesChange={changes => { const change = changes.find(item => item.type === 'select' && item.selected); if (change?.type === 'select' && change.id !== selected) activate(change.id); }}
        onEdgesChange={changes => { const change = changes.find(item => item.type === 'select' && item.selected); if (change?.type === 'select' && change.id !== selected) onSelect(change.id); }}>
        <Background color="var(--graph-grid)" gap={24} size={1} />
        <GraphNavigator nodeCount={visible.length} edgeCount={visibleEdges.length} selectedIds={selectedIds} onFitAll={fitAll} label="Repair map navigation" />
      </ReactFlow>
    </div>
    <div className="rc-legend"><span><i className="rc-key-target" />Repair target</span><span><i className="rc-key-interruption" />Recorded interruption</span><span><i className="rc-key-context" />Finding context</span><small>Relationships describe recorded recommendations, not applied or verified fixes.</small></div>
  </section>;
}
