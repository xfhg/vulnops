import { useEffect, useMemo, useState } from 'react';
import {
  Background, BaseEdge, EdgeLabelRenderer, getBezierPath, getNodesBounds, Handle, MarkerType, Position, ReactFlow, ReactFlowProvider,
  useReactFlow, useStore, useViewport, type Edge, type EdgeProps, type Node, type NodeProps,
} from '@xyflow/react';
import { ArrowRight, ArrowUpRight, FileCode2, FileText, GitBranch, Layers3, Link2, Wrench } from 'lucide-react';
import '@xyflow/react/dist/style.css';
import type { FindingRecord } from '../../domain/index';
import GraphNavigator from '../../components/graph/GraphNavigator';
import { Button } from '../../components/ui';
import {
  collapseProjection, humanize, locationReference, object, projectFinding, records, repairActions, string,
  type DetailField, type EvidenceCallback, type GraphItem, type GraphLink, type GraphMode, type Projection,
} from './projection';
import { connectedAnchor, connectedRecords, neighborhood, type ConnectedRecords } from './relationships';
import './explorer.css';

export interface AttackExplorerProps {
  finding: FindingRecord;
  mode?: GraphMode;
  selected?: string;
  repairId?: string;
  onModeChange?: (mode: GraphMode) => void;
  onSelect?: (id: string) => void;
  onRepairChange?: (id: string) => void;
  onReadRepair?: (actionId: string, locationIndex?: number) => void;
  onEvidence?: EvidenceCallback;
}

function statusClass(status: string): string {
  return /environment|unresolved|blocked|unknown|failed|contradicted|rejected|unavailable/.test(status) ? 'uncertain' : status === 'proposed_repair' ? 'repair' : 'recorded';
}

/** Structured values stay complete and inert; the inspector never interprets markup. */
export function ReadableValue({ value }: { value: unknown }) {
  if (value === null || value === undefined || value === '') return <span className="graph-muted">Not recorded</span>;
  if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') return <span>{String(value)}</span>;
  if (Array.isArray(value)) return <ul className="graph-value-list">{value.map((item, index) => <li key={index}><ReadableValue value={item} /></li>)}</ul>;
  return <dl className="graph-fields graph-fields-nested">{Object.entries(object(value)).map(([key, item]) => (
    <div key={key}><dt>{humanize(key)}</dt><dd><ReadableValue value={item} /></dd></div>
  ))}</dl>;
}

function referenceLabel(reference: unknown): string {
  if (typeof reference === 'string') return reference;
  const ref = object(reference);
  return [ref.execution_id, ref.artifact_ref, ref.record_id ?? ref.selector].filter(Boolean).join(' · ') || 'Recorded reference';
}

function EvidenceLinks({ references, finding, onEvidence }: { references: unknown[]; finding: FindingRecord; onEvidence?: EvidenceCallback }) {
  const unique = [...new Map(references.map(reference => [JSON.stringify(reference), reference])).values()];
  if (!unique.length) return <p className="graph-muted">No references recorded for this item.</p>;
  return <ul className="graph-reference-list">{unique.map((reference, index) => <li key={index}>
    <button className="graph-reference" onClick={() => onEvidence?.(reference, finding.runId)} disabled={!onEvidence}>
      {referenceLabel(reference)}
    </button>
  </li>)}</ul>;
}

function EvidenceNode({ data }: NodeProps) {
  const item = data.item as GraphItem;
  const compact = data.compact === true;
  const related = data.related === true;
  const kind = item.hiddenCount ? 'group' : item.kind ?? 'procedure';
  const Icon = kind === 'trace' || kind === 'example' ? FileText : kind === 'composition' || kind === 'transition' ? GitBranch
    : kind === 'component' || kind === 'group' ? Layers3 : kind === 'repair' ? Wrench : kind === 'evidence' ? Link2 : ArrowRight;
  const kindLabel = kind === 'composition' ? 'Capability' : kind === 'trace' ? `Source · ${humanize(item.status)}` : humanize(kind);
  return <div className={`${related ? 'graph-connected-node' : 'graph-evidence-node'} graph-typed-node graph-kind-${kind} ${compact ? 'is-compact' : ''} ${item.highlighted ? 'repair-highlight' : ''}`}>
    <Handle type="target" position={Position.Left} />
    <div className="graph-node-meta"><span><Icon size={13} aria-hidden="true" />{item.hiddenCount ? `${item.hiddenCount} RECORDS` : `${String(item.ordinal + 1).padStart(2, '0')} · ${kindLabel}`}</span>
      <span className={`graph-status ${statusClass(item.status)}`}>{humanize(item.status)}</span></div>
    <strong className="graph-node-title" title={item.label}>{item.label}</strong>
    <div className="graph-node-caption" title={item.caption || item.localId}>{item.caption || item.localId}</div>
    {!item.hiddenCount && <dl className="graph-node-fields">{item.preview?.slice(0, 2).map(field => <div key={field.label}>
      <dt>{field.label}</dt><dd title={String(field.value ?? 'Not recorded')}>{String(field.value ?? 'Not recorded')}</dd>
    </div>)}</dl>}
    <div className="graph-node-footer">{item.highlighted ? <span className="graph-repair-indicator">◈ Proposed repair point</span>
      : <span>{related ? 'Recorded association' : item.kind === 'trace' ? 'Assessed source sequence' : item.kind === 'composition' ? 'Recorded capability' : 'Recorded procedure'}</span>}
      <span>{item.evidence.length} {item.evidence.length === 1 ? 'reference' : 'references'}</span></div>
    <Handle type="source" position={Position.Right} />
    <Handle id="metadata" type="source" position={Position.Bottom} className="graph-metadata-handle" />
  </div>;
}

const nodeTypes = { evidence: EvidenceNode };
function TransitionEdge(props: EdgeProps) {
  const [path, x, y] = getBezierPath(props);
  const item = props.data?.item as GraphLink | undefined;
  const select = props.data?.onSelect as ((id: string) => void) | undefined;
  return <><BaseEdge id={props.id} path={path} style={props.style} markerEnd={props.markerEnd} />
    <EdgeLabelRenderer><button className={`graph-transition-label nodrag nopan ${props.selected ? 'active' : ''} ${statusClass(item?.status ?? 'unknown')}`}
      style={{ transform: `translate(-50%, -50%) translate(${x}px,${y}px)` }}
      onClick={() => select?.(props.id)} aria-label={`Inspect transition: ${item?.label}. ${item?.summary ?? ''}`}>
      <span><GitBranch size={11} aria-hidden="true" />{item?.label}</span><small>{item?.summary}</small>
    </button></EdgeLabelRenderer></>;
}
const edgeTypes = { recordedTransition: TransitionEdge };
const NODE_WIDTH = 304, NODE_HEIGHT = 264;
const layoutCache = new Map<string, Array<{ id: string; x: number; y: number }>>();

function Canvas({ projection, connections, mode, selected, onSelect, onExpand }: {
  projection: Projection; connections: ConnectedRecords; mode: GraphMode; selected: string; onSelect: (id: string) => void; onExpand: (group: string) => void;
}) {
  const { fitBounds, viewportInitialized } = useReactFlow();
  const { zoom } = useViewport();
  const paneWidth = useStore(state => state.width);
  const paneHeight = useStore(state => state.height);
  const [positions, setPositions] = useState<Array<{ id: string; x: number; y: number }>>([]);
  const [layoutError, setLayoutError] = useState('');
  const layoutKey = useMemo(() => JSON.stringify([mode, NODE_WIDTH, NODE_HEIGHT, projection.nodes.map(node => node.id), projection.edges.map(edge => [edge.source, edge.target])]), [projection, mode]);
  useEffect(() => {
    const existing = layoutCache.get(layoutKey);
    setLayoutError('');
    if (existing) { setPositions(existing); return; }
    setPositions([]);
    let worker: Worker;
    try { worker = new Worker(new URL('./layout.worker.ts', import.meta.url), { type: 'module' }); }
    catch { setLayoutError('Automatic layout unavailable. Use the complete linear view.'); return; }
    worker.onmessage = (event: MessageEvent) => {
      if (event.data.error) { setLayoutError(String(event.data.error)); return; }
      const next = event.data.positions as Array<{ id: string; x: number; y: number }>;
      if (layoutCache.size > 40) layoutCache.delete(layoutCache.keys().next().value!);
      layoutCache.set(layoutKey, next); setPositions(next);
    };
    worker.onerror = () => setLayoutError('Automatic layout unavailable. Use the complete linear view.');
    // Reserve additional horizontal room for obligation callouts in composition.
    worker.postMessage({ placement: mode === 'composition' ? 'topology' : 'sequence', nodes: projection.nodes.map(({ id }) => ({ id, width: NODE_WIDTH + (mode === 'composition' ? 110 : 0), height: NODE_HEIGHT })), edges: projection.edges.map(({ id, source, target }) => ({ id, source, target })), requestId: layoutKey });
    return () => worker.terminate();
  }, [layoutKey]);
  const positionMap = new Map(positions.map(position => [position.id, position]));
  const nodes: Node[] = projection.nodes.map((item, index) => ({
    id: item.id, type: 'evidence', data: { item, compact: zoom < .52 }, selected: item.id === selected,
    position: positionMap.get(item.id) ?? { x: (index % 4) * 350, y: Math.floor(index / 4) * 215 },
    ariaLabel: `${item.localId}: ${item.label}. ${humanize(item.status)}${item.highlighted ? '. Proposed repair point' : ''}`,
    width: NODE_WIDTH, height: NODE_HEIGHT,
  }));
  const anchorNode = nodes.find(node => node.id === connections.anchorId);
  const anchorEdge = projection.edges.find(edge => edge.id === connections.anchorId);
  const edgeSource = nodes.find(node => node.id === anchorEdge?.source);
  const origin = anchorNode?.position ?? edgeSource?.position ?? { x: 0, y: 0 };
  const bottom = Math.max(origin.y + NODE_HEIGHT, ...nodes.map(node => node.position.y + NODE_HEIGHT));
  // The metadata shelf sits below the original graph. It cannot reorder the
  // procedure or overlap another recorded branch, and has no flow meaning.
  connections.nodes.forEach((item, index) => nodes.push({
    id: item.id, type: 'evidence', data: { item, related: true, compact: zoom < .52 }, selected: item.id === selected,
    position: { x: origin.x + (index % 3 - 1) * (NODE_WIDTH + 54), y: bottom + 130 + Math.floor(index / 3) * (NODE_HEIGHT + 75) },
    width: NODE_WIDTH, height: NODE_HEIGHT,
    ariaLabel: `${humanize(item.kind ?? 'record')}: ${item.localId}. ${item.label}. ${humanize(item.status)}. Recorded association, not execution flow.`,
  }));
  const connectionIds = new Set(connections.nodes.map(node => node.id));
  const fitNodes = connectionIds.size ? nodes.filter(node => connectionIds.has(node.id) || node.id === connections.anchorId || node.id === anchorEdge?.source || node.id === anchorEdge?.target)
    // Keep the entire timeline rendered, but start large sequences at a readable slice.
    : projection.nodes.length > 24 ? nodes.slice(0, 3) : nodes;
  const fitGeometry = JSON.stringify(fitNodes.map(node => [node.id, node.position.x, node.position.y, node.width, node.height]));
  useEffect(() => {
    if (!viewportInitialized || !paneWidth || !paneHeight || !positions.length || !fitNodes.length) return;
    // One fit authority uses the complete rendered geometry. Queued fitView
    // calls can race controlled-node updates when metadata is first appended.
    // These controlled nodes have fixed layout dimensions, so fitting does not
    // depend on React Flow's separately persisted `measured` dimensions.
    const bounds = getNodesBounds(fitNodes);
    const frame = requestAnimationFrame(() => { void fitBounds(bounds, { padding: .2, duration: 0 }); });
    return () => cancelAnimationFrame(frame);
  }, [fitGeometry, positions, viewportInitialized, paneWidth, paneHeight, fitBounds]);
  const edges: Edge[] = projection.edges.map(item => ({
    id: item.id, source: item.source, target: item.target, label: item.label,
    type: item.kind === 'transition' ? 'recordedTransition' : undefined, data: { item, onSelect },
    selected: item.id === selected, focusable: true,
    ariaLabel: `${item.label}. Select to inspect recorded transition.`,
    style: { stroke: item.id === selected ? 'var(--graph-node-accent)' : statusClass(item.status) === 'uncertain' ? 'var(--graph-unresolved)' : 'var(--graph-edge)', strokeWidth: item.id === selected ? 3 : 1.6,
      strokeDasharray: statusClass(item.status) === 'uncertain' ? '5 4' : undefined },
    markerEnd: { type: MarkerType.ArrowClosed, color: item.id === selected ? 'var(--graph-node-accent)' : statusClass(item.status) === 'uncertain' ? 'var(--graph-unresolved)' : 'var(--graph-edge)' },
  }));
  for (const item of connections.edges) edges.push({ id: item.id, source: item.source, target: item.target,
    sourceHandle: 'metadata', label: item.label, selected: item.id === selected, focusable: true,
    ariaLabel: `${item.label}. Recorded association, not execution flow.`,
    style: { stroke: 'var(--graph-unresolved)', strokeWidth: 1.4, strokeDasharray: '3 5' },
  });
  const selectedEdge = edges.find(edge => edge.id === selected);
  const selectedIds = nodes.some(node => node.id === selected) ? [selected] : selectedEdge ? [selectedEdge.source, selectedEdge.target] : [];
  return <div className="graph-canvas" aria-label="Interactive assessed attack graph" data-layout-status={projection.nodes.every(node => positionMap.has(node.id)) ? 'ready' : 'loading'}>
    {layoutError && <div role="status" className="graph-layout-note">{layoutError}</div>}
    <ReactFlow nodes={nodes} edges={edges} nodeTypes={nodeTypes} edgeTypes={edgeTypes} minZoom={.005} maxZoom={1.6}
      nodesDraggable={false} nodesConnectable={false} elementsSelectable
      onNodesChange={changes => {
        // User selection changes are authoritative. A selection-list observer can
        // echo the previous controlled nodes while a URL selection is updating.
        const change = changes.find(change => change.type === 'select' && change.selected);
        if (!change || change.type !== 'select') return;
        const item = [...projection.nodes, ...connections.nodes].find(node => node.id === change.id);
        if (item?.hiddenCount) onExpand(item.group);
        else if (item && item.id !== selected) onSelect(item.id);
      }}
      onEdgesChange={changes => {
        const change = changes.find(change => change.type === 'select' && change.selected);
        if (change && change.type === 'select' && change.id !== selected) onSelect(change.id);
      }}>
      <Background color="var(--graph-grid)" gap={24} size={1} />
      <GraphNavigator nodeCount={nodes.length} edgeCount={edges.length} selectedIds={selectedIds} label="Attack graph navigation" />
    </ReactFlow>
  </div>;
}

function Inspector({ item, finding, actions, repairId, onRepairChange, onReadRepair, onEvidence }: {
  item?: GraphItem | GraphLink; finding: FindingRecord; actions: Record<string, unknown>[]; repairId: string;
  onRepairChange: (id: string) => void; onReadRepair?: AttackExplorerProps['onReadRepair']; onEvidence?: EvidenceCallback;
}) {
  if (!item) return <div className="graph-inspector-empty"><span className="graph-empty-mark">◎</span><h3>Select a record</h3><p>Follow a step, source location or recorded transition to inspect its evidence and proposed repairs.</p></div>;
  const step = 'localId' in item ? item : undefined;
  const relevantActions = actions.filter(action => step?.repairIds.includes(string(action.id)));
  const examples = records(finding.raw.technical_examples).filter(example => {
    const ids = step?.raw.example_ids;
    return Array.isArray(ids) && ids.includes(example.id);
  });
  return <div className="graph-inspector-content" key={item.id}>
    <div className="graph-eyebrow">{step ? step.localId : item.kind === 'association' ? 'Recorded association' : item.kind === 'sequence' ? 'Recorded order' : 'Capability transition'}</div>
    <h3>{item.label}</h3>
    <span className={`graph-status ${statusClass(item.status)}`}>{humanize(item.status)}</span>
    <dl className="graph-fields">{item.details.map(({ label, value }: DetailField) => <div key={label}><dt>{label}</dt><dd><ReadableValue value={value} /></dd></div>)}</dl>
    {examples.length > 0 && <section><h4>Recorded examples</h4>{examples.map((example, index) => <div className="graph-example" key={index}>
      <strong>{string(example.id)}</strong><span className="graph-status">{humanize(string(example.execution_status, 'unknown'))}</span>
      <pre>{string(example.content)}</pre>
      {Array.isArray(example.substitutions) && example.substitutions.length > 0 && <ReadableValue value={example.substitutions} />}
    </div>)}</section>}
    {relevantActions.length > 0 && <section><h4>Proposed interruption points</h4>{relevantActions.map(action => <article
      key={string(action.id)} className={`graph-repair-card ${repairId === action.id ? 'active' : ''}`} aria-label={`Related repair ${string(action.id)}`}>
      <span>{string(action.id)} · Proposed repair</span><strong>{string(action.change)}</strong>
      <div className="graph-repair-card-actions">{onReadRepair && string(action.id) && <Button className="graph-read-repair" size="sm" onClick={() => onReadRepair(string(action.id))}>Read implementation instructions<ArrowUpRight size={13} aria-hidden="true"/></Button>}
        <Button variant="outline" size="sm" onClick={() => onRepairChange(repairId === action.id ? '' : string(action.id))}><GitBranch size={13} aria-hidden="true"/>{repairId === action.id ? 'Clear repair overlay' : 'Show repair overlay'}</Button>
      </div>
    </article>)}</section>}
    <section><h4>Supporting evidence</h4><EvidenceLinks references={item.evidence} finding={finding} onEvidence={onEvidence} /></section>
  </div>;
}

export default function AttackExplorer({ finding, mode: controlledMode, selected: controlledSelected, repairId: controlledRepairId,
  onModeChange, onSelect, onRepairChange, onReadRepair, onEvidence }: AttackExplorerProps) {
  const [localMode, setLocalMode] = useState<GraphMode>('procedure');
  const [localSelected, setLocalSelected] = useState('');
  const [localRepair, setLocalRepair] = useState('');
  const [linear, setLinear] = useState(false);
  const [connected, setConnected] = useState(false);
  const [focused, setFocused] = useState(false);
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());
  const [inspectorWidth, setInspectorWidth] = useState(34);
  const mode = controlledMode ?? localMode;
  const selected = controlledSelected ?? localSelected;
  const repairId = controlledRepairId ?? localRepair;
  const select = (id: string) => { setLocalSelected(id); onSelect?.(id); };
  const changeRepair = (id: string) => { setLocalRepair(id); onRepairChange?.(id); };
  const changeMode = (next: GraphMode) => {
    setLocalMode(next); setLocalSelected(''); setCollapsed(new Set()); setConnected(false); setFocused(false);
    // A controlled route changes mode and clears its selection in one history entry.
    if (onModeChange) onModeChange(next); else onSelect?.('');
  };
  const projection = useMemo(() => projectFinding(finding, mode, repairId), [finding, mode, repairId]);
  const selectionAnchor = connectedAnchor(finding.key, mode, selected);
  const connectedActive = connected || selectionAnchor !== null;
  const connections = useMemo(() => connectedActive ? connectedRecords(finding, mode, projection, selected)
    : { anchorId: null, nodes: [], edges: [], diagnostics: [] }, [finding, mode, projection, selected, connectedActive]);
  const focusedProjection = useMemo(() => focused ? neighborhood(projection, selectionAnchor ?? selected) : projection, [projection, focused, selectionAnchor, selected]);
  const visible = useMemo(() => collapseProjection(focusedProjection, connectedActive || focused ? new Set() : collapsed), [focusedProjection, collapsed, connectedActive, focused]);
  const actions = repairActions(finding);
  const selectedItem = [...projection.nodes, ...connections.nodes].find(node => node.id === selected)
    ?? [...projection.edges, ...connections.edges].find(edge => edge.id === selected);
  const activeRepair = actions.find(action => action.id === repairId);
  const collapsibleGroups = !linear && !connectedActive && !focused ? projection.groups.filter(group => group.count > 1) : [];
  useEffect(() => { setCollapsed(new Set()); setLocalSelected(''); setLocalRepair(''); setConnected(false); setFocused(false); }, [finding.key]);
  const toggleConnections = () => {
    if (connectedActive) { setConnected(false); if (selectionAnchor) select(selectionAnchor); }
    else { setConnected(true); setCollapsed(new Set()); if (!selectedItem && projection.nodes[0]) select(projection.nodes[0].id); }
  };
  const toggleFocus = () => {
    setFocused(value => !value); setCollapsed(new Set());
    if (!selectedItem && projection.nodes[0]) select(projection.nodes[0].id);
  };
  const toggleGroup = (group: string) => setCollapsed(previous => {
    const next = new Set(previous); if (next.has(group)) next.delete(group); else next.add(group); return next;
  });
  return <section className="stake-explorer" aria-label="Attack explorer">
    <div className="graph-control-panel">
      <div className="graph-toolbar">
        <div role="tablist" aria-label="Attack representation" className="graph-tabs">
          {(['procedure', 'trace', 'composition'] as GraphMode[]).map(value => <button type="button" role="tab" key={value}
            aria-selected={mode === value} className={mode === value ? 'active' : ''} onClick={() => changeMode(value)}>
            {value === 'procedure' ? 'Attack procedure' : value === 'trace' ? 'Code trace' : 'Composition'}
          </button>)}
        </div>
        <div className="graph-view-actions">
          <button className="graph-view-toggle" aria-pressed={connectedActive} disabled={!projection.nodes.length} onClick={toggleConnections}><Link2 size={13} aria-hidden="true" />Connected records</button>
          {!linear && <button className="graph-view-toggle" aria-pressed={focused} disabled={!projection.nodes.length} onClick={toggleFocus}>Selected neighborhood</button>}
          <button className="graph-view-toggle" aria-pressed={linear} onClick={() => setLinear(value => !value)}>{linear ? 'Show graph' : 'Linear view'}</button>
        </div>
      </div>
      {(actions.length > 0 || collapsibleGroups.length > 0) && <div className="graph-secondary-controls">
        {actions.length > 0 && <div className="graph-repair-toolbar"><label htmlFor="graph-repair-select">Show proposed repair</label>
          <select id="graph-repair-select" value={repairId} onChange={event => changeRepair(event.target.value)}>
            <option value="">No repair overlay</option>{actions.map(action => <option value={string(action.id)} key={string(action.id)}>{string(action.id)} — {string(action.change)}</option>)}
          </select></div>}
        {collapsibleGroups.length > 0 && <div className="graph-groups"><span>Collapse groups</span>
          {collapsibleGroups.map(group => <button key={group.id} aria-pressed={collapsed.has(group.id)} onClick={() => toggleGroup(group.id)}>
            {collapsed.has(group.id) ? '+' : '−'} {group.label} <span>{group.count}</span></button>)}</div>}
      </div>}
      <div className="graph-context-bar"><span>{projection.nodes.length} {mode === 'procedure' ? 'recorded steps' : mode === 'trace' ? 'cited locations' : 'recorded primitives'}</span>
        <span>{mode === 'trace' ? 'Assessed trace · not a complete call graph' : mode === 'composition' ? 'Explicit capability transitions only' : 'Ordered actions · evidence status retained per step'}</span>
        {focused && !linear && <span role="status">Showing {focusedProjection.nodes.length} of {projection.nodes.length} records · {projection.nodes.length - focusedProjection.nodes.length} outside this neighborhood</span>}
        {connectedActive && <span>{connections.nodes.length} connected records · dotted links are associations, not execution flow</span>}</div>
    </div>
    {activeRepair && <section className="graph-repair-summary" aria-label={`Proposed repair ${string(activeRepair.id)}`}>
      <header><h3><Wrench size={15} aria-hidden="true"/>Proposed repair · {string(activeRepair.id)}</h3>
        {onReadRepair && string(activeRepair.id) && <Button className="graph-read-repair" size="sm" onClick={() => onReadRepair(string(activeRepair.id))}>Read implementation instructions<ArrowRight size={14} aria-hidden="true"/></Button>}</header>
      <p className="graph-repair-change">{string(activeRepair.change)}</p>
      {string(activeRepair.rationale) && <div className="graph-repair-rationale">{string(activeRepair.rationale).length > 420
        ? <details><summary>Recorded rationale</summary><p>{string(activeRepair.rationale)}</p></details>
        : <><h4>Recorded rationale</h4><p>{string(activeRepair.rationale)}</p></>}</div>}
      {records(activeRepair.locations).length > 0 && <ul className="graph-repair-locations" aria-label="Proposed repair locations">{records(activeRepair.locations).map((loc, index) => {
        const reference = locationReference(loc);
        const file = string(loc.file), filename = file.split('/').at(-1) || 'Location not recorded';
        const range = file && reference.length > file.length ? reference.slice(file.length + 1) : '';
        const coordinates = range ? `${range.includes('-') ? 'Lines' : 'Line'} ${range.replace('-', '–')}` : file ? 'File-level target' : 'Source path not recorded';
        const content = <><FileCode2 size={15} aria-hidden="true"/><span className="graph-repair-location-copy"><span><strong>{filename}</strong><code>{coordinates}</code></span><small>{file || 'No source path recorded'}</small></span>{onReadRepair && string(activeRepair.id) && <ArrowUpRight size={13} aria-hidden="true"/>}</>;
        return <li key={index}>{onReadRepair && string(activeRepair.id)
          ? <button type="button" className="graph-repair-location" title={reference || 'Location not recorded'} aria-label={`Read implementation instructions for ${reference || `location ${index + 1}`} of ${string(activeRepair.id)}`} onClick={() => onReadRepair(string(activeRepair.id), index)}>{content}</button>
          : <div className="graph-repair-location graph-repair-location-static" title={reference || 'Location not recorded'}>{content}</div>}</li>;
      })}</ul>}
      <small className="graph-repair-summary-note">Highlighted relationships describe the recommendation; no applied or passing fix is implied.</small></section>}
    {projection.diagnostics.length + connections.diagnostics.length > 0 && <ul className="graph-diagnostics" role="status">{[...projection.diagnostics, ...connections.diagnostics].map(message => <li key={message}>{message}</li>)}</ul>}
    {!projection.nodes.length ? <div className="graph-empty"><span className="graph-empty-mark">◇</span><h3>{mode === 'composition' ? 'No composition recorded' : 'No recorded steps in this view'}</h3>
      <p>{mode === 'composition' ? 'This finding has no explicit primitive chain. Its attack procedure and source trace remain available.' : 'The available record does not contain this evidence. No steps have been inferred.'}</p></div>
      : <div className="graph-panes" style={{ gridTemplateColumns: `minmax(0, ${100 - inspectorWidth}fr) minmax(240px, ${inspectorWidth}fr)` }}>
        <div className="graph-main-panel">{linear ? <ol className="graph-linear-list">{projection.nodes.map(item => <li key={item.id}>
          <button onClick={() => select(item.id)} className={`graph-linear-item ${selected === item.id ? 'active' : ''} ${item.highlighted ? 'repair-highlight' : ''}`}>
            <span className="graph-linear-number">{String(item.ordinal + 1).padStart(2, '0')}</span><span><strong>{item.label}</strong><small>{item.caption || item.localId}</small>
              <span className={`graph-status ${statusClass(item.status)}`}>{humanize(item.status)}</span>{item.highlighted && <span className="graph-repair-indicator">Proposed repair point</span>}</span>
          </button>
          {mode === 'composition' && projection.edges.filter(edge => edge.source === item.id).map(edge => <button key={edge.id} className={'graph-linear-transition ' + (statusClass(edge.status) === 'uncertain' ? 'is-unresolved' : '')} onClick={() => select(edge.id)}>
            → {projection.nodes.find(node => node.id === edge.target)?.localId} · {edge.label} · Inspect transition
          </button>)}
        </li>)}</ol> : <ReactFlowProvider><Canvas mode={mode} projection={visible} connections={connections} selected={selected} onSelect={select} onExpand={toggleGroup} /></ReactFlowProvider>}
          {connectedActive && linear && <section className="graph-connected-list" aria-label="Connected records">
            <h3>Connected records</h3><p>Explicit associations for the selected record. These links do not describe execution flow.</p>
            {connections.nodes.length ? <ul>{connections.nodes.map(item => <li key={item.id}><button className={`graph-connection-link ${item.id === selected ? 'active' : ''}`} onClick={() => select(item.id)}>
              <span>{humanize(item.kind ?? 'record')} · {connections.edges.find(edge => edge.target === item.id)?.label ?? 'Selected transition'}</span>
              <strong>{item.label}</strong><small>{item.localId} · {humanize(item.status)}</small>
            </button></li>)}</ul> : <p>No connected records are recorded for this selection.</p>}
          </section>}
          <div className="graph-legend"><span><i className="recorded" />Recorded evidence</span><span><i className="uncertain" />Unresolved / environment required</span><span><i className="repair" />Proposed repair</span>{connectedActive && <span><i className="association" />Recorded association</span>}</div>
        </div>
        <aside className="graph-inspector" aria-label="Selected evidence inspector">
          <div className="graph-inspector-top"><strong>Evidence inspector</strong><label>Width <input aria-label="Evidence inspector width" type="range" min="25" max="55" value={inspectorWidth} onChange={event => setInspectorWidth(Number(event.target.value))} /></label></div>
          {selected && !selectedItem ? <div role="status" className="graph-inspector-empty"><h3>Selection unavailable</h3><p>This record is not part of the selected finding and graph mode.</p></div>
            : <Inspector item={selectedItem} finding={finding} actions={actions} repairId={repairId} onRepairChange={changeRepair} onReadRepair={onReadRepair} onEvidence={onEvidence} />}
        </aside>
      </div>}
  </section>;
}
