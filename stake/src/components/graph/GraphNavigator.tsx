import { useEffect, useId, useState, type KeyboardEvent } from 'react';
import { MiniMap, Panel, useReactFlow, useStore, useViewport } from '@xyflow/react';
import { Focus, Map, Maximize, Minus, Plus } from 'lucide-react';
import './graph-navigator.css';

const decorativeNodeTypes = new Set(['context', 'codeSourceGroup']);

export interface GraphNavigatorProps {
  nodeCount: number;
  edgeCount: number;
  selectedIds: string[];
  /** Override fitting when a canvas also has lane headings outside its nodes. */
  onFitAll?: () => void;
  label?: string;
}

/** Shared navigation rendered inside the ReactFlow whose viewport it controls. */
export default function GraphNavigator({ nodeCount, edgeCount, selectedIds, onFitAll, label = 'Graph navigation' }: GraphNavigatorProps) {
  const flow = useReactFlow();
  const { zoom } = useViewport();
  const minZoom = useStore(state => state.minZoom);
  const maxZoom = useStore(state => state.maxZoom);
  const hasSelection = useStore(state => selectedIds.some(id => {
    const node = state.nodeLookup.get(id);
    return node !== undefined && !node.hidden;
  }));
  const [showMap, setShowMap] = useState(() => typeof window !== 'undefined' && window.matchMedia('(min-width: 768px)').matches);
  const [reducedMotion, setReducedMotion] = useState(() => typeof window !== 'undefined' && window.matchMedia('(prefers-reduced-motion: reduce)').matches);
  const instructionsId = useId();
  const duration = reducedMotion ? 0 : 180;
  const ready = flow.viewportInitialized && nodeCount > 0;

  useEffect(() => {
    const media = window.matchMedia('(prefers-reduced-motion: reduce)');
    const update = () => setReducedMotion(media.matches);
    media.addEventListener('change', update);
    return () => media.removeEventListener('change', update);
  }, []);

  function fitAll() {
    if (!ready) return;
    if (onFitAll) onFitAll();
    else void flow.fitView({ padding: 0.2, minZoom, maxZoom: Math.min(maxZoom, 1.2), duration });
  }

  function focusSelection() {
    const nodes = selectedIds.flatMap(id => {
      const node = flow.getNode(id);
      return node && !node.hidden ? [{ id }] : [];
    });
    if (nodes.length) void flow.fitView({ nodes, padding: 0.3, minZoom, maxZoom: Math.min(maxZoom, 1.2), duration });
  }

  function navigate(event: KeyboardEvent<HTMLDivElement>) {
    if (event.altKey || event.ctrlKey || event.metaKey || !ready) return;
    const pan = { ArrowLeft: [48, 0], ArrowRight: [-48, 0], ArrowUp: [0, 48], ArrowDown: [0, -48] }[event.key];
    if (pan) {
      const viewport = flow.getViewport();
      void flow.setViewport({ ...viewport, x: viewport.x + pan[0], y: viewport.y + pan[1] }, { duration: 0 });
    } else if (event.key === '+' || event.key === '=') void flow.zoomIn({ duration });
    else if (event.key === '-') void flow.zoomOut({ duration });
    else if (event.key === 'Home') fitAll();
    else return;
    event.preventDefault();
    event.stopPropagation();
  }

  return <>
    <Panel position="bottom-left" className="graph-navigator-controls nodrag nopan nowheel" role="group" aria-label={label} aria-describedby={instructionsId} onKeyDown={navigate}>
      <span id={instructionsId} className="graph-navigator-instructions">Use the buttons to zoom and fit the graph. Arrow keys pan while these controls have focus; Home fits all nodes.</span>
      <button type="button" aria-label="Zoom Out" title="Zoom out" disabled={!ready || zoom <= minZoom + 0.00001} onClick={() => void flow.zoomOut({ duration })}><Minus size={17} aria-hidden="true" /></button>
      <output className="graph-navigator-zoom" aria-label="Zoom level">{Math.round(zoom * 100)}%</output>
      <button type="button" aria-label="Zoom In" title="Zoom in" disabled={!ready || zoom >= maxZoom - 0.00001} onClick={() => void flow.zoomIn({ duration })}><Plus size={17} aria-hidden="true" /></button>
      <span className="graph-navigator-divider" aria-hidden="true" />
      <button type="button" aria-label="Fit View" title="Fit all nodes" disabled={!ready} onClick={fitAll}><Maximize size={17} aria-hidden="true" /></button>
      <button type="button" aria-label="Focus selected nodes" title={hasSelection ? 'Focus selected nodes' : 'Select a node or connection to focus'} disabled={!ready || !hasSelection} onClick={focusSelection}><Focus size={17} aria-hidden="true" /></button>
      <button type="button" className="graph-navigator-map-toggle" aria-label={showMap ? 'Hide minimap' : 'Show minimap'} title={showMap ? 'Hide minimap' : 'Show minimap'} aria-pressed={showMap} onClick={() => setShowMap(value => !value)}><Map size={17} aria-hidden="true" /></button>
      <span className="graph-navigator-counts">{nodeCount} nodes <span aria-hidden="true">·</span> {edgeCount} links</span>
    </Panel>
    {showMap && <MiniMap
      className="graph-navigator-minimap"
      position="bottom-right"
      style={{ width: 160, height: 100 }}
      ariaLabel={`${label}: minimap. Drag to pan; scroll to zoom.`}
      pannable
      zoomable
      nodeBorderRadius={4}
      nodeColor={node => decorativeNodeTypes.has(node.type ?? '') ? 'transparent' : selectedIds.includes(node.id) ? 'var(--primary)' : 'var(--graph-node-accent)'}
      nodeStrokeColor={node => decorativeNodeTypes.has(node.type ?? '') ? 'transparent' : 'var(--panel)'}
      nodeStrokeWidth={1}
      bgColor="var(--panel-soft)"
      maskColor="color-mix(in srgb, var(--panel) 75%, transparent)"
      maskStrokeColor="var(--primary-text)"
      maskStrokeWidth={1.5}
    />}
  </>;
}
