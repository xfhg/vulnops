import { useCallback, useMemo, useState } from 'react';
import { ReactFlowProvider } from '@xyflow/react';
import { ChevronLeft, ChevronRight, FolderTree, GitBranch, List, MapPin } from 'lucide-react';
import { buildCodeIndex, type FindingRecord } from '../../domain/index';
import { humanize, type EvidenceCallback } from '../attack-explorer/projection';
import { CodeCanvas } from './CodeCanvas';
import { CodeInspector } from './CodeInspector';
import { codeCoordinate, codeGraphWindow, codeRangeLabel, evidenceForCodeRange, groupCodeLocations, projectCodeFile, type CodeGraphNode } from './projection';
import '../attack-explorer/explorer.css';
import './code-map.css';

// Kept as a public export for existing scope-qualified file grouping consumers.
export { groupCodeLocations } from './projection';
export interface CodeMapProps {
  findings: FindingRecord[];
  selected?: string;
  onSelect?: (key: string) => void;
  onFinding: (findingKey: string) => void;
  onEvidence?: EvidenceCallback;
}

export default function CodeMap({ findings, selected: controlled, onSelect, onFinding, onEvidence }: CodeMapProps) {
  const [query, setQuery] = useState('');
  const [component, setComponent] = useState('');
  const [view, setView] = useState<'graph' | 'locations'>('graph');
  const [localSelection, setLocalSelection] = useState('');
  const [graphSelection, setGraphSelection] = useState({ file: '', id: '', page: 0 });
  const requested = controlled ?? localSelection;
  const locations = useMemo(() => buildCodeIndex(findings), [findings]);
  const files = useMemo(() => groupCodeLocations(locations.filter(location => (!component || location.componentKeys.includes(component)) &&
    `${location.file} ${location.scope ?? ''} ${location.explanations.join(' ')}`.toLowerCase().includes(query.toLowerCase()))), [locations, component, query]);
  const allFiles = useMemo(() => groupCodeLocations(locations), [locations]);
  const rankedFiles = useMemo(() => [...files].sort((a, b) => new Set(b.locations.flatMap(location => location.findingKeys)).size - new Set(a.locations.flatMap(location => location.findingKeys)).size ||
    b.locations.filter(location => location.roles.includes('repair')).length - a.locations.filter(location => location.roles.includes('repair')).length || a.key.localeCompare(b.key)), [files]);
  const selected = requested || rankedFiles[0]?.key || '';
  const active = allFiles.find(file => file.key === selected);
  const repos = [...new Set(files.map(file => file.repository))];
  const components = [...new Map(findings.flatMap(finding => finding.components.map(item => [item.key, item] as const))).values()];
  const findingMap = new Map(findings.map(finding => [finding.key, finding]));
  const associated = active ? [...new Set(active.locations.flatMap(location => location.findingKeys))].map(key => findingMap.get(key)).filter((finding): finding is FindingRecord => Boolean(finding)) : [];
  const graph = useMemo(() => active ? projectCodeFile(active, findings) : null, [active, findings]);
  const rangeNodes = graph?.nodes.filter(node => node.kind === 'location') ?? [];
  const initialRange = Math.max(0, rangeNodes.findIndex(node => node.roles.includes('root_cause') || node.roles.includes('repair')));
  const requestedPage = graphSelection.file === selected ? graphSelection.page : Math.floor(initialRange / 5);
  const window = useMemo(() => graph ? codeGraphWindow(graph, requestedPage) : null, [graph, requestedPage]);
  const graphSelected = graphSelection.file === selected && graphSelection.id ? graphSelection.id : window?.nodes.find(node => node.kind === 'location' && (node.roles.includes('root_cause') || node.roles.includes('repair')))?.id ?? window?.nodes.find(node => node.kind === 'location')?.id ?? '';
  const choose = (key: string) => { setLocalSelection(key); onSelect?.(key); };
  const selectGraph = useCallback((id: string) => setGraphSelection({ file: selected, id, page: requestedPage }), [selected, requestedPage]);
  const openGraphNode = useCallback((node: CodeGraphNode) => {
    if (node.kind === 'location') {
      const original = active ? evidenceForCodeRange(node, active.file) : undefined;
      if (original) onEvidence?.(original.reference, original.runId);
      else if (active) onEvidence?.(codeCoordinate(active.file, node.line ?? null, node.endLine ?? null), node.runId);
    } else if (node.findingKeys[0]) onFinding(node.findingKeys[0]);
  }, [active, onEvidence, onFinding]);
  const moveWindow = (page: number) => setGraphSelection({ file: selected, id: '', page });

  return <section className="stake-code-map" aria-label="Cited code map">
    <div className="code-map-intro"><div><span className="graph-eyebrow">SOURCE RELATIONSHIPS</span><h2>Connect findings to the code that matters</h2><p>Follow recorded citations from a finding to its source ranges and proposed repair points.</p></div>
      <div className="code-map-metrics"><strong>{files.length}</strong><span>cited files</span><strong>{locations.length}</strong><span>recorded locations</span></div></div>
    <div className="code-map-filters"><label>Find a file<input type="search" placeholder="Path, symbol or explanation…" value={query} onChange={event => setQuery(event.target.value)} /></label>
      <label>Component<select value={component} onChange={event => setComponent(event.target.value)}><option value="">All cited components</option>
        {components.map(item => <option value={item.key} key={item.key}>{item.name} · {item.repository ?? 'Unknown repository'}</option>)}
      </select></label>{(query || component) && <button className="graph-view-toggle" onClick={() => { setQuery(''); setComponent(''); }}>Reset filters</button>}</div>
    <div className="code-map-panes"><nav className="code-map-tree" aria-label="Cited repositories and files">
      <div className="cg-tree-title"><FolderTree size={14}/><strong>Source files</strong><span>{files.length}</span></div>
      {!files.length && <p className="graph-empty">No cited files match these filters.</p>}
      {repos.map(repository => <details key={repository} open><summary><span>▱ {repository}</span><span>{files.filter(file => file.repository === repository).length}</span></summary>
        <ul>{files.filter(file => file.repository === repository).map(file => <li key={file.key}>
          <button className={`code-file-button ${selected === file.key ? 'active' : ''}`} onClick={() => choose(file.key)} aria-current={selected === file.key ? 'true' : undefined}>
            <strong>{file.file.split('/').at(-1)}</strong><span>{file.file}</span><small>{file.sourceView ?? 'Source view unknown'} · {file.runId}</small>
            <span className="code-file-count">{new Set(file.locations.flatMap(location => location.findingKeys)).size} findings · {file.locations.length} locations</span>
          </button></li>)}</ul></details>)}
    </nav><div className="code-map-detail">
      {!active ? <div className="graph-inspector-empty"><span className="graph-empty-mark">⌘</span><h3>{requested ? 'Selected file unavailable' : 'No cited files in this scope'}</h3><p>{requested ? 'The selected location does not belong to the loaded assessment scope.' : 'Adjust the filters or load an assessment with recorded source locations.'}</p></div> : <>
        <div className="cg-file-header"><div><span className="graph-eyebrow">{active.repository}</span><h3 className="code-path-title">{active.file}</h3></div><div className="cg-view-switch" aria-label="Code map view"><button type="button" aria-pressed={view === 'graph'} onClick={() => setView('graph')}><GitBranch size={13}/>Relationships</button><button type="button" aria-pressed={view === 'locations'} onClick={() => setView('locations')}><List size={13}/>Locations</button></div></div>
        <div className="code-scope"><span>Execution: {active.runId}</span><span>Assessment: {active.scopeId ?? 'Unknown'}</span><span>Source view: {active.sourceView ?? 'Unknown'}</span></div>
        {view === 'graph' && graph && window && <div className="cg-workspace">
          <div className="cg-graph-heading"><div><strong>Finding → source → proposed repair</strong><p>Lines show recorded associations, not call or execution flow.</p></div><span>{associated.length} {associated.length === 1 ? 'finding' : 'findings'} · {graph.nodes.filter(node => node.kind === 'repair').length} proposed actions</span></div>
          {window.nodes.length ? <ReactFlowProvider key={active.key}><CodeCanvas file={active} graphNodes={window.nodes} graphEdges={window.edges} selected={graphSelected} toolbarVisible={graphSelection.file === selected && Boolean(graphSelection.id)} onSelect={selectGraph} onOpen={openGraphNode}/></ReactFlowProvider> : <p className="graph-empty">No graphable citations are recorded for this file.</p>}
          <div className="cg-graph-footer"><div className="cg-legend"><span><i/>Finding citation</span><span><i className="repair"/>Proposed change location</span><span><i className="support"/>Repair evidence</span></div>
            <div className="cg-window-controls"><span>Ranges {window.start}–{window.end} of {window.total}</span><button type="button" aria-label="Previous cited ranges" disabled={window.page === 0} onClick={() => moveWindow(window.page - 1)}><ChevronLeft size={15}/></button><button type="button" aria-label="Next cited ranges" disabled={window.page + 1 >= window.pages} onClick={() => moveWindow(window.page + 1)}><ChevronRight size={15}/></button></div></div>
          <details className="cg-connection-list"><summary>Browse {window.edges.length} visible connections as a list</summary><ul>{window.edges.map(edge => <li key={edge.id}><button type="button" aria-pressed={graphSelected === edge.id} onClick={() => selectGraph(edge.id)}><span>{edge.findingId}</span><strong>{edge.label}</strong><small>{graph.nodes.find(node => node.id === (edge.kind === 'citation' ? edge.target : edge.source))?.label}</small></button></li>)}</ul></details>
          <CodeInspector graph={graph} selected={graphSelected} onFinding={onFinding} onEvidence={onEvidence}/>
          {graph.diagnostics.length > 0 && <details className="cg-diagnostics"><summary>{graph.diagnostics.length} unresolved graph {graph.diagnostics.length === 1 ? 'reference' : 'references'}</summary><ul>{graph.diagnostics.map(message => <li key={message}>{message}</li>)}</ul></details>}
        </div>}
        <p className="code-location-note"><MapPin size={14}/>Recorded coordinates only. This map does not establish the current file content or complete repository coverage.</p>
        <section><h4>Related findings</h4><div className="code-related-findings">{associated.map(finding => <button key={finding.key} onClick={() => onFinding(finding.key)}>
          <span className={`graph-status ${finding.cohort === 'needs_environment' ? 'uncertain' : 'recorded'}`}>{finding.id} · {humanize(finding.cohort)}</span><strong>{finding.title}</strong></button>)}</div></section>
        <section><h4>Locations and repair points <span className="cg-count">{active.locations.length}</span></h4><ol className="code-location-list">{active.locations.map(location => <li key={location.key}>
          <div className="code-location-heading"><button className="graph-reference" onClick={() => onEvidence?.(codeCoordinate(location.file, location.line, location.endLine), location.runId)} disabled={!onEvidence}>
            {codeRangeLabel(location.line, location.endLine)}
          </button><div>{location.roles.map(role => <span key={role} className={`graph-status ${role === 'repair' ? 'repair' : ''}`}>{role === 'repair' ? 'Proposed repair location' : humanize(role)}</span>)}</div></div>
          {location.scope && <strong>{location.scope}</strong>}
          {location.explanations.map((explanation, index) => <p key={index}>{explanation}</p>)}
          <div className="code-location-findings">{location.findingKeys.map(key => findingMap.get(key)).filter((finding): finding is FindingRecord => Boolean(finding)).map(finding => <button key={finding.key} onClick={() => onFinding(finding.key)}>{finding.id} ↗</button>)}</div>
        </li>)}</ol></section>
      </>}
    </div></div>
  </section>;
}
