import { lazy, Suspense, useEffect, useMemo, useState } from 'react';
import { MarkerType, ReactFlowProvider, type Edge } from '@xyflow/react';
import { ArrowUpRight, GitBranch, Route, Search, Layers3 } from 'lucide-react';
import '@xyflow/react/dist/style.css';
import type { FindingRecord } from '../../domain';
import { buildCompositionOverview, buildEntrypointIndex, chainForSelection, compositionCounts, overviewChainId, overviewFindingId, overviewUnassignedId,
  type EntrypointCluster, type EntrypointIndex, type OverviewMode, type EntrypointSort, type CompositionSort } from './model';
import OverviewCanvas, { type OverviewGraphNode, type OverviewLane } from './OverviewCanvas';
import { entrypointLanes } from './graph-groups';
import './entrypoints.css';

const AttackExplorer = lazy(() => import('../attack-explorer/AttackExplorer'));
type EvidenceHandler = (reference: unknown, runId: string) => void;
type FindingHandler = (finding: FindingRecord, mode?: 'procedure' | 'trace' | 'composition') => void;
type ReadRepairHandler = (finding: FindingRecord, actionId: string, locationIndex?: number) => void;
export interface EntrypointExplorerProps {
  findings: FindingRecord[];
  mode?: OverviewMode;
  selected?: string;
  onModeChange?: (mode: OverviewMode) => void;
  entrySort?: EntrypointSort;
  chainSort?: CompositionSort;
  onEntrySortChange?: (sort: EntrypointSort) => void;
  onChainSortChange?: (sort: CompositionSort) => void;
  onSelect?: (id: string) => void;
  onFinding: FindingHandler;
  onReadRepair?: ReadRepairHandler;
  onEvidence?: EvidenceHandler;
}

const human = (value: string | null) => value?.replaceAll('_', ' ') || 'Unknown';
const scopeLabel = (runId: string, scopeId: string | null, sourceView: string | null) =>
  `${runId} · ${scopeId || 'Scope unknown'} · ${sourceView || 'Source view unknown'}`;
function EntrypointCanvas({ index, selected, onSelect, onFinding }: { index: EntrypointIndex; selected: string; onSelect: (id: string) => void; onFinding: FindingHandler }) {
  const unassignedKeys = new Set(index.unassigned.map(finding => finding.key));
  const graphNodes: OverviewGraphNode[] = [
    ...index.clusters.map(cluster => ({ id: cluster.id, laneId: '', column: 0 as const, data: { kind: 'entrypoint' as const, title: cluster.label,
      caption: cluster.repository || 'Repository unknown',
      label: `${cluster.findingKeys.length} finding${cluster.findingKeys.length === 1 ? '' : 's'}`,
      status: cluster.findingKeys.length > 1 ? 'Shared recorded entrypoint' : 'Recorded entrypoint', shared: cluster.findingKeys.length > 1,
      facts: [{ label: 'component refs', value: new Set(cluster.citations.map(c => JSON.stringify([c.findingKey, c.componentId]))).size },
        { label: 'references', value: new Set(cluster.citations.flatMap(c => c.evidence.map(ref => JSON.stringify(ref)))).size }] } })),
    ...index.findings.filter(finding => index.unassigned.length < 2 || !unassignedKeys.has(finding.key)).map(finding => ({ id: overviewFindingId(finding.key), laneId: '', column: 1 as const, data: { kind: 'finding' as const, title: finding.title,
      caption: human(finding.cohort), eyebrow: finding.id, label: human(finding.severity),
      status: unassignedKeys.has(finding.key) ? 'No recorded entrypoint' : human(finding.verificationLevel), unassigned: unassignedKeys.has(finding.key),
      facts: [{ label: 'steps', value: finding.stepCount }, { label: 'repairs', value: finding.repairCount }, { label: 'trace entries', value: finding.traceCount }],
      onOpen: () => onFinding(finding) } })),
    ...(index.unassigned.length > 1 ? [{ id: overviewUnassignedId, laneId: '', column: 1 as const, data: { kind: 'finding' as const, title: 'Unassigned entrypoints', caption: 'Individual records and scopes remain available in the list', label: `${index.unassigned.length} findings`, status: 'Select to explore all unassigned findings', unassigned: true } }] : []),
  ];
  const edges: Edge[] = index.associations.map(association => ({ id: association.id, source: association.entrypointId, target: overviewFindingId(association.findingKey),
    selected: selected === association.id, focusable: true, label: 'cited entrypoint', data: {
      detail: `${index.clusters.find(cluster => cluster.id === association.entrypointId)?.citations.filter(citation => citation.findingKey === association.findingKey).length ?? 0} component citations · association only`,
    },
    ariaLabel: 'Recorded entrypoint citation. Association only; no capability transition is asserted.',
    style: { stroke: selected === association.id ? 'var(--graph-node-accent)' : 'var(--graph-edge)', strokeWidth: selected === association.id ? 2.5 : 1.3, strokeDasharray: '4 4' } }));
  const grouped = entrypointLanes(graphNodes, edges, index);
  return <OverviewCanvas graphNodes={grouped.nodes} edges={edges} lanes={grouped.lanes} placement="bipartite" selected={selected} onSelect={onSelect} label="Entrypoint findings graph" />;
}

function FindingLink({ finding, onFinding, mode }: { finding: FindingRecord; onFinding: FindingHandler; mode?: 'composition' }) {
  return <button type="button" className="ep-finding-link" onClick={() => onFinding(finding, mode)}>
    <span><span className="ep-kicker">{finding.id} · {human(finding.severity)} · {human(finding.cohort)}</span><strong>{finding.title}</strong>
      <small>{scopeLabel(finding.runId, finding.scopeId, finding.sourceView)}</small></span><ArrowUpRight size={16} aria-hidden="true" />
  </button>;
}

function ClusterScope({ cluster }: { cluster: EntrypointCluster }) {
  return <dl className="ep-scope"><div><dt>Execution</dt><dd>{cluster.runId}</dd></div><div><dt>Assessment scope</dt><dd>{cluster.scopeId || 'Unknown'}</dd></div>
    <div><dt>Source view</dt><dd>{cluster.sourceView || 'Unknown'}</dd></div><div><dt>Repository</dt><dd>{cluster.repository || 'Unknown'}</dd></div></dl>;
}

function EntrypointInspector({ index, selected, onFinding, onEvidence }: { index: EntrypointIndex; selected: string; onFinding: FindingHandler; onEvidence?: EvidenceHandler }) {
  const association = index.associations.find(association => association.id === selected);
  const cluster = index.clusters.find(cluster => cluster.id === (association?.entrypointId ?? selected));
  const finding = index.findings.find(finding => overviewFindingId(finding.key) === selected);
  const related = cluster ? index.findings.filter(finding => cluster.findingKeys.includes(finding.key) && (!association || association.findingKey === finding.key)) : [];
  return <aside className="ep-inspector" aria-label="Entrypoint evidence inspector"><header>Recorded relationships</header>
    {selected === overviewUnassignedId ? <div className="ep-inspector-body"><span className="ep-kicker">{index.unassigned.length} individual records</span><h3>Unassigned entrypoints</h3><p className="ep-explanation">No explicit component entrypoint is recorded for these findings. Each retains its own execution, assessment scope and disposition.</p>{index.unassigned.map(finding => <FindingLink key={finding.key} finding={finding} onFinding={onFinding} />)}</div>
      : !cluster && !finding ? <div className="ep-inspector-empty"><Route size={28} /><h3>{selected ? 'Selection unavailable' : 'Start at an entrypoint'}</h3><p>{selected ? 'This record is not present in the currently loaded assessment scope.' : 'Select an entrypoint to see the findings that cite it, their original scope and the supporting references.'}</p></div>
      : cluster ? <div className="ep-inspector-body"><span className="ep-kicker">{association ? 'Recorded citation' : `${related.length} associated finding${related.length === 1 ? '' : 's'}`}</span><h3>{cluster.label}</h3>
        <p className="ep-explanation">These findings name the same exact entrypoint within this assessed scope. This association does not establish an attack chain or a deployed service binding.</p>
        <ClusterScope cluster={cluster} />{cluster.incompleteScope && <p className="ep-note">Scope metadata is incomplete. This label is isolated to its owning finding.</p>}
        <h4>Associated findings</h4>{related.map(finding => <FindingLink key={finding.key} finding={finding} onFinding={onFinding} />)}
        <h4>Recorded component citations</h4>{cluster.citations.filter(citation => !association || citation.findingKey === association.findingKey).map((citation, index) => {
          const owner = related.find(finding => finding.key === citation.findingKey);
          return <div className="ep-citation" key={index}><strong>{citation.componentName || citation.componentId}</strong><span>{citation.componentId} · {owner?.id}</span><code>{citation.recordedLabel}</code>
            {citation.evidence.length ? [...new Map(citation.evidence.map(reference => [JSON.stringify(reference), reference])).values()].map((reference, index) => <button type="button" key={index} disabled={!onEvidence || !owner} onClick={() => owner && onEvidence?.(reference, owner.runId)}>{typeof reference === 'string' ? reference : 'Recorded component reference'}</button>) : <small>No supporting references recorded on this component.</small>}
          </div>;
        })}</div>
      : finding && <div className="ep-inspector-body"><span className="ep-kicker">{finding.id} · {human(finding.severity)}</span><h3>{finding.title}</h3><p>{finding.attackSummary || finding.impact || 'No attack summary recorded.'}</p>
        <p className="ep-explanation">{scopeLabel(finding.runId, finding.scopeId, finding.sourceView)}</p><p className="ep-status-label">{human(finding.cohort)} · {human(finding.verificationLevel)}</p>
        <h4>Recorded entrypoints</h4>{index.clusters.filter(cluster => cluster.findingKeys.includes(finding.key)).map(cluster => <p key={cluster.id} className="ep-related-route"><code>{cluster.label}</code><small>{cluster.repository || 'Repository unknown'}</small></p>)}
        {index.unassigned.some(item => item.key === finding.key) && <p className="ep-note">No explicit component entrypoint is recorded. Source symbols and trace locations have not been turned into route labels.</p>}
        <button type="button" className="ep-open-finding" onClick={() => onFinding(finding)}>Open finding <ArrowUpRight size={15} /></button>
      </div>}
  </aside>;
}

function EntrypointList({ index, selected, onSelect, onFinding }: { index: EntrypointIndex; selected: string; onSelect: (id: string) => void; onFinding: FindingHandler }) {
  return <div className="ep-linear-list" aria-label="Entrypoint associations list">{index.clusters.map(cluster => <section key={cluster.id} className="ep-linear-cluster">
    <button type="button" className={'ep-linear-heading ' + (selected === cluster.id ? 'active' : '')} onClick={() => onSelect(cluster.id)}>
      <span><code>{cluster.label}</code><small>{cluster.repository || 'Repository unknown'} · {scopeLabel(cluster.runId, cluster.scopeId, cluster.sourceView)}</small></span>
      <span className="ep-count">{cluster.findingKeys.length} finding{cluster.findingKeys.length === 1 ? '' : 's'}</span>
    </button><p className="ep-linear-relation">Recorded entrypoint citations · no inferred composition</p>
    {index.findings.filter(finding => cluster.findingKeys.includes(finding.key)).map(finding => <div className="ep-linear-finding" key={finding.key}>
      <button type="button" aria-pressed={selected === overviewFindingId(finding.key)} onClick={() => onSelect(overviewFindingId(finding.key))}><span>{finding.id} · {human(finding.cohort)}</span><strong>{finding.title}</strong></button>
      <button type="button" className="ep-open-inline" aria-label={`Open finding ${finding.id}`} onClick={() => onFinding(finding)}><ArrowUpRight size={16} /></button>
    </div>)}
  </section>)}{index.unassigned.length > 0 && <section className="ep-linear-cluster"><h3>Unassigned entrypoints <span className="ep-count">{index.unassigned.length}</span></h3><p className="ep-linear-relation">These findings have no explicit component entrypoint label.</p>
    {index.unassigned.map(finding => <div className="ep-linear-finding" key={finding.key}><button type="button" aria-pressed={selected === overviewFindingId(finding.key)} onClick={() => onSelect(overviewFindingId(finding.key))}><span>{finding.id} · {human(finding.cohort)}</span><strong>{finding.title}</strong></button><button type="button" className="ep-open-inline" aria-label={`Open finding ${finding.id}`} onClick={() => onFinding(finding)}><ArrowUpRight size={16} /></button></div>)}
  </section>}</div>;
}

function CompositionCanvas({ overview, selected, onSelect, onFinding }: { overview: ReturnType<typeof buildCompositionOverview>; selected: string; onSelect: (id: string) => void; onFinding: FindingHandler }) {
  const lanes: OverviewLane[] = overview.chains.map(({ finding }) => ({ id: finding.key, selectionId: overviewChainId(finding.key),
    title: finding.title, subtitle: `${finding.id} · ${human(finding.severity)} · ${human(finding.cohort)}`, detail: scopeLabel(finding.runId, finding.scopeId, finding.sourceView) }));
  const graphNodes: OverviewGraphNode[] = [
    ...overview.nodes.map(node => ({ id: node.id, laneId: node.finding.key, data: { kind: 'primitive' as const, title: typeof node.raw.output_capability === 'string' && node.raw.output_capability.trim() ? node.raw.output_capability : 'Output capability not recorded',
      eyebrow: `${node.finding.id} · Primitive`, caption: node.caption || 'Boundary not recorded', label: node.localId, status: `${node.evidence.length} recorded references`,
      input: typeof node.raw.input_capability === 'string' ? node.raw.input_capability : undefined, onOpen: () => onFinding(node.finding, 'composition') } })),
    ...overview.unavailable.map(finding => ({ id: overviewChainId(finding.key), laneId: finding.key, data: { kind: 'finding' as const,
      title: 'Primitive details not recorded', eyebrow: finding.id, caption: finding.title, label: human(finding.cohort), status: 'Select to inspect this finding' } })),
  ];
  const edges: Edge[] = overview.edges.map(edge => ({ id: edge.id, source: edge.source, target: edge.target, label: edge.label, selected: selected === edge.id, focusable: true,
    data: { detail: `${edge.details.filter(detail => !['Producer', 'Consumer', 'Resolution'].includes(detail.label)).length} recorded obligations · ${edge.evidence.length} references` },
    ariaLabel: `${edge.finding.id}: ${edge.label}. Recorded capability transition.`, markerEnd: { type: MarkerType.ArrowClosed, color: edge.status === 'established' ? 'var(--graph-edge)' : 'var(--graph-unresolved)' },
    style: { stroke: edge.status === 'established' ? 'var(--graph-edge)' : 'var(--graph-unresolved)', strokeWidth: selected === edge.id ? 2.5 : 1.5, strokeDasharray: edge.status === 'established' ? undefined : '5 4' } }));
  return <OverviewCanvas graphNodes={graphNodes} edges={edges} lanes={lanes} selected={selected} onSelect={onSelect} label="All recorded compositions graph" />;
}

function ComposedAttacks({ index, sort, onSortChange, selected, onSelect, onFinding, onReadRepair, onEvidence }: { index: EntrypointIndex; sort: CompositionSort; onSortChange: (sort: CompositionSort) => void; selected: string; onSelect: (id: string) => void; onFinding: FindingHandler; onReadRepair?: ReadRepairHandler; onEvidence?: EvidenceHandler }) {
  const [linear, setLinear] = useState(false);
  const overview = useMemo(() => buildCompositionOverview(index.chains, sort), [index.chains, sort]);
  const current = selected ? chainForSelection(index.chains, selected) : index.chains[0];
  return <div className="ep-composed"><p className="ep-mode-description">One lane per attack. Follow recorded capability transitions from left to right; select a card to inspect the evidence.</p>
    {!index.chains.length ? <div className="ep-empty"><GitBranch size={28} /><h3>No composed attacks recorded</h3><p>Findings that share an entrypoint remain visible in the entrypoint map. Shared labels do not create a chain.</p></div> : <>
      <div className="ep-order-bar"><label>Order attacks<select aria-label="Order attacks" value={sort} onChange={event => onSortChange(event.target.value as CompositionSort)}><option value="priority">Finding priority</option><option value="id">Finding ID</option></select></label><p>{sort === 'priority' ? 'Disposition → severity → finding ID. Confirmed findings appear first.' : 'Natural finding ID order, with execution and scope as tiebreakers.'} Primitive positions follow recorded dependencies.</p></div>
      <div className="ep-composition-heading"><h3>All recorded compositions <span>{index.chains.length} separate attacks</span></h3><button type="button" className="ep-view-toggle" aria-pressed={linear} onClick={() => setLinear(value => !value)}>{linear ? 'Show all compositions graph' : 'Linear compositions view'}</button></div>
      <div className="ep-all-compositions">{linear ? <div className="ep-composition-list" aria-label="All recorded compositions list">{overview.chains.map(({ finding, projection }) => <section key={finding.key}><h4>{finding.id} · {finding.title}</h4><p>{scopeLabel(finding.runId, finding.scopeId, finding.sourceView)}</p>
        {projection.nodes.map(node => <div key={node.id}><button type="button" aria-pressed={selected === node.id} onClick={() => onSelect(node.id)}><span>{node.localId} · Recorded primitive</span><strong>{node.label}</strong><small>{node.caption}</small></button>{projection.edges.filter(edge => edge.source === node.id).map(edge => <button type="button" key={edge.id} className={'ep-linear-transition ' + (edge.status === 'established' ? '' : 'is-unresolved')} aria-pressed={selected === edge.id} onClick={() => onSelect(edge.id)}>→ {projection.nodes.find(node => node.id === edge.target)?.localId} · {edge.label} · Inspect recorded transition</button>)}</div>)}
        {!projection.nodes.length && <button type="button" onClick={() => onSelect(overviewChainId(finding.key))}>Primitive details not recorded · Inspect this chain</button>}
        {projection.diagnostics.map(message => <p className="ep-chain-limitation" key={message}>{message}</p>)}
      </section>)}</div> : <ReactFlowProvider><CompositionCanvas overview={overview} selected={selected} onSelect={onSelect} onFinding={onFinding} /></ReactFlowProvider>}<div className="ep-map-legend"><span>Arrows follow explicit transitions within each finding</span><span>{overview.nodes.length} primitives · {overview.edges.length} recorded edges · {overview.unavailable.length} without primitive details</span></div></div>
      <div className="ep-chain-cards" aria-label="Recorded composed attacks">{index.chains.map(finding => {
        const counts = compositionCounts(finding);
        return <button type="button" key={finding.key} className={'ep-chain-card ' + (current?.key === finding.key ? 'active' : '')} aria-pressed={current?.key === finding.key} onClick={() => onSelect(overviewChainId(finding.key))}>
          <span className="ep-kicker">{finding.id} · {human(finding.severity)} · {human(finding.cohort)}</span><strong>{finding.title}</strong><small>{scopeLabel(finding.runId, finding.scopeId, finding.sourceView)}</small>
          <span className="ep-chain-counts"><span>{counts.primitives} primitives</span><span>{counts.transitions} recorded transitions</span></span>
          {counts.unresolved > 0 && <span className="ep-chain-limitation">{counts.unresolved} transition{counts.unresolved === 1 ? '' : 's'} not established</span>}
          {!counts.primitives && <span className="ep-chain-limitation">Primitive details not recorded</span>}
        </button>;
      })}</div>
      {current ? <section className="ep-selected-chain" aria-label="Selected composed attack"><div className="ep-chain-heading"><div><span className="ep-kicker">{current.id} · {current.runId}</span><h3>{current.title}</h3></div><button type="button" className="ep-open-finding" onClick={() => onFinding(current, 'composition')}>Open full finding <ArrowUpRight size={15} /></button></div>
        <Suspense fallback={<p role="status" className="ep-mode-description">Loading recorded composition…</p>}><AttackExplorer key={current.key} finding={current} mode="composition" selected={selected.startsWith('["entity",') ? selected : ''}
          onSelect={onSelect} onModeChange={mode => onFinding(current, mode)} onReadRepair={onReadRepair ? (actionId, locationIndex) => onReadRepair(current, actionId, locationIndex) : undefined} onEvidence={onEvidence} /></Suspense>
      </section> : <div className="ep-empty" role="status"><h3>Selected chain unavailable</h3><p>Choose a recorded chain from the current assessment scope.</p></div>}
    </>}
  </div>;
}

export default function EntrypointExplorer({ findings, mode: controlledMode, selected: controlledSelected, onModeChange, entrySort: controlledEntrySort, chainSort: controlledChainSort, onEntrySortChange, onChainSortChange, onSelect, onFinding, onReadRepair, onEvidence }: EntrypointExplorerProps) {
  const [localMode, setLocalMode] = useState<OverviewMode>('entrypoints');
  const [localSelected, setLocalSelected] = useState('');
  const [linear, setLinear] = useState(false);
  const [query, setQuery] = useState('');
  const [focusedEntry, setFocusedEntry] = useState(controlledSelected ? '' : 'auto');
  const [localEntrySort, setLocalEntrySort] = useState<EntrypointSort>('shared');
  const [localChainSort, setLocalChainSort] = useState<CompositionSort>('priority');
  const entrySort = controlledEntrySort ?? localEntrySort;
  const chainSort = controlledChainSort ?? localChainSort;
  const mode = controlledMode ?? localMode;
  const selected = controlledSelected ?? localSelected;
  const index = useMemo(() => buildEntrypointIndex(findings, entrySort, chainSort), [findings, entrySort, chainSort]);
  // Dense atlases start at one ranked route; every association remains available explicitly.
  const automaticFocus = focusedEntry === 'auto' && index.clusters.length > 24 && !query.trim();
  const effectiveFocus = focusedEntry === 'auto' ? automaticFocus ? index.clusters[0]?.id || '' : '' : focusedEntry;
  useEffect(() => {
    if (focusedEntry && focusedEntry !== 'auto' && focusedEntry !== 'unassigned' && !index.clusters.some(cluster => cluster.id === focusedEntry)) setFocusedEntry('');
  }, [index, focusedEntry]);
  const visibleIndex = useMemo(() => {
    const needle = query.trim().toLocaleLowerCase();
    if (!needle && !effectiveFocus) return index;
    const candidates = effectiveFocus === 'unassigned' ? [] : index.clusters.filter(cluster => !effectiveFocus || cluster.id === effectiveFocus);
    const scopedKeys = effectiveFocus === 'unassigned' ? new Set(index.unassigned.map(finding => finding.key)) : effectiveFocus ? new Set(candidates.flatMap(cluster => cluster.findingKeys)) : new Set(index.findings.map(finding => finding.key));
    const matchingFindings = new Set(index.findings.filter(finding => scopedKeys.has(finding.key) && [finding.id, finding.title, finding.runId].some(value => value.toLocaleLowerCase().includes(needle))).map(finding => finding.key));
    const clusters = candidates.filter(cluster => [cluster.label, cluster.repository, cluster.runId].some(value => value?.toLocaleLowerCase().includes(needle)) || cluster.findingKeys.some(key => matchingFindings.has(key)));
    const keys = new Set([...matchingFindings, ...clusters.flatMap(cluster => cluster.findingKeys)]);
    const clusterIds = new Set(clusters.map(cluster => cluster.id));
    return { ...index, clusters, associations: index.associations.filter(association => clusterIds.has(association.entrypointId)), findings: index.findings.filter(finding => keys.has(finding.key)), unassigned: index.unassigned.filter(finding => keys.has(finding.key)) };
  }, [index, query, effectiveFocus]);
  const select = (id: string) => { if (id === overviewUnassignedId) { setFocusedEntry('unassigned'); setLinear(true); } setLocalSelected(id); onSelect?.(id); };
  const changeMode = (next: OverviewMode) => { setLocalMode(next); setLocalSelected(''); if (onModeChange) onModeChange(next); else onSelect?.(''); };
  const shared = index.clusters.filter(cluster => cluster.findingKeys.length > 1).length;
  return <section className="entrypoint-explorer" aria-label="Attack overview"><div className="ep-page-heading"><div><p className="ep-kicker">ATTACK OVERVIEW</p><h1>Follow the entry. Understand the chain.</h1><p>Find shared entrypoints, inspect recorded compositions, and open the evidence behind each finding.</p></div><span>{index.findings.length} findings in scope</span></div><div className="ep-overview-stats">
    <div><Route size={17} /><strong>{index.clusters.length}</strong><span>recorded entrypoints</span></div><div><Layers3 size={17} /><strong>{shared}</strong><span>shared entrypoint{shared === 1 ? '' : 's'}</span></div><div><GitBranch size={17} /><strong>{index.chains.length}</strong><span>recorded composed attacks</span></div><div><strong>{index.unassigned.length}</strong><span>unassigned findings</span></div>
  </div><div className="ep-toolbar"><div role="tablist" aria-label="Attack overview representation" className="ep-tabs"><button type="button" role="tab" aria-selected={mode === 'entrypoints'} onClick={() => changeMode('entrypoints')}><Route size={15} />Entry points</button><button type="button" role="tab" aria-selected={mode === 'composed'} onClick={() => changeMode('composed')}><GitBranch size={15} />Composed attacks <span>{index.chains.length}</span></button></div>
    {mode === 'entrypoints' && <button type="button" className="ep-view-toggle" aria-pressed={linear} onClick={() => setLinear(value => !value)}>{linear ? 'Show entrypoint graph' : 'Linear entrypoint view'}</button>}
  </div>{mode === 'entrypoints' ? <><div className="ep-map-description"><p>See which findings cite the same entrypoint. Dashed links are recorded associations; only the composed-attacks view shows capability transitions.</p><label className="ep-search"><Search size={14} /><input aria-label="Find entrypoint or finding" placeholder="Find an entrypoint or finding…" value={query} onChange={event => setQuery(event.target.value)} /></label></div>
    <div className="ep-order-bar"><label>Order entrypoints<select aria-label="Order entrypoints" value={entrySort} onChange={event => { const next = event.target.value as EntrypointSort; setLocalEntrySort(next); onEntrySortChange?.(next); }}><option value="shared">Most shared first</option><option value="priority">Finding priority</option><option value="route">Repository / route</option></select></label><p>{entrySort === 'shared' ? 'Most associated findings first, then finding priority.' : entrySort === 'priority' ? 'Highest-priority associated finding first, then number of findings.' : 'Repository and route in natural alphabetical order.'} Related cards stay together; findings follow disposition, severity and ID.</p></div>
    <div className="ep-map-controls"><label>Focus entrypoint<select aria-label="Focus entrypoint" value={automaticFocus ? "auto" : effectiveFocus} onChange={event => setFocusedEntry(event.target.value)}>{index.clusters.length > 24 && <option value="auto">Highest-ranked entrypoint</option>}<option value="">All recorded associations</option>{index.clusters.map(cluster => <option key={cluster.id} value={cluster.id}>{cluster.label} · {cluster.repository || 'Repository unknown'} · {scopeLabel(cluster.runId, cluster.scopeId, cluster.sourceView)} · {cluster.findingKeys.length} findings</option>)}<option value="unassigned">Unassigned entrypoints · {index.unassigned.length} findings</option></select></label><div className="ep-scope-note">{automaticFocus && <strong className="ep-auto-focus-note">Showing the highest-ranked of {index.clusters.length} entrypoints. Choose “All recorded associations” for the full map.</strong>}Each execution, assessment scope, source view and repository stays separate. Labels are matched exactly; trace symbols are not inferred entrypoints.</div></div>
    {visibleIndex.findings.length ? <div className="ep-panes"><div className="ep-map-main">{linear ? <EntrypointList index={visibleIndex} selected={selected} onSelect={select} onFinding={onFinding} /> : <ReactFlowProvider><EntrypointCanvas index={visibleIndex} selected={selected} onSelect={select} onFinding={onFinding} /></ReactFlowProvider>}<div className="ep-map-legend"><span><i />Recorded entrypoint citation</span><span>{visibleIndex.findings.length} findings · {visibleIndex.clusters.length} scoped entrypoints</span></div></div><EntrypointInspector index={index} selected={selected} onFinding={onFinding} onEvidence={onEvidence} /></div>
      : <div className="ep-empty"><Route size={28} /><h3>{query ? 'No matching entrypoints or findings' : 'No findings in this scope'}</h3><p>{query ? 'Search by an exact route fragment, finding title, ID or execution.' : 'Choose another loaded assessment or repository to explore its recorded findings.'}</p></div>}
  </> : <ComposedAttacks index={index} sort={chainSort} onSortChange={sort => { setLocalChainSort(sort); onChainSortChange?.(sort); }} selected={selected} onSelect={select} onFinding={onFinding} onReadRepair={onReadRepair} onEvidence={onEvidence} />}</section>;
}
