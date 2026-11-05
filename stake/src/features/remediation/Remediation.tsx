import { lazy, Suspense, useEffect, useMemo, useState } from 'react';
import { ReactFlowProvider } from '@xyflow/react';
import { ArrowUpRight, ChevronDown, FileCode2, FileText, GitBranch, List, Search, ShieldCheck, Wrench } from 'lucide-react';
import type { FindingRecord } from '../../domain';
import type { EvidenceHandler } from '../../components/RecordView';
import { Badge, Button, Empty, Loading, Tabs, TabsContent, TabsList, TabsTrigger } from '../../components/ui';
import { Card } from '../../components/ui/data-display';
import { human } from '../../app/state';
import { RawDisclosure } from '../findings/DossierPrimitives';
import { buildRepairEntries, projectRepair, type RepairNode } from './model';
import RepairInspector, { repairKindLabel } from './RepairInspector';
import RepairBrief from './RepairBrief';
import './remediation.css';

const RepairCanvas = lazy(() => import('./RepairCanvas'));
export type RepairView = 'brief' | 'map' | 'records';
export interface RemediationProps {
  findings: FindingRecord[];
  selectedAction?: string;
  selectedNode?: string;
  selectedView?: string;
  onView?: (view: RepairView) => void;
  onSelection?: (action: string, node: string | null, view?: RepairView) => void;
  onFinding: (finding: FindingRecord, actionId?: string) => void;
  onRecord: (finding: FindingRecord, node: RepairNode, actionId: string) => void;
  onCode: (finding: FindingRecord, file: string) => void;
  onEvidence: EvidenceHandler;
}

export default function Remediation({ findings, selectedAction: controlledAction, selectedNode: controlledNode, selectedView: controlledView, onView, onSelection, onFinding, onRecord, onCode, onEvidence }: RemediationProps) {
  const entries = useMemo(() => buildRepairEntries(findings), [findings]);
  const [query, setQuery] = useState('');
  const [focus, setFocus] = useState('all');
  const [localView, setLocalView] = useState('');
  const [queueOpen, setQueueOpen] = useState(false);
  const [mountedMap, setMountedMap] = useState('');
  const [localSelection, setLocalSelection] = useState({ action: '', node: '' });
  const requestedAction = controlledAction ?? localSelection.action;
  const requestedNode = controlledNode ?? localSelection.node;
  const requestedView = controlledView ?? localView;
  const view: RepairView = ['brief', 'map', 'records'].includes(requestedView) ? requestedView as RepairView : requestedNode ? 'map' : 'brief';
  const setView = (next: RepairView) => {
    if (active) {
      choose(active.key, requestedNode || null, next);
      if (!onSelection) onView?.(next);
    } else { setLocalView(next); onView?.(next); }
  };
  const filtered = useMemo(() => entries.filter(({ finding, action }) => {
    const text = [finding.id, finding.title, finding.runId, ...finding.repositories, action.id, action.change, action.rationale,
      ...(action.locations ?? []).map(location => location.file), ...(action.component_ids ?? []).flatMap(id => [id, finding.components.find(component => component.id === id)?.name])].join(' ').toLowerCase();
    return text.includes(query.trim().toLowerCase()) && (focus === 'all' || focus === 'priority' && ['critical', 'high'].includes(finding.severity)
      || focus === 'no_locations' && !action.locations?.length || focus === 'no_checks' && !finding.raw.remediation?.verification_checks?.length);
  }), [entries, query, focus]);
  const active = requestedAction ? entries.find(entry => entry.key === requestedAction) : filtered[0];
  const graph = useMemo(() => active ? projectRepair(active) : null, [active]);
  const selected = requestedNode || graph?.nodes.find(node => node.kind === 'action')?.id || '';
  const choose = (action: string, node: string | null = null, nextView?: RepairView) => {
    setLocalSelection({ action, node: node ?? '' });
    if (nextView) setLocalView(nextView);
    onSelection?.(action, node, nextView);
  };
  const chooseRepair = (action: string) => {
    choose(action, null, 'brief');
    if (window.matchMedia?.('(max-width: 900px)').matches) {
      setQueueOpen(false);
      requestAnimationFrame(() => document.querySelector<HTMLElement>('.rm-active-header h2')?.focus());
    }
  };
  useEffect(() => { if (view === 'map' && active) setMountedMap(active.key); }, [view, active?.key]);
  const selectNode = (id: string) => { if (active) choose(active.key, id); };
  const selectQuery = (next: string) => { setQuery(next); choose('', null, 'brief'); };
  const resetFilters = () => { setQuery(''); setFocus('all'); choose('', null, 'brief'); };
  const scopedFindings = [...new Map(entries.map(entry => [entry.finding.key, entry.finding])).values()];
  const sources = new Set(entries.flatMap(entry => (entry.action.locations ?? []).map(location => JSON.stringify([entry.finding.runId, entry.finding.scopeId, entry.finding.sourceView, location.file]))));
  const kinds: RepairNode['kind'][] = ['action', 'location', 'component', 'step', 'example', 'check', 'guidance', 'finding'];
  function openNode(node: RepairNode) {
    if (!active || node.unavailable) return;
    if (['action', 'finding', 'location', 'step', 'example', 'check'].includes(node.kind)) onRecord(active.finding, node, active.action.id);
    else { selectNode(node.id); document.getElementById('repair-inspector')?.scrollIntoView({ block: 'nearest', behavior: 'instant' }); }
  }

  return <section className="remediation-workspace" aria-label="Repair workspace">
    <header className="rm-heading"><div><span className="eyebrow">REMEDIATION</span><h1>Plan the change. Trace the repair.</h1><p>Choose a repair, review the proposed change, then explore its code and evidence.</p></div><Wrench size={28} aria-hidden="true"/></header>
    <div className="rm-metrics" aria-label="Repair scope summary">
      <div><Wrench size={16}/><strong>{entries.length}</strong><span>proposed actions</span></div>
      <div><GitBranch size={16}/><strong>{scopedFindings.length}</strong><span>findings with guidance</span></div>
      <div><FileCode2 size={16}/><strong>{sources.size}</strong><span>cited change files</span></div>
      <div><ShieldCheck size={16}/><strong>{scopedFindings.reduce((sum, finding) => sum + (finding.raw.remediation?.verification_checks?.length ?? 0), 0)}</strong><span>finding-level checks</span></div>
    </div>
    {!entries.length ? <Empty title="No repair actions in this scope" description="Choose another assessment or repository to review recorded remediation."/> : <div className="rm-workspace-grid">
      <aside className={`rm-queue ${queueOpen ? 'rm-queue-open' : ''}`} aria-label="Repair actions">
        <header><div><span className="rm-queue-kicker">START HERE</span><h2>Choose a repair</h2></div><span>{filtered.length} of {entries.length}</span><button type="button" className="rm-queue-toggle" aria-label="Choose a repair" aria-expanded={queueOpen} aria-controls="repair-queue-body" onClick={() => setQueueOpen(open => !open)}><ChevronDown size={16}/></button></header>
        <div id="repair-queue-body" className="rm-queue-body"><p className="rm-queue-order">Confirmed first, then severity.</p>
        <div className="rm-queue-filters"><label className="rm-search"><Search size={14} aria-hidden="true"/><input type="search" aria-label="Search repair actions" placeholder="Finding, change or file…" value={query} onChange={event => selectQuery(event.target.value)}/></label>
          <select aria-label="Filter repair actions" value={focus} onChange={event => { setFocus(event.target.value); choose('', null, 'brief'); }}><option value="all">All proposed actions</option><option value="priority">High & critical findings</option><option value="no_locations">Without change locations</option><option value="no_checks">Without verification checks</option></select></div>
        <div className="rm-queue-list">{filtered.map(entry => <article className={`repair-row rm-queue-item ${active?.key === entry.key ? 'active' : ''}`} key={entry.key}>
          <button type="button" className="rm-queue-select" aria-pressed={active?.key === entry.key} onClick={() => chooseRepair(entry.key)} aria-label={`Select repair ${entry.finding.id} / ${entry.action.id} · ${entry.finding.runId}`}>
            <span className="rm-queue-identity"><code>{entry.finding.id} / {entry.action.id}</code><span className="rm-queue-badges"><Badge tone={entry.finding.severity}>{entry.finding.severity}</Badge>{entry.finding.origin === 'historical' && <Badge>Historical</Badge>}</span></span>
            <strong>{entry.action.change || 'Implementation change not recorded'}</strong><small>{human(entry.finding.cohort)} · {entry.finding.repositories.join(', ') || 'Repository not recorded'}</small>
            <span className="rm-queue-counts">{entry.action.locations?.length ?? 0} locations · {entry.action.breaks_steps?.length ?? 0} interruption links</span>
          </button><footer><span title={entry.finding.runId}>{entry.finding.runId}</span><button type="button" onClick={() => onFinding(entry.finding, entry.action.id)}>Review repair<ArrowUpRight size={12}/></button></footer>
        </article>)}</div>
        {active && !filtered.some(entry => entry.key === active.key) && <div className="rm-no-matches"><p>The selected repair is outside this list filter.</p><Button variant="outline" size="sm" onClick={() => { setQuery(''); setFocus('all'); }}>Show selected repair in list</Button></div>}
        {!filtered.length && <div className="rm-no-matches"><p>No actions match these filters.</p><Button variant="outline" size="sm" onClick={resetFilters}>Reset repair filters</Button></div>}
        </div>
      </aside>
      <div className="rm-detail">{!active || !graph ? <Empty title={requestedAction ? 'Selected repair unavailable' : 'No matching repair'} description={requestedAction ? 'This repair is outside the current assessment or repository.' : 'Adjust the action filters to explore the recorded guidance.'} action={<Button variant="outline" onClick={resetFilters}>Choose an available repair</Button>}/> : <>
        <Card className="rm-active-header"><div className="rm-active-topline"><span><Badge tone={active.finding.severity}>{active.finding.severity}</Badge><code>{active.finding.id} / {active.action.id}</code><Badge>Proposed repair</Badge><Badge>{human(active.finding.cohort)}</Badge>{active.finding.origin === 'historical' && <Badge>Historical</Badge>}</span></div><h2 tabIndex={-1}>{active.action.change || 'Implementation change not recorded'}</h2><p>{active.finding.title}</p></Card>
        <Tabs className="rm-view-tabs" value={view} onValueChange={value => setView(value as RepairView)}>
          <TabsList className="rm-representation" aria-label="Repair representation">
            <TabsTrigger value="brief"><FileText size={14}/>Repair brief</TabsTrigger>
            <TabsTrigger value="map"><GitBranch size={14}/>Repair map</TabsTrigger>
            <TabsTrigger value="records"><List size={14}/>All repair records<span>{graph.nodes.length}</span></TabsTrigger>
          </TabsList>
          <TabsContent value="brief"><RepairBrief graph={graph} onExplore={id => choose(active.key, id ?? null, 'map')} onFinding={() => onFinding(active.finding, active.action.id)}/></TabsContent>
          <TabsContent value="map" forceMount hidden={view !== 'map'}>
            {(view === 'map' || mountedMap === active.key) && <Suspense fallback={<Loading label="Mapping repair relationships…"/>}><ReactFlowProvider key={active.key}><RepairCanvas graph={graph} selected={selected} onSelect={selectNode} onOpen={openNode}/></ReactFlowProvider></Suspense>}
          </TabsContent>
          <TabsContent value="records"><div className="rm-records" aria-label="All repair records">{kinds.map(kind => {
            const records = graph.nodes.filter(node => node.kind === kind);
            return records.length ? <section key={kind}><h3>{repairKindLabel(kind)} <span>{records.length}</span></h3><div>{records.map(node => <button type="button" key={node.id} className={`rm-record ${selected === node.id ? 'active' : ''}`} aria-pressed={selected === node.id} onClick={() => selectNode(node.id)}><span><code>{node.localId}</code><Badge>{node.unavailable ? 'Unavailable' : node.scope === 'finding' ? 'Finding context' : human(node.status)}</Badge></span><strong>{node.title}</strong><small>{node.caption}</small></button>)}</div></section> : null;
          })}</div></TabsContent>
        </Tabs>
        {view !== 'brief' && requestedNode && <RepairInspector graph={graph} selected={selected} onSelect={selectNode} onOpen={openNode} onEvidence={onEvidence} onCode={file => onCode(active.finding, file)}/>}
        <div className="rm-support">
          <details className="rm-provenance"><summary>Assessment context <span>{active.finding.runId}</span></summary><dl><div><dt>Owning execution</dt><dd>{active.finding.runId}</dd></div><div><dt>Assessment</dt><dd>{active.finding.scopeId || 'Not recorded'}</dd></div><div><dt>Source view</dt><dd>{active.finding.sourceView || 'Not recorded'}</dd></div>{active.finding.origin === 'historical' && <div><dt>Imported by</dt><dd>{active.finding.historicalIn.join(', ') || 'Not recorded'}</dd></div>}</dl></details>
        {graph.diagnostics.length > 0 && <details className="rm-diagnostics"><summary>{graph.diagnostics.length} unresolved record {graph.diagnostics.length === 1 ? 'reference' : 'references'}</summary><ul>{graph.diagnostics.map((message, index) => <li key={index}>{message}</li>)}</ul></details>}
        <RawDisclosure value={active.finding.raw.remediation} label="Complete remediation record"/>
        </div>
      </>}</div>
    </div>}
  </section>;
}
