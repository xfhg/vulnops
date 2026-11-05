import { useState, useEffect, useCallback, useRef, lazy, Suspense, useMemo } from 'react';
import { LayoutDashboard, ShieldCheck, GitBranch, FolderCode, Wrench, ScanLine, Search, ChevronDown, Sun, Moon, ArrowUpRight, Command, X, Menu, CircleAlert, SlidersHorizontal, Settings } from 'lucide-react';
import ReactMarkdown from 'react-markdown';
import { MotionConfig } from 'motion/react';
import { filterFindings } from '../domain';
import type { FindingSummary, FindingRecord, FindingFilters } from '../domain/types';
import { useRoute, routeHref, ApiError, human, type View } from './state';
import { Button, Badge, Drawer, Empty, Loading } from '../components/ui';
import { useWorkspace } from './useWorkspace';
import { ReportSourcesSheet, ReportSourcesSetup } from '../features/settings/ReportSources';
import { ArchiveSourcesSheet, EmptyBrowserWorkspace, importLabel } from '../features/settings/ArchiveSources';
import Overview from '../features/overview/Overview';
import FindingsTable from '../features/findings/FindingsTable';
import FindingDetail from '../features/findings/FindingDetail';
import { buildRepairEntries } from '../features/remediation/model';
import Assessment from '../features/assessment/Assessment';
const Remediation = lazy(() => import('../features/remediation/Remediation'));

const CodeMap = lazy(() => import('../features/code-map/CodeMap'));
const EntrypointExplorer = lazy(() => import('../features/entrypoint-explorer/EntrypointExplorer'));
const navigation: Array<{ view: View; label: string; icon: typeof ShieldCheck }> = [
  { view: 'overview', label: 'Overview', icon: LayoutDashboard },
  { view: 'findings', label: 'Findings', icon: ShieldCheck },
  { view: 'attacks', label: 'Attack explorer', icon: GitBranch },
  { view: 'code', label: 'Code map', icon: FolderCode },
  { view: 'remediation', label: 'Remediation', icon: Wrench },
  { view: 'assessment', label: 'Assessment', icon: ScanLine },
];
type EvidenceResult = { status?: string; kind?: string; label?: string; message?: string; content?: unknown; format?: string; token?: string; reference?: unknown; executionId?: string };

export default function App() {
  const runtime = useWorkspace();
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [droppedFiles, setDroppedFiles] = useState<File[] | undefined>();
  function openSettings() { setDroppedFiles(undefined); setSettingsOpen(true); }
  const initialGeneration = useRef<string | null>(null);
  if (runtime.workspace && !initialGeneration.current) initialGeneration.current = runtime.workspace.generation;
  // Bootstrap fills the existing shell so early keyboard focus is retained.
  // Only a later source replacement retires all report-derived state.
  const reportLifetime = runtime.workspace && runtime.workspace.generation !== initialGeneration.current ? runtime.workspace.generation : 'initial';
  useEffect(() => {
    if (!runtime.ownCompletion) return;
    setSettingsOpen(false);
    // Let the dialog restore focus before placing it on the newly loaded view.
    const frame = requestAnimationFrame(() => requestAnimationFrame(() => {
      const heading = document.querySelector<HTMLElement>('#main h1') ?? document.getElementById('main');
      heading?.setAttribute('tabindex', '-1');
      heading?.focus();
    }));
    return () => cancelAnimationFrame(frame);
  }, [runtime.ownCompletion]);
  return <>
    {runtime.browser && !runtime.workspace?.assessments.length ? <EmptyBrowserWorkspace state={runtime.browser} onSettings={openSettings} onDrop={files => { setDroppedFiles(files); setSettingsOpen(true); }} /> : <WorkspaceApplication key={reportLifetime} runtime={runtime} onSettings={openSettings} />}
    {runtime.browser && <ArchiveSourcesSheet open={settingsOpen} onOpenChange={setSettingsOpen} state={runtime.browser} initialFiles={droppedFiles} onImport={runtime.importArchive} onRemove={runtime.removeArchive} onCancel={runtime.cancelImport} />}
    {runtime.sources && <ReportSourcesSheet open={settingsOpen} onOpenChange={setSettingsOpen} state={runtime.sources} busy={runtime.busy} onLoad={runtime.loadSources} />}
  </>;
}

function WorkspaceApplication({ runtime, onSettings }: { runtime: ReturnType<typeof useWorkspace>; onSettings: () => void }) {
  const { workspace, sources, loadError, refresh } = runtime;
  const generation = workspace?.generation;
  const route = useRoute();
  const view = route.value('view', 'overview') as View;
  const runId = route.value('run');
  const findingKey = route.value('finding');
  const [finding, setFinding] = useState<FindingRecord | null>(null);
  const [findingError, setFindingError] = useState('');
  const [allDetails, setAllDetails] = useState<FindingRecord[] | null>(null);
  const [detailsError, setDetailsError] = useState('');
  const [mobileNav, setMobileNav] = useState(false);
  const [dark, setDark] = useState(() => { try { return localStorage.getItem('stake-theme') === 'dark'; } catch { return false; } });
  const [evidence, setEvidence] = useState<EvidenceResult | null>(null);
  const [evidenceOpen, setEvidenceOpen] = useState(false);
  const [evidenceLoading, setEvidenceLoading] = useState(false);
  useEffect(() => { document.documentElement.classList.toggle('dark', dark); try { localStorage.setItem('stake-theme', dark ? 'dark' : 'light'); } catch { /* Theme remains usable when storage is denied. */ } document.querySelector('meta[name="theme-color"]')?.setAttribute('content', dark ? '#0a0a0a' : '#f7f7f7'); }, [dark]);
  const evidenceController = useRef<AbortController | null>(null);
  useEffect(() => () => evidenceController.current?.abort(), []);
  function handleDataError(error: unknown, onError: (message: string) => void) {
    if ((error instanceof ApiError && (error.code === 'workspace_changed' || error.code === 'reload_required')) || (error && typeof error === 'object' && 'code' in error && error.code === 'stale')) { void refresh(); return; }
    onError(error instanceof Error ? error.message : 'The requested record is unavailable.');
  }
  useEffect(() => {
    setFinding(null); setFindingError('');
    if (!findingKey || !generation) return;
    const controller = new AbortController();
    runtime.dataSource.finding(findingKey, generation, controller.signal).then(value => { if (!controller.signal.aborted) setFinding(value); }).catch(error => { if (!controller.signal.aborted) handleDataError(error, setFindingError); });
    return () => controller.abort();
  }, [findingKey, generation]);
  useEffect(() => {
    if (!generation || !['code', 'remediation', 'attacks'].includes(view) || allDetails) return;
    const controller = new AbortController();
    async function load() {
      let offset = 0; const items: FindingRecord[] = [];
      do {
        const page = await runtime.dataSource.page(offset, 250, generation!, controller.signal);
        items.push(...page.items); offset += page.items.length;
        if (offset >= page.total) break;
        if (!page.items.length) throw new Error('The complete finding collection could not be loaded.');
      } while (true);
      if (!controller.signal.aborted) setAllDetails(items);
    }
    load().catch(error => { if (!controller.signal.aborted) handleDataError(error, setDetailsError); });
    return () => controller.abort();
  }, [view, allDetails, generation]);
  useEffect(() => {
    function shortcut(event: KeyboardEvent) {
      if ((event.metaKey || event.ctrlKey) && event.key === 'k') { event.preventDefault(); document.getElementById('global-search')?.focus(); }
      if (event.key === 'Escape') setMobileNav(false);
    }
    window.addEventListener('keydown', shortcut);
    return () => window.removeEventListener('keydown', shortcut);
  }, []);
  const filters = { assessment: runId, query: route.value('q'), repository: route.value('repo'), severity: route.value('severity'), disposition: route.value('status'), kind: route.value('kind'), classification: route.value('classification'), origin: route.value('origin') };
  const visible = useMemo(() => filterFindings(workspace?.findings ?? [], filters), [workspace, runId, route.value('q'), route.value('repo'), route.value('severity'), route.value('status'), route.value('kind'), route.value('classification'), route.value('origin')]);
  const scoped = useMemo(() => filterFindings(workspace?.findings ?? [], { assessment: runId, repository: route.value('repo') }), [workspace, runId, route.value('repo')]);
  const assessments = workspace?.assessments.filter(a => !runId || a.id === runId) ?? [];
  const detailScope = filterFindings(allDetails ?? [], { assessment: runId, repository: route.value('repo') });
  const repositories = [...new Set((workspace?.findings ?? []).flatMap(f => f.repositories))].sort();
  const selectedRun = workspace?.assessments.find(a => a.id === runId);
  const openFinding = useCallback((f: FindingSummary, actionId?: string) => {
    // The brief can be selected by a local search before its key reaches the URL.
    // Bind that exact action before unmounting the queue so the return is stable.
    const repairEntry = view === 'remediation' && actionId
      ? buildRepairEntries(allDetails ?? []).find(entry => entry.finding.key === f.key && entry.action.id === actionId) : undefined;
    route.navigate({ view: view === 'remediation' ? 'remediation' : 'findings', finding: f.key,
      panel: actionId ? 'repair' : 'summary', repair: actionId ?? null, selected: null, detailRecord: null, location: null, mode: 'procedure',
      ...(view !== 'remediation' ? { repairAction: null, repairSelected: null, repairView: null }
        : repairEntry ? { repairAction: repairEntry.key, repairSelected: route.value('repairAction') === repairEntry.key ? route.value('repairSelected') || null : null } : {}) });
  }, [route.params.toString(), allDetails]);
  function openRepairMap(finding: FindingRecord, actionId: string) {
    const entry = buildRepairEntries([finding]).find(entry => entry.action.id === actionId);
    if (!entry) return;
    route.navigate({ view: 'remediation', finding: null, panel: null, detailRecord: null, selected: null, repair: null, location: null,
      run: workspace?.assessments.some(assessment => assessment.id === finding.runId) ? finding.runId : null, repo: null,
      repairAction: entry.key, repairSelected: null, repairView: 'map' });
  }
  function changeView(next: string) { route.navigate({ view: next, finding: null, detailRecord: null, selected: null, repair: null, panel: null, location: null, repairAction: null, repairSelected: null, repairView: null }); setMobileNav(false); }
  async function openEvidence(reference: unknown, owner: string) {
    if (!generation) return;
    evidenceController.current?.abort();
    const controller = new AbortController();
    evidenceController.current = controller;
    setEvidenceOpen(true); setEvidenceLoading(true); setEvidence(null);
    try {
      const entry = await runtime.dataSource.reference(owner, reference, generation, controller.signal);
      const result = entry.token ? await runtime.dataSource.evidence(entry.token, generation, controller.signal) : entry;
      if (!controller.signal.aborted) setEvidence(result);
    } catch (error) { if (!controller.signal.aborted) handleDataError(error, message => setEvidence({ status: 'unavailable', message })); }
    finally { if (!controller.signal.aborted) setEvidenceLoading(false); }
  }
  function exploreFindings(filters: FindingFilters) {
    route.navigate({ view: 'findings', finding: null, panel: null, selected: null, repair: null, location: null,
      q: filters.query ?? null, severity: filters.severity ?? null, status: filters.disposition ?? filters.cohort ?? null,
      kind: filters.kind ?? null, classification: filters.classification ?? null, origin: filters.origin ?? 'assessed',
      repo: filters.repository ?? (route.value('repo') || null), run: filters.assessment ?? filters.runId ?? (runId || null) });
  }
  const unattributedReviewCount = filterFindings(workspace?.findings ?? [], { assessment: runId, origin: 'assessed' })
    .filter(finding => !finding.conflicted && !finding.repositories.length && !['confirmed', 'needs_environment'].includes(finding.cohort)).length;
  function resetFilters() { route.navigate({ q: null, severity: null, repo: null, status: null, kind: null, classification: null, origin: null }); }
  const panel = ['summary', 'reproduce', 'repair', 'verify', 'evidence', 'graph'].includes(route.value('panel')) ? route.value('panel') : !route.value('panel') && (route.value('selected') || ['trace', 'composition'].includes(route.value('mode'))) ? 'graph' : 'summary';
  const mode = ['procedure','trace','composition'].includes(route.value('mode')) ? route.value('mode') as 'procedure'|'trace'|'composition' : 'procedure';

  return <MotionConfig reducedMotion="user"><div className="app-shell"><a className="skip-link" href="#main" onClick={event => { if (runtime.browser) { event.preventDefault(); document.getElementById('main')?.focus(); } }}>Skip to content</a>
    <aside className={'sidebar ' + (mobileNav ? 'sidebar-open' : '')}><a className="brand" aria-label="VulnOps @stake home" href={routeHref('view=overview')} onClick={event => { event.preventDefault(); changeView('overview'); }}><img className="brand-logo" src="/brand/vulnops-icon.svg" alt="VulnOps Doberman" /><span className="brand-name"><strong>VulnOps</strong><span className="brand-label">@stake</span></span></a>
      <div className="workspace-label">SECURITY OPERATIONS</div><nav aria-label="Main navigation">{navigation.map(item => <button key={item.view} className={'nav-item ' + (view === item.view ? 'active' : '')} onClick={() => changeView(item.view)} aria-current={view === item.view ? 'page' : undefined}><item.icon size={18} strokeWidth={1.7} />{item.label}{item.view === 'findings' && workspace && <span className="nav-count">{workspace.findings.filter(f => f.hasDossier && !f.conflicted).length}</span>}</button>)}</nav>
      <div className="sidebar-footer"><span className="online-dot" />Local workspace<span>v0.1</span></div>
    </aside>{mobileNav && <button className="mobile-scrim" aria-label="Close navigation" onClick={() => setMobileNav(false)} />}
    <div className="main-shell"><header className="topbar"><Button variant="ghost" size="icon" className="mobile-menu" onClick={() => setMobileNav(!mobileNav)} aria-label="Toggle navigation"><Menu size={20} /></Button><div className="topbar-context"><span>Workspace</span><ChevronDown size={12} /><strong>{selectedRun?.repository || 'All assessments'}</strong></div>{runtime.browser?.progress && <Button variant="ghost" size="sm" onClick={onSettings} aria-live="polite">{importLabel(runtime.browser)}</Button>}<div className="global-search"><Search size={16} /><input id="global-search" aria-label="Search findings" placeholder="Search findings…" value={route.value('q')} onChange={event => route.navigate({ q: event.target.value, view: 'findings', finding: null }, true)} /><kbd><Command size={10} />K</kbd></div><Button variant="ghost" size="icon" onClick={onSettings} disabled={!sources && !runtime.browser} aria-label="Settings"><Settings size={18} /></Button><Button variant="ghost" size="icon" onClick={() => setDark(!dark)} aria-label={dark ? 'Use light theme' : 'Use dark theme'}>{dark ? <Sun size={18} /> : <Moon size={18} />}</Button></header>
      <main id="main" tabIndex={-1}>{!!workspace?.assessments.length && <div className="scope-toolbar">{view === 'assessment' ? <nav className="view-breadcrumb" aria-label="Breadcrumb"><span>Workspace</span><span aria-hidden="true">/</span><strong>Assessment</strong></nav> : <div className="scope-select"><span className="scope-indicator" /><select aria-label="Select assessment" value={runId} onChange={event => route.navigate({ run: event.target.value, finding: null, selected: null, repair: null, repairAction: null, repairSelected: null, repairView: null })}><option value="">All loaded assessments</option>{workspace?.assessments.map(a => <option key={a.id} value={a.id}>{a.kind === 'audit' ? 'Ordinary audit' : 'Advantage'} · {a.repository || a.id}</option>)}</select><ChevronDown size={12} /></div>}{view !== 'assessment' && <select className="repository-select" aria-label="Filter repository" value={route.value('repo')} onChange={event => route.navigate({ repo: event.target.value, repairAction: null, repairSelected: null, repairView: null })}><option value="">All repositories</option>{repositories.map(repo => <option value={repo} key={repo}>{repo}</option>)}</select>}<span className="scope-readonly"><span className="online-dot" />Read-only publication</span></div>}
        {(runtime.notice || runtime.busy) && <p className="workspace-notice" role="status" aria-live="polite">{runtime.busy ? 'Loading reports… You can continue browsing while this finishes.' : runtime.notice}</p>}
        {sources?.persistence.status === 'session_only' && <div className="warning-banner" role="status"><CircleAlert size={17} /><p>{sources.persistence.message || 'Loaded for this session; paths could not be remembered.'}</p></div>}
        {loadError && <div className="warning-banner" role="alert"><CircleAlert size={17} /><p>{loadError}</p><Button variant="outline" size="sm" onClick={() => void refresh()}>Retry</Button></div>}
        {!workspace || (!runtime.browser && !sources) ? <Loading /> : !workspace.assessments.length && sources ? <ReportSourcesSetup state={sources} busy={runtime.busy} onLoad={runtime.loadSources} /> : <>
          {workspace.failures.map((failure, i) => <div key={i} className="warning-banner" role="alert"><CircleAlert size={17} /><div><strong>Input unavailable</strong><p>{failure.message}</p>{failure.inputPath && <span className="mono small">{failure.inputPath}</span>}</div></div>)}
          {!!workspace.conflicts.length && <div className="warning-banner"><CircleAlert size={17} />{workspace.conflicts.length} conflicting historical identities are excluded from combined totals. See finding diagnostics.</div>}
          {runId && !selectedRun ? <Empty title="Assessment unavailable" description="This URL references an assessment that is not loaded in this local session." /> : findingKey ? findingError ? <Empty title="Finding unavailable" description={findingError} action={<Button variant="outline" onClick={() => route.navigate({ finding: null })}>Back to findings</Button>} /> : !finding ? <Loading label="Loading the complete dossier…" /> : <FindingDetail key={finding.key} finding={finding} backLabel={view === 'remediation' ? `Back to repair ${route.value('repairView') === 'map' ? 'map' : route.value('repairView') === 'records' ? 'records' : 'brief'}` : view === 'attacks' ? 'Back to attack overview' : 'Back to findings'} contextRunId={runId} panel={panel} graphMode={mode} selected={route.value('selected')} repairId={route.value('repair')} detailRecord={route.value('detailRecord')} onNavigate={changes => route.navigate(changes)} onRepairMap={id => openRepairMap(finding, id)} onPanel={value => route.navigate({ panel: value })} onBack={() => route.navigate({ finding: null, selected: null, repair: null, panel: null, detailRecord: null })} onMode={value => route.navigate({ mode: value, selected: null })} onSelect={value => route.navigate({ selected: value })} onRepair={value => route.navigate({ repair: value })} onEvidence={openEvidence} /> : view === 'overview' ? <Overview assessments={assessments} findings={scoped} onFinding={openFinding} onView={changeView} onExplore={exploreFindings} scopedRepository={route.value('repo')} unattributedReviewCount={unattributedReviewCount} /> : view === 'attacks' ? detailsError ? <Empty title="Attack map unavailable" description={detailsError} /> : !allDetails ? <Loading label="Mapping recorded entrypoints and attack compositions…" /> : <Suspense fallback={<Loading />}><EntrypointExplorer findings={detailScope} mode={route.value('entryMode') === 'composed' ? 'composed' : 'entrypoints'} selected={route.value('entrySelected')} entrySort={route.value('entrySort') === 'priority' ? 'priority' : route.value('entrySort') === 'route' ? 'route' : 'shared'} chainSort={route.value('chainSort') === 'id' ? 'id' : 'priority'} onEntrySortChange={sort => route.navigate({ entrySort: sort })} onChainSortChange={sort => route.navigate({ chainSort: sort })} onModeChange={mode => route.navigate({ entryMode: mode, entrySelected: null })} onSelect={key => route.navigate({ entrySelected: key })} onFinding={(finding, mode) => route.navigate({ view: 'attacks', finding: finding.key, mode: mode ?? 'procedure', selected: null, repair: null, panel: 'graph', detailRecord: null })} onReadRepair={(finding, id, index) => route.navigate({ view: 'attacks', finding: finding.key, panel: 'repair', repair: id, selected: null, detailRecord: index === undefined ? null : JSON.stringify(['repair-location', id, index]) })} onEvidence={openEvidence} /></Suspense> : view === 'findings' ? <>
            <div className="page-heading"><div><p className="eyebrow">ASSESSMENT RESULTS</p><h1>Findings, in context.</h1><p>Prioritize the impact, inspect the evidence, and work toward the repair.</p></div><Badge>{visible.length} results</Badge></div>
            <div className="filters"><SlidersHorizontal size={16} /><span className="small muted">Filter</span>{[{key:'severity',label:'severity',values:['critical,high','critical','high','medium','low','info']},{key:'status',label:'disposition',values:['confirmed','needs_environment','historical','unconfirmed','non_promoted','rejected']},{key:'kind',label:'kind',values:[...new Set(workspace.findings.map(f=>f.kind).filter((x): x is string=>Boolean(x)))]},{key:'classification',label:'Advantage outcome',values:['new_root','new_chain','impact_expansion','baseline_revalidation','baseline_correction']}].map(filter=><select key={filter.key} aria-label={'Filter '+filter.label} value={route.value(filter.key)} onChange={event=>route.navigate({[filter.key]:event.target.value,...(filter.key === 'status' ? {origin:null} : {})})}><option value="">All {filter.label}</option>{filter.values.map(value=><option value={value} key={value}>{value === 'critical,high' ? 'Critical & high' : human(value)}</option>)}</select>)}<Button variant="ghost" size="sm" onClick={resetFilters}><X size={13} />Reset</Button></div>
            <FindingsTable findings={visible} onFinding={openFinding} onReset={resetFilters} />
          </> : view === 'code' ? <><div className="page-heading"><div><p className="eyebrow">CITED SOURCE LOCATIONS</p><h1>See where findings meet code.</h1><p>Explore the repositories, components and files cited by these assessments.</p></div><div className="heading-icon"><FolderCode size={26}/></div></div>{detailsError ? <Empty title="Code map unavailable" description={detailsError} /> : !allDetails ? <Loading label="Indexing cited locations…" /> : <Suspense fallback={<Loading />}><CodeMap findings={detailScope} selected={route.value('location')} onSelect={key => route.navigate({ location: key })} onFinding={key => { const f = workspace.findings.find(f => f.key === key); if (f) openFinding(f); }} onEvidence={openEvidence} /></Suspense>}</> : view === 'remediation' ? detailsError ? <Empty title="Repairs unavailable" description={detailsError} /> : !allDetails ? <Loading label="Loading repair actions…" /> : <Suspense fallback={<Loading label="Loading repair map…" />}><Remediation findings={detailScope} selectedAction={route.value('repairAction')} selectedNode={route.value('repairSelected')} selectedView={route.value('repairView')} onView={view => route.navigate({ repairView: view })} onSelection={(action, node, view) => route.navigate({ repairAction: action || null, repairSelected: node, ...(view ? { repairView: view } : {}) })} onFinding={openFinding} onEvidence={openEvidence}
            onCode={(finding, file) => route.navigate({ view: 'code', run: workspace.assessments.some(assessment => assessment.id === finding.runId) ? finding.runId : null, repo: null, finding: null, selected: null, repair: null, panel: null, location: JSON.stringify([finding.runId, finding.scopeId, finding.sourceView, file]) })}
            onRecord={(finding, node, actionId) => {
              if (node.kind === 'action') openFinding(finding, actionId);
              else if (node.kind === 'finding') openFinding(finding);
              else route.navigate({ view: 'remediation', finding: finding.key, panel: node.kind === 'location' ? 'repair' : node.kind === 'check' ? 'verify' : 'reproduce', mode: 'procedure', repair: actionId, selected: null,
                repairAction: buildRepairEntries([finding]).find(entry => entry.action.id === actionId)?.key ?? null,
                detailRecord: node.kind === 'location' ? JSON.stringify(['repair-location', actionId, node.locationIndex]) : JSON.stringify([node.kind, node.localId]) });
            }} /></Suspense> : view === 'assessment' ? <Assessment assessments={workspace.assessments} selectedAssessmentId={runId || undefined} onAssessmentChange={id => route.navigate({ run: id })} onEvidence={openEvidence} /> : <Empty title="View unavailable" description="Choose one of the workspace views in the navigation." />}
        </>}
        <footer className="page-footer"><span className="footer-brand"><strong>VulnOps</strong><span className="brand-label">@stake</span></span><span>Assessment intelligence / Local workspace</span></footer>
      </main>
    </div>
    <Drawer open={evidenceOpen} onOpenChange={open => { setEvidenceOpen(open); if (!open) evidenceController.current?.abort(); }} title={evidence?.label || 'Evidence reference'} description={evidence?.executionId ? 'Owning execution: ' + evidence.executionId : 'Evidence resolves only within explicitly loaded bundles.'}>
      {evidenceLoading ? <Loading label="Resolving evidence…" /> : evidence && <><div className="detail-badges"><Badge tone={evidence.status === 'available' ? 'sage' : 'amber'}>{human(evidence.status || evidence.kind)}</Badge><Badge>{human(evidence.kind)}</Badge></div>{evidence.message && <p className="prose">{evidence.message}</p>}{evidence.content !== undefined && <div className="evidence-body">{evidence.format === 'markdown' || (evidence.format === 'text' && evidence.label?.endsWith('.md')) ? <ReactMarkdown skipHtml components={{ img: () => null, a: ({ children }) => <span>{children}</span> }}>{String(evidence.content)}</ReactMarkdown> : <pre>{typeof evidence.content === 'string' ? evidence.content : JSON.stringify(evidence.content, null, 2)}</pre>}</div>}</>}
    </Drawer>
  </div></MotionConfig>;
}
