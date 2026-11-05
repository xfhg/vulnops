import { lazy, Suspense, useEffect, useRef, useState } from 'react';
import { ArrowLeft, ArrowRight, AlertTriangle, GitBranch, Wrench } from 'lucide-react';
import type { FindingRecord } from '../../domain/types';
import { localEntityKey } from '../../domain';
import { Button, Tabs, TabsList, TabsTrigger, TabsContent, Section, Loading } from '../../components/ui';
import { RecordView, type EvidenceHandler } from '../../components/RecordView';
import FindingHeader from './FindingHeader';
import SummaryPanel from './SummaryPanel';
import ReproducePanel from './ReproducePanel';
import RepairPanel from './RepairPanel';
import { VerificationPanel, EvidencePanel } from './ReviewPanels';
import './finding-journey.css';
const AttackExplorer = lazy(() => import('../attack-explorer/AttackExplorer'));

export default function FindingDetail({ finding, panel, graphMode, selected, repairId, detailRecord = '', contextRunId, backLabel = 'Back to findings', onPanel, onBack, onMode, onSelect, onRepair, onNavigate, onRepairMap, onEvidence }: {
  finding: FindingRecord; panel: string; graphMode: 'procedure'|'trace'|'composition'; selected: string; repairId: string; detailRecord?: string;
  contextRunId?: string; backLabel?: string;
  onPanel: (panel: string) => void; onBack: () => void; onMode: (mode: 'procedure'|'trace'|'composition') => void;
  onSelect: (id: string) => void; onRepair: (id: string) => void; onEvidence: EvidenceHandler;
  onNavigate?: (changes: Record<string, string | null>) => void;
  onRepairMap?: (id: string) => void;
}) {
  const actions = finding.raw.remediation?.actions ?? [];
  const steps = finding.raw.exploitation?.steps ?? [];
  const checks = finding.raw.remediation?.verification_checks ?? [];
  const journey = useRef<HTMLDivElement>(null);
  const priorPanel = useRef<string | null>(null);
  const [graphMounted, setGraphMounted] = useState(panel === 'graph');
  useEffect(() => { if (panel === 'graph') setGraphMounted(true); }, [panel]);

  // A linked record opens its instructions, with focus and position following the URL.
  // Plain Summary entry keeps the title in view; browser back restores the selected panel.
  useEffect(() => {
    const changed = priorPanel.current !== null && priorPanel.current !== panel;
    priorPanel.current = panel;
    const frame = requestAnimationFrame(() => {
      const root = journey.current;
      if (!root) return;
      const record = detailRecord && [...root.querySelectorAll<HTMLElement>('[data-detail-record]')].find(element => element.dataset.detailRecord === detailRecord);
      const action = panel === 'repair' && repairId && [...root.querySelectorAll<HTMLElement>('[data-repair-id]')].find(element => element.dataset.repairId === repairId);
      const target = record || action;
      if (target) { target.scrollIntoView({ block: 'start', behavior: 'instant' }); target.focus({ preventScroll: true }); }
      else if (changed || panel !== 'summary') { root.scrollIntoView({ block: 'start', behavior: 'instant' }); root.querySelector<HTMLElement>('[role="tab"][data-state="active"]')?.focus({ preventScroll: true }); }
    });
    return () => cancelAnimationFrame(frame);
  }, [finding.key, panel, detailRecord, repairId]);

  function navigate(changes: Record<string, string | null>) {
    if (onNavigate) { onNavigate(changes); return; }
    if (changes.mode) onMode(changes.mode as typeof graphMode);
    if ('selected' in changes) onSelect(changes.selected ?? '');
    if ('repair' in changes) onRepair(changes.repair ?? '');
    if (changes.panel) onPanel(changes.panel);
  }
  const changePanel = (value: string) => navigate({ panel: value, detailRecord: null });
  const openRecord = (kind: 'step'|'example', id: string, actionId?: string) => navigate({ panel: 'reproduce', detailRecord: JSON.stringify([kind, id]), selected: null, ...(actionId ? { repair: actionId } : {}) });
  const openRepair = (id: string, locationIndex?: number) => navigate({ panel: 'repair', repair: id, detailRecord: locationIndex === undefined ? null : JSON.stringify(['repair-location', id, locationIndex]), selected: null });
  const openStepMap = (id: string) => navigate({ panel: 'graph', mode: 'procedure', selected: localEntityKey(finding.key, 'procedure', id), detailRecord: null });
  const openOverlay = (id: string) => navigate({ panel: 'graph', mode: 'procedure', repair: id || null, selected: null, detailRecord: null });

  return <article className="finding-detail"><Button variant="ghost" size="sm" className="back-button" onClick={onBack}><ArrowLeft size={15} />{backLabel}</Button>
    <FindingHeader finding={finding} onRepair={finding.hasDossier ? () => openRepair('') : undefined} onReproduce={finding.hasDossier ? () => changePanel('reproduce') : undefined}/>
    {contextRunId && contextRunId !== finding.runId && finding.historicalIn.includes(contextRunId) && <div className="info-banner">Historical baseline context for {contextRunId}. Owning execution: {finding.runId}.</div>}
    {finding.conflicted && <div className="warning-banner"><AlertTriangle size={18} />This historical identity has conflicting representations. Its content is not included in a deduplicated combined total.</div>}
    {!finding.hasDossier ? <Section title="Recorded disposition" caption="A complete accepted dossier is not available for this record."><RecordView value={finding.raw} /></Section> : <div ref={journey} className="finding-journey">
      <Tabs value={panel} onValueChange={changePanel}>
        <TabsList aria-label="Finding detail" className="finding-journey-tabs">
          <TabsTrigger value="summary"><span className="journey-stage" aria-hidden="true">01</span>Summary</TabsTrigger>
          <TabsTrigger value="reproduce"><span className="journey-stage" aria-hidden="true">02</span>Reproduce <span>{steps.length}</span></TabsTrigger>
          <TabsTrigger value="repair"><span className="journey-stage" aria-hidden="true">03</span>Repair <span>{actions.length}</span></TabsTrigger>
          <TabsTrigger value="verify"><span className="journey-stage" aria-hidden="true">04</span>Verify</TabsTrigger>
          <TabsTrigger value="graph" className="journey-map-tab"><GitBranch size={14}/>Attack map</TabsTrigger>
          <TabsTrigger value="evidence">Evidence</TabsTrigger>
        </TabsList>
        <TabsContent value="summary"><SummaryPanel finding={finding} onEvidence={onEvidence}/><div className="finding-next-step"><div><Wrench size={19}/><span><strong>Ready to work on the repair?</strong><small>{actions.length} recorded actions · {checks.length} verification checks</small></span></div><Button onClick={() => openRepair(actions[0]?.id ?? '')}>Read repair instructions<ArrowRight size={15}/></Button></div></TabsContent>
        <TabsContent value="reproduce"><ReproducePanel finding={finding} onStep={openStepMap} onRecordStep={id => openRecord('step', id)} onRepair={openRepair} onEvidence={onEvidence}/><div className="finding-next-step"><span>Continue from the recorded procedure to its control changes.</span><Button onClick={() => openRepair(repairId || actions[0]?.id || '')}>Read repair instructions<ArrowRight size={15}/></Button></div></TabsContent>
        <TabsContent value="repair"><RepairPanel finding={finding} repairId={repairId} onRepair={openOverlay} onRepairMap={onRepairMap} onActionSelect={openRepair} onExample={(id, actionId) => openRecord('example', id, actionId)} onStep={(id, actionId) => openRecord('step', id, actionId)} onVerify={() => changePanel('verify')} onEvidence={onEvidence}/></TabsContent>
        <TabsContent value="verify"><div className="finding-check-context"><span>Verification checks for {finding.id}</span><Button variant="outline" size="sm" onClick={() => openRepair(repairId || actions[0]?.id || '')}><Wrench size={14}/>Back to repair instructions</Button></div><VerificationPanel finding={finding} onEvidence={onEvidence}/></TabsContent>
        <TabsContent value="graph" forceMount hidden={panel !== 'graph'}>{(graphMounted || panel === 'graph') && <div id="finding-graph" className="detail-graph"><div className="finding-graph-heading"><div><h2>Attack path</h2><p>Explore the procedure, source trace and recorded composition.</p></div><Button variant="outline" size="sm" onClick={() => openRepair(repairId || actions[0]?.id || '')}><Wrench size={14}/>Read repair instructions</Button></div><Suspense fallback={<Loading label="Loading attack explorer…"/>}><AttackExplorer finding={finding} mode={graphMode} selected={selected} repairId={repairId} onModeChange={onMode} onSelect={onSelect} onRepairChange={onRepair} onReadRepair={openRepair} onEvidence={onEvidence}/></Suspense></div>}</TabsContent>
        <TabsContent value="evidence"><EvidencePanel finding={finding} onEvidence={onEvidence}/></TabsContent>
      </Tabs>
    </div>}
  </article>;
}
