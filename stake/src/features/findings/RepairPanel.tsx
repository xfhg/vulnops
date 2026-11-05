import { useId } from 'react';
import { ArrowDown, ArrowRight, ArrowUpRight, CheckCheck, CircleHelp, FileCode2, GitBranch, Layers, Map as MapIcon, ShieldCheck, Wrench } from 'lucide-react';
import type { FindingRecord, RepairAction } from '../../domain';
import type { EvidenceHandler } from '../../components/RecordView';
import { Badge, Button } from '../../components/ui';
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger, Card, CardContent, CardFooter, CardHeader, CardTitle } from '../../components/ui/data-display';
import { human } from '../../app/state';
import { DetailSection, EvidenceList, NarrativeList, RawDisclosure } from './DossierPrimitives';
import RepairLocations from './RepairLocations';
import './repair-panel.css';

export interface RepairPanelProps {
  finding: FindingRecord;
  repairId: string;
  onRepair: (id: string) => void;
  onStep: (id: string, actionId?: string) => void;
  onActionSelect?: (id: string) => void;
  onRepairMap?: (id: string) => void;
  onExample?: (id: string, actionId?: string) => void;
  onVerify: () => void;
  onEvidence: EvidenceHandler;
}

const recordedText = (value: unknown): string | null => typeof value === 'string' && value.trim() ? value : null;
const itemCount = (value: unknown) => Array.isArray(value) ? value.length : null;

/** Prefer a recorded sentence; never replace the complete change with this label. */
function headline(value: string): string {
  const sentence = value.match(/^\s*([\s\S]*?[.!?])(?=\s|$)/)?.[1];
  if (sentence && sentence.length <= 180) return sentence;
  if (value.length <= 180) return value;
  const end = value.lastIndexOf(' ', 175);
  return value.slice(0, end > 80 ? end : 175) + '…';
}

function Rationale({ value }: { value: unknown }) {
  const rationale = recordedText(value);
  return <div className="repair-rationale"><h4>Why this interrupts the attack</h4>{rationale ? rationale.length > 420
    ? <details><summary>{headline(rationale)}<span>Read full rationale</span></summary><p>{rationale}</p></details>
    : <p>{rationale}</p>
    : <p className="repair-empty-copy">No rationale was recorded for this action.</p>}</div>;
}

function ActionCard({ action, index, anchorId, finding, repairId, onRepair, onStep, onRepairMap, onExample, onActionSelect, onEvidence }: Omit<RepairPanelProps, 'onVerify'> & { action: RepairAction; index: number; anchorId: string }) {
  const change = recordedText(action.change), title = change ? headline(change) : 'Implementation change not recorded';
  const steps = new Map((finding.raw.exploitation?.steps ?? []).map(step => [step.id, step]));
  const components = new Map((finding.raw.affected_components ?? []).map(component => [component.id, component]));
  const examples = new Map((finding.raw.technical_examples ?? []).map(example => [example.id, example]));
  const stepIds = action.breaks_steps ?? [], componentIds = action.component_ids ?? [], exampleIds = action.example_ids ?? [];
  const locations = action.locations ?? [], selected = repairId === action.id;
  const mappedSteps = stepIds.filter(id => steps.has(id)).length;
  const hasOverlayTarget = mappedSteps > 0 || locations.some(location => recordedText(location.file));
  const status = recordedText(action.status);
  return <article id={anchorId} tabIndex={-1} aria-label={`Repair action ${index + 1}: ${action.id || 'ID not recorded'}`} className={'repair-implementation-card' + (selected ? ' repair-implementation-selected' : '')} data-repair-id={action.id}>
    <Card><CardHeader className="repair-action-header"><div className="repair-action-topline"><span className="repair-action-number">CONTROL CHANGE {String(index + 1).padStart(2, '0')}</span><Badge>{status ? `Recorded status: ${human(status)}` : 'Proposed control'}</Badge></div><CardTitle>{title}</CardTitle><div className="repair-action-identity"><code>{action.id || 'Action ID not recorded'}</code>{selected && <span><Wrench size={12} aria-hidden="true"/>Selected action</span>}</div></CardHeader>
      <CardContent className="repair-action-body">
        {change && title !== change && <div className="repair-complete-change"><h4>Implementation change</h4><p>{change}</p></div>}
        <div className="repair-source-locations"><div className="repair-source-heading"><div className="repair-block-heading"><FileCode2 size={15} aria-hidden="true"/><h4>Where to change</h4><span>{locations.length}</span></div>{onRepairMap && <Button variant="outline" size="sm" disabled={!action.id} onClick={() => onRepairMap(action.id)}><MapIcon size={14} aria-hidden="true"/>Open repair map<ArrowUpRight size={13} aria-hidden="true"/></Button>}</div><RepairLocations finding={finding} action={action} onActionSelect={onActionSelect}/></div>
        <Rationale value={action.rationale}/>
        <div className="repair-action-associations"><div className="repair-interruptions"><div className="repair-block-heading"><GitBranch size={15}/><h4>Recorded interruption points</h4><span>{stepIds.length}</span></div>
          {stepIds.length ? <ul>{stepIds.map((id, position) => {
            const step = steps.get(id);
            return <li key={`${id}-${position}`}>{step ? <button type="button" className="repair-step-link" aria-label={`Read reproduction step ${id}: ${recordedText(step.action) ?? 'Step action not recorded'}`} onClick={() => onStep(id, action.id)}><span className="repair-step-id">{id}</span><span className="repair-step-title">{recordedText(step.action) ?? 'Step action not recorded'}<small>Read reproduction step</small></span><ArrowUpRight size={15} aria-hidden="true"/></button>
              : <div className="repair-missing-reference"><CircleHelp size={15}/><span><code>{id}</code><small>Referenced step is unavailable in this dossier.</small></span></div>}</li>;
          })}</ul> : <p className="repair-empty-copy">No explicit step association was recorded.</p>}
          {stepIds.length > mappedSteps && <p className="repair-reference-note">Only available, explicitly linked steps can be opened in the procedure.</p>}
        </div><div className="repair-components"><div className="repair-block-heading"><Layers size={15}/><h4>Linked components</h4><span>{componentIds.length}</span></div>
          {componentIds.length ? <ul>{componentIds.map((id, position) => {
            const component = components.get(id);
            return <li key={`${id}-${position}`}><span>{component ? recordedText(component.name) ?? 'Component name not recorded' : 'Referenced component unavailable'}</span><code>{id}</code>{component?.repository && <small>{component.repository}</small>}</li>;
          })}</ul> : <p className="repair-empty-copy">No explicit component association was recorded.</p>}
        </div></div>
        {exampleIds.length > 0 && <div className="repair-example-references"><h4>Referenced technical examples</h4><ul>{exampleIds.map((id, position) => {
          const example = examples.get(id);
          return <li key={`${id}-${position}`}>{example && onExample ? <button type="button" className="repair-example-link" aria-label={`Open technical example ${id}`} onClick={() => onExample(id, action.id)}><FileCode2 size={14} aria-hidden="true"/><span><code>{id}</code><small>{human(example.kind)} · Open technical example</small></span><ArrowUpRight size={14} aria-hidden="true"/></button>
            : <div className={example ? 'repair-example-summary' : 'repair-missing-reference'}>{!example && <CircleHelp size={14} aria-hidden="true"/>}<span><code>{id}</code><small>{example ? `${human(example.kind)} · Available in Reproduce` : 'Referenced example unavailable'}</small></span></div>}</li>;
        })}</ul></div>}
        <EvidenceList refs={action.evidence_refs} runId={finding.runId} onEvidence={onEvidence} label="Action evidence"/>
        <RawDisclosure value={action} label="Complete action record"/>
      </CardContent>
      <CardFooter className="repair-action-footer"><p><GitBranch size={15}/><span>Attack graph overlay: highlight the explicitly linked steps and source locations.</span></p><Button variant="outline" size="sm" disabled={!action.id || !hasOverlayTarget} title={!hasOverlayTarget ? 'No available step or source location is linked to this action.' : undefined} onClick={() => onRepair(action.id)}><GitBranch size={14}/>Show interruption</Button></CardFooter>
    </Card>
  </article>;
}

export default function RepairPanel({ finding, repairId, onRepair, onStep, onActionSelect, onRepairMap, onExample, onVerify, onEvidence }: RepairPanelProps) {
  const anchorPrefix = useId();
  const remediation = finding.raw.remediation, actions = remediation?.actions ?? [], checks = remediation?.verification_checks;
  const actionAnchor = (index: number) => `${anchorPrefix}-repair-action-${index}`;
  const jumpToAction = (index: number) => {
    const id = actions[index]?.id;
    
    const target = document.getElementById(actionAnchor(index));
    target?.scrollIntoView({ block: 'start', behavior: 'instant' });
    target?.focus({ preventScroll: true });
    if (onActionSelect && id) onActionSelect(id);
  };
  const guidance = [
    { id: 'containment', title: 'Temporary containment', description: 'Recorded controls that limit exposure while a repair is prepared.', value: remediation?.containment, empty: 'No temporary containment guidance was recorded.' },
    { id: 'detection', title: 'Detection guidance', description: 'Recorded signals and observations to support investigation.', value: remediation?.detection, empty: 'No detection guidance was recorded.' },
    { id: 'limitations', title: 'Implementation limitations', description: 'Constraints on this remediation guidance.', value: remediation?.limitations, empty: 'No implementation limitations were recorded.' },
    { id: 'unresolved-decisions', title: 'Unresolved decisions', description: 'Decisions left open by the assessment.', value: remediation?.unresolved_decisions, empty: 'No unresolved decisions were recorded.' },
  ];
  return <div className="repair-panel"><div className="repair-panel-intro"><div><p className="repair-panel-eyebrow">IMPLEMENTATION GUIDANCE</p><h2>Break the recorded attack path.</h2><p>Review each control change, its exact interruption points and the source locations cited by the assessment.</p></div><span className="repair-action-total"><Wrench size={16}/>{actions.length} {actions.length === 1 ? 'action' : 'actions'} recorded</span></div>
    {actions.length > 1 && <nav className="repair-action-navigation" aria-label="Repair actions"><span>Recorded action order · Jump to a control change</span><ol>{actions.map((action, index) => <li key={`${action.id}-${index}`}><button type="button" onClick={() => jumpToAction(index)} aria-label={`Go to repair action ${index + 1}: ${action.id || 'ID not recorded'}`} aria-current={repairId === action.id ? 'true' : undefined} title={recordedText(action.change) ?? undefined}><span className="repair-navigation-number">{String(index + 1).padStart(2, '0')}</span><span className="repair-navigation-copy"><strong>{recordedText(action.change) ? headline(action.change) : 'Implementation change not recorded'}</strong><code>{action.id || 'Action ID not recorded'}</code></span><ArrowDown size={14} aria-hidden="true"/></button></li>)}</ol></nav>}
    {actions.length ? <div className="repair-action-stack">{actions.map((action, index) => <ActionCard key={`${action.id}-${index}`} action={action} index={index} anchorId={actionAnchor(index)} finding={finding} repairId={repairId} onRepair={onRepair} onStep={onStep} onRepairMap={onRepairMap} onExample={onExample} onActionSelect={() => jumpToAction(index)} onEvidence={onEvidence}/>)}</div>
      : <DetailSection title="No repair actions recorded" description="This dossier does not include an implementation action."><p className="repair-empty-copy">Original evidence and any supporting guidance remain available below.</p></DetailSection>}
    <DetailSection title="Supporting guidance" description="Additional controls and decisions for implementation." className="repair-supporting-guidance"><Accordion type="multiple">{guidance.map(section => <AccordionItem value={section.id} key={section.id}><AccordionTrigger><span><strong>{section.title}</strong><small>{section.description}</small></span><Badge>{itemCount(section.value) ?? 'Not recorded'}</Badge></AccordionTrigger><AccordionContent><NarrativeList value={section.value} empty={section.empty}/></AccordionContent></AccordionItem>)}</Accordion></DetailSection>
    <Card className="repair-verification-handoff"><CardContent><span className="repair-verification-icon"><ShieldCheck size={23}/></span><div><h3>Check the attack and the legitimate path.</h3><p>{checks === undefined ? 'Verification checks were not recorded.' : checks.length ? `${checks.length} recorded ${checks.length === 1 ? 'check describes' : 'checks describe'} the expected attack rejection and legitimate behavior.` : 'No verification checks are included in this dossier.'}</p><p className="repair-verification-scope">Checks belong to the finding; no action-specific check link is recorded.</p></div><Button variant="outline" onClick={onVerify}><CheckCheck size={15}/>Review verification checks<ArrowRight size={15}/></Button></CardContent></Card>
    <div className="repair-complete-record"><RawDisclosure value={remediation} label="Complete remediation record"/></div>
  </div>;
}
