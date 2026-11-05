import { lazy, Suspense, useId } from 'react';
import { ArrowDown, ArrowUpRight, FileCode2, GitBranch, ListOrdered, UserRound, Wrench } from 'lucide-react';
import type { FindingRecord, ProcedureStep } from '../../domain/types';
import { human } from '../../app/state';
import { Badge, Button } from '../../components/ui';
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger, Card, CardContent, CardFooter, CardHeader, CardTitle } from '../../components/ui/data-display';
import type { EvidenceHandler } from '../../components/RecordView';
import { DetailSection, EvidenceList, NarrativeList, RawDisclosure } from './DossierPrimitives';
import './reproduce-panel.css';

const CodeBlock = lazy(() => import('../../components/CodeBlock'));

export interface ReproducePanelProps {
  finding: FindingRecord;
  onStep: (id: string) => void;
  onRecordStep?: (id: string) => void;
  onRepair: (id: string) => void;
  onEvidence: EvidenceHandler;
}

function hasValue(value: unknown): boolean {
  return value !== null && value !== undefined && (typeof value !== 'string' || value.trim().length > 0);
}

function StepField({ label, value, empty = 'Not recorded.' }: { label: string; value: unknown; empty?: string }) {
  return <div className="repro-field"><dt>{label}</dt><dd><NarrativeList value={value} empty={empty} /></dd></div>;
}

export default function ReproducePanel({ finding, onStep, onRecordStep, onRepair, onEvidence }: ReproducePanelProps) {
  const prefix = useId();
  const raw = finding.raw;
  const exploitation = raw.exploitation;
  const steps = exploitation?.steps ?? [];
  const examples = raw.technical_examples ?? [];
  const actions = raw.remediation?.actions ?? [];
  const components = new Map((raw.affected_components ?? []).map(component => [component.id, component]));
  const actor = raw.attacker;
  const setup = [...new Set(exploitation?.setup ?? [])];
  const conditions = [...new Set(raw.conditions ?? [])];
  const additionalConditions = conditions.filter(condition => !setup.includes(condition));
  const sharedConditionCount = conditions.length - additionalConditions.length;
  const exampleTarget = (index: number) => `${prefix}-example-${index}`;
  const jumpToExample = (index: number) => {
    const target = document.getElementById(exampleTarget(index));
    target?.scrollIntoView({ block: 'start', behavior: 'instant' });
    target?.focus({ preventScroll: true });
  };

  function renderStep(step: ProcedureStep, index: number) {
    const repairs = actions.filter(action => action.breaks_steps?.includes(step.id));
    const componentIds = step.component_ids ?? [];
    const primitiveIds = step.primitive_ids ?? [];
    const observationRecorded = hasValue(step.observed_result);
    return <li key={`${step.id}-${index}`} className="repro-walkthrough-item"><section tabIndex={-1} data-detail-record={JSON.stringify(['step', step.id])} aria-labelledby={`${prefix}-step-${index}`}><Card className="procedure-card repro-procedure-card">
      <CardHeader className="repro-step-header"><span className="repro-step-number" aria-label={`Step ${index + 1}`}>{String(index + 1).padStart(2, '0')}</span>
        <div className="repro-step-heading"><div className="repro-step-identity"><span className="repro-record-id">{step.id}</span><Badge tone={step.evidence_status === 'environment_required' ? 'amber' : 'neutral'}>{human(step.evidence_status)}</Badge></div>
          <CardTitle id={`${prefix}-step-${index}`}>{step.action || 'Action not recorded'}</CardTitle>
        </div>
      </CardHeader>
      <CardContent className="repro-step-body"><dl className="repro-step-inputs">
        <StepField label="Controlled input" value={step.controlled_input} />
        <StepField label="Why it works" value={step.why_it_works} />
      </dl>
        <dl className="repro-step-effects"><div className="repro-effect repro-effect-expected"><dt>Expected effect</dt><dd><NarrativeList value={step.expected_result} empty="No expected effect recorded." /></dd></div>
          <div className={'repro-effect repro-effect-observed ' + (observationRecorded ? 'has-observation' : '')}><dt>Observed effect</dt><dd><NarrativeList value={step.observed_result} empty="No observation recorded; no execution claimed." /></dd>
            {step.evidence_status === 'observed_contained' && <small>Recorded observation scope: contained environment.</small>}
          </div>
        </dl>
        {(hasValue(step.missing_fact) || hasValue(step.missing_prerequisite) || hasValue(step.next_action)) && <dl className="repro-step-prerequisite">
          {(hasValue(step.missing_fact) || hasValue(step.missing_prerequisite)) && <StepField label="Missing prerequisite" value={step.missing_fact ?? step.missing_prerequisite} />}
          {hasValue(step.next_action) && <StepField label="Next action" value={step.next_action} />}
        </dl>}
        <div className="repro-step-evidence"><EvidenceList refs={step.evidence_refs} runId={finding.runId} onEvidence={onEvidence} label="Supporting evidence" />
          {Boolean(step.observation_refs?.length) && <EvidenceList refs={step.observation_refs} runId={finding.runId} onEvidence={onEvidence} label="Observation references" />}
        </div>
        {(componentIds.length > 0 || primitiveIds.length > 0) && <div className="repro-step-context">
          {componentIds.length > 0 && <div><span>Components</span><ul>{componentIds.map((id, componentIndex) => <li key={`${id}-${componentIndex}`}><strong>{components.get(id)?.name || id}</strong>{components.has(id) ? <code>{id}</code> : <small>Component record unavailable</small>}</li>)}</ul></div>}
          {primitiveIds.length > 0 && <div><span>Recorded primitives</span><ul>{primitiveIds.map((id, primitiveIndex) => <li key={`${id}-${primitiveIndex}`}><code>{id}</code></li>)}</ul></div>}
        </div>}
        <div className="repro-step-record"><RawDisclosure value={step} label="Complete recorded step" /></div>
      </CardContent>
      <CardFooter className="repro-step-footer"><div className="repro-step-actions"><Button variant="outline" size="sm" onClick={() => onStep(step.id)}><GitBranch size={14} />Show in attack map</Button>
        {repairs.map((action, actionIndex) => <Button key={`${action.id}-${actionIndex}`} variant="ghost" size="sm" onClick={() => onRepair(action.id)} title={action.change}><Wrench size={13} />Read repair {action.id}<ArrowUpRight size={12} /></Button>)}
      </div>{Boolean(step.example_ids?.length) && <div className="repro-step-examples">{step.example_ids!.map((id, exampleIndex) => {
        const target = examples.findIndex(example => example.id === id);
        return target >= 0 ? <Button variant="ghost" size="sm" key={`${id}-${exampleIndex}`} onClick={() => jumpToExample(target)} aria-label={`View example ${id}`}><FileCode2 size={13} />{id}<ArrowDown size={12} /></Button>
          : <span className="repro-unavailable-example" key={`${id}-${exampleIndex}`}><FileCode2 size={12} />{id} · Example unavailable</span>;
      })}</div>}</CardFooter>
    </Card></section></li>;
  }

  return <div className="reproduce-panel">
    <DetailSection title="Setup and prerequisites" description="Recorded requirements, access and conditions.">
      <div className="repro-setup-grid"><div className="repro-setup-requirements"><h3><ListOrdered size={16} />Recorded setup</h3><div className="repro-checklist"><NarrativeList value={setup} empty="No setup requirements recorded." /></div>
        <div className="repro-required-conditions"><h3>Required conditions</h3>{additionalConditions.length > 0 || !sharedConditionCount ? <NarrativeList value={additionalConditions} empty="No additional conditions recorded." /> : null}
          {sharedConditionCount > 0 && <p className="repro-shared-requirements">{sharedConditionCount} condition{sharedConditionCount === 1 ? ' is' : 's are'} already included in the setup list.</p>}
        </div>
      </div><aside className="repro-access" aria-label="Recorded actor and access"><h3><UserRound size={15} />Actor and starting access</h3><dl>
        <StepField label="Actor" value={actor?.perspective} />
        <StepField label="Starting access" value={actor?.starting_access} />
        {hasValue(actor?.boundary_crossed) && <StepField label="Boundary crossed" value={actor?.boundary_crossed} />}
      </dl></aside></div>
      {hasValue(exploitation?.rationale) && <Accordion type="single" collapsible className="repro-setup-rationale"><AccordionItem value="rationale"><AccordionTrigger>Why this procedure works</AccordionTrigger><AccordionContent><NarrativeList value={exploitation?.rationale} /></AccordionContent></AccordionItem></Accordion>}
      <RawDisclosure label="Complete setup and access record" value={{ attacker: raw.attacker, conditions: raw.conditions, ...Object.fromEntries(Object.entries(exploitation ?? {}).filter(([key]) => key !== 'steps')) }} />
    </DetailSection>

    <div className="repro-walkthrough-heading"><div><span className="repro-kicker">RECORDED PROCEDURE</span><h2>Reproduction walkthrough</h2></div><span>{steps.length} step{steps.length === 1 ? '' : 's'}</span></div>
    {steps.length ? <ol className="procedure-list repro-walkthrough" aria-label="Recorded reproduction procedure">{steps.map(renderStep)}</ol>
      : <div className="repro-empty"><ListOrdered size={25} /><h3>No reproduction procedure recorded</h3><p>This finding does not contain ordered reproduction steps. Any recorded examples remain available below.</p></div>}

    <DetailSection title="Reviewed technical examples" description="Copying an example does not run it or change its recorded execution status." aside={<Badge>{examples.length} example{examples.length === 1 ? '' : 's'}</Badge>} className="repro-examples-section">
      {examples.length ? <div className="repro-examples">{examples.map((example, index) => {
        const usedBy = steps.filter(step => step.example_ids?.includes(example.id));
        return <section key={`${example.id}-${index}`} className="repro-example" id={exampleTarget(index)} data-detail-record={JSON.stringify(['example', example.id])} tabIndex={-1} aria-label={`Recorded technical example ${example.id}`}>
          <div className="repro-example-heading"><span className="repro-kicker">{human(example.kind)} example</span>{usedBy.length > 0 && <div><span>Referenced by</span>{usedBy.map((step, stepIndex) => <Button variant="ghost" size="sm" key={`${step.id}-${stepIndex}`} onClick={() => onRecordStep ? onRecordStep(step.id) : onStep(step.id)}>{step.id}<GitBranch size={12} /></Button>)}</div>}</div>
          <Suspense fallback={<pre className="code-content">{example.content}</pre>}><CodeBlock example={example} /></Suspense>
          <EvidenceList refs={example.evidence_refs} runId={finding.runId} onEvidence={onEvidence} label="Example evidence" />
          {Boolean(example.observation_refs?.length) && <EvidenceList refs={example.observation_refs} runId={finding.runId} onEvidence={onEvidence} label="Observation references" />}
          <RawDisclosure value={example} label="Complete recorded example" />
        </section>;
      })}</div> : <div className="repro-empty repro-empty-compact"><FileCode2 size={23} /><h3>No reviewed technical examples recorded</h3><p>The procedure can still be reviewed against its cited evidence.</p></div>}
    </DetailSection>
  </div>;
}
