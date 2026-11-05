import { useId, type ReactNode } from 'react';
import { Boxes, FileCode2, KeyRound, ShieldAlert, Target, type LucideIcon } from 'lucide-react';
import type { FindingRecord, RawComponent } from '../../domain/types';
import type { EvidenceHandler } from '../../components/RecordView';
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from '../../components/ui/data-display';
import { Trace, TraceCollapsible, TraceCollapsibleContent, TraceCollapsibleTrigger, TraceDescription, TraceIcon, TraceLine, TraceTitle } from '../../components/ui/trace';
import { human } from '../../app/state';
import { DetailSection, EvidenceList, NarrativeList, RawDisclosure, SourceLocations } from './DossierPrimitives';
import './summary-panel.css';

function recorded(value: unknown, empty = 'Not recorded.'): string {
  return typeof value === 'string' && value.trim() ? value : empty;
}

function excerpt(value: unknown, empty: string): string {
  const text = recorded(value, empty).replace(/\s+/g, ' ').trim();
  if (text.length <= 185) return text;
  const boundary = text.lastIndexOf(' ', 182);
  return `${text.slice(0, boundary > 120 ? boundary : 182)}…`;
}

function ExplanationRow({ title, preview, icon: Icon, defaultOpen = false, children }: {
  title: string; preview: string; icon: LucideIcon; defaultOpen?: boolean; children: ReactNode;
}) {
  const id = useId();
  return <li><TraceCollapsible defaultOpen={defaultOpen} className="summary-trace-item">
    <h3 className="summary-trace-heading"><TraceCollapsibleTrigger aria-labelledby={`${id}-title`} aria-describedby={`${id}-preview`}>
      <TraceLine><TraceIcon className="summary-trace-icon"><Icon size={17} /></TraceIcon><span className="summary-trace-copy">
        <TraceTitle id={`${id}-title`}>{title}</TraceTitle><TraceDescription id={`${id}-preview`} className="summary-trace-preview">{preview}</TraceDescription>
      </span></TraceLine>
    </TraceCollapsibleTrigger></h3>
    <TraceCollapsibleContent className="summary-trace-content">{children}</TraceCollapsibleContent>
  </TraceCollapsible></li>;
}

function ComponentRecord({ component, runId, onEvidence }: { component: RawComponent; runId: string; onEvidence: EvidenceHandler }) {
  const entrypoints = component.entrypoints ?? [];
  const service = component.service;
  return <div className="summary-component-record">
    <div className="summary-component-grid">
      <section className="summary-component-routes" aria-label="Recorded component entrypoints">
        <h4>Recorded entrypoints <span>{entrypoints.length}</span></h4>
        {entrypoints.length ? <ol className="summary-entrypoints">{entrypoints.map((entrypoint, index) => <li key={index}>
          <span className="summary-entrypoint-number" aria-hidden="true">{String(index + 1).padStart(2, '0')}</span>
          <p>{recorded(entrypoint, 'An empty entrypoint label was recorded.')}</p>
        </li>)}</ol> : <p className="summary-empty">No entrypoints recorded for this component.</p>}
      </section>
      <section className="summary-service-context" aria-label="Recorded component service context">
        <h4>Service context</h4>
        {service ? <>
          <dl className="summary-service-facts">
            <div><dt>Service</dt><dd>{recorded(service.name, 'Name not recorded')}</dd></div>
            <div><dt>Binding</dt><dd>{service.binding ? human(service.binding) : 'Not recorded'}</dd></div>
          </dl>
          <div className="summary-service-limitation"><h5>Recorded limitation</h5><NarrativeList value={service.limitation} empty="No service limitation recorded." /></div>
          <EvidenceList refs={service.evidence_refs} runId={runId} onEvidence={onEvidence} label="Service evidence" />
        </> : <p className="summary-empty">No service binding recorded for this component.</p>}
      </section>
    </div>
    <div className="summary-component-sources"><SourceLocations locations={component.locations ?? []} runId={runId} onEvidence={onEvidence} label="Component source locations" /></div>
    <EvidenceList refs={component.evidence_refs} runId={runId} onEvidence={onEvidence} label="Component evidence" />
    <RawDisclosure value={component} label="Complete component record" />
  </div>;
}

export default function SummaryPanel({ finding, onEvidence }: { finding: FindingRecord; onEvidence: EvidenceHandler }) {
  const raw = finding.raw;
  const attacker = raw.attacker;
  const components = raw.affected_components ?? [];
  const roots = raw.root_causes ?? [];
  const specialist = Object.fromEntries(['dependency', 'secret'].filter(key => raw[key] !== undefined && raw[key] !== null).map(key => [key, raw[key]]));
  return <div className="finding-summary-panel">
    <DetailSection title="How this finding works" description="Recorded access, the failing control and its impact. Expand a row for the complete explanation."
      aside={<span className="summary-trace-provenance">From the assessed dossier</span>}>
      <Trace><ul className="summary-explanation-list" role="list" aria-label="Recorded finding explanation">
      <ExplanationRow title="Starting access and prerequisites" preview={excerpt(attacker?.starting_access ?? attacker?.perspective, 'Starting access was not recorded.')} icon={KeyRound}>
        <dl className="summary-access-facts">
          <div><dt>Actor</dt><dd>{recorded(attacker?.perspective, 'Not recorded')}</dd></div>
          <div><dt>Starting access</dt><dd>{recorded(attacker?.starting_access, 'Not recorded')}</dd></div>
          <div><dt>Boundary crossed</dt><dd>{recorded(attacker?.boundary_crossed, 'Not recorded')}</dd></div>
        </dl>
        <div className="summary-conditions"><h4>Required conditions</h4><NarrativeList value={raw.conditions} empty="No prerequisites recorded." /></div>
      </ExplanationRow>
      <ExplanationRow title="Why the boundary fails" preview={excerpt(raw.exploitation?.rationale, 'The exploitation mechanism was not recorded.')} icon={ShieldAlert} defaultOpen>
      <div className="summary-boundary-grid">
        <div><h4>Intended behavior</h4><p>{recorded(raw.intended_behavior, 'No intended behavior recorded.')}</p></div>
        <div><h4>Recorded mechanism</h4><p>{recorded(raw.exploitation?.rationale, 'No exploitation rationale recorded.')}</p></div>
      </div>
      </ExplanationRow>
      <ExplanationRow title="Impact and limits" preview={excerpt(raw.impact, 'An impact description was not recorded.')} icon={Target}>
        <p className="summary-impact">{recorded(raw.impact, 'No impact description recorded.')}</p>
        <div className="summary-limits"><h4>Recorded limits</h4><NarrativeList value={raw.impact_limits} empty="No impact limits recorded." /></div>
      </ExplanationRow>
      <ExplanationRow title="Supporting source citations" preview={roots.length ? `${roots.length} recorded root-cause location${roots.length === 1 ? '' : 's'}. Open a citation to inspect its source reference.` : 'No root-cause locations were recorded.'} icon={FileCode2}>
        <SourceLocations locations={roots} runId={finding.runId} onEvidence={onEvidence} label="Root-cause locations" />
      </ExplanationRow>
      </ul></Trace>
    </DetailSection>

    {raw.closure_rationale != null && <DetailSection title="Assessment conclusion"><NarrativeList value={raw.closure_rationale} /></DetailSection>}

    <DetailSection title="Affected components" description="Expand a component to read its complete entrypoint labels, service context and source citations."
      aside={<span className="summary-inventory-count"><Boxes size={14} aria-hidden="true" />{components.length} component{components.length === 1 ? '' : 's'}</span>}
      className="summary-components-section">
      {components.length ? <Accordion type="multiple" defaultValue={[]} className="summary-component-inventory">
        {components.map((component, index) => <AccordionItem key={`${component.id}-${index}`} value={`component-${index}`} className="summary-component-item">
          <AccordionTrigger className="summary-component-trigger">
            <span className="summary-component-icon" aria-hidden="true"><FileCode2 size={18} /></span>
            <span className="summary-component-identity"><strong>{recorded(component.name, 'Unnamed component')}</strong>
              <span><code>{recorded(component.id, 'ID not recorded')}</code><span aria-hidden="true">·</span><span>{recorded(component.repository, 'Repository not recorded')}</span></span>
            </span>
            <span className="summary-component-counts"><span>{component.entrypoints?.length ?? 0} entrypoint{component.entrypoints?.length === 1 ? '' : 's'}</span><span>{component.locations?.length ?? 0} source location{component.locations?.length === 1 ? '' : 's'}</span></span>
          </AccordionTrigger>
          <AccordionContent className="summary-component-body"><ComponentRecord component={component} runId={finding.runId} onEvidence={onEvidence} /></AccordionContent>
        </AccordionItem>)}
      </Accordion> : <p className="summary-empty">No affected components recorded.</p>}
    </DetailSection>

    {Object.keys(specialist).length > 0 && <DetailSection title="Specialist context" description="Additional dependency or redacted-secret context retained in the finding."><RawDisclosure value={specialist} label="Recorded specialist context" /></DetailSection>}
    <div className="summary-record-disclosure"><RawDisclosure value={raw} label="Complete finding record" /></div>
  </div>;
}
