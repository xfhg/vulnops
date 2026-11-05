import { useState } from 'react';
import * as Collapsible from '@radix-ui/react-collapsible';
import { ArrowRight, ArrowUpRight, ChevronDown, FileCode2, GitBranch, ListChecks } from 'lucide-react';
import { Button } from '../../components/ui';
import { Card } from '../../components/ui/data-display';
import type { RepairGraph, RepairNode } from './model';
import './repair-brief.css';

export interface RepairBriefProps {
  graph: RepairGraph;
  onExplore: (nodeId?: string) => void;
  onFinding: () => void;
}

const count = (value: number, singular: string, plural = `${singular}s`) => `${value} ${value === 1 ? singular : plural}`;

function Rationale({ text }: { text: string | null }) {
  const [expanded, setExpanded] = useState(false);
  if (!text) return <section className="rb-rationale" aria-label="Why this change"><h3>Why this change</h3><p className="rb-muted">Rationale not recorded for this action.</p></section>;
  if (text.length <= 500) return <section className="rb-rationale" aria-label="Why this change"><h3>Why this change</h3><p className="rb-rationale-text">{text}</p></section>;
  const preview = text.slice(0, 260).trimEnd();
  return <section className="rb-rationale" aria-label="Why this change"><h3>Why this change</h3>
    <Collapsible.Root open={expanded} onOpenChange={setExpanded}>
      {!expanded && <p className="rb-rationale-preview">{preview}…</p>}
      <Collapsible.Content><p className="rb-rationale-text">{text}</p></Collapsible.Content>
      <Collapsible.Trigger className="rb-rationale-toggle">{expanded ? 'Collapse rationale' : 'Show full rationale'}<ChevronDown size={14} aria-hidden="true" /></Collapsible.Trigger>
    </Collapsible.Root>
  </section>;
}

function MissingReferences({ records, label, onExplore }: { records: RepairNode[]; label: string; onExplore: RepairBriefProps['onExplore'] }) {
  const unavailable = records.filter(record => record.unavailable);
  if (!unavailable.length) return null;
  return <button type="button" className="rb-missing-references" onClick={() => onExplore(unavailable[0].id)}>
    Inspect {count(unavailable.length, `unavailable ${label} reference`)}<ArrowUpRight size={12} aria-hidden="true" />
  </button>;
}

function LocationPreview({ node, onExplore }: { node: RepairNode; onExplore: RepairBriefProps['onExplore'] }) {
  const fullPath = node.file || node.title;
  const basename = node.file ? node.file.split('/').at(-1) || node.file : node.title;
  const coordinate = node.unavailable ? 'Unresolved reference' : node.line == null ? 'File-level target'
    : `L${node.line}${node.endLine != null && node.endLine !== node.line ? `–${node.endLine}` : ''}`;
  return <button type="button" className={`rb-location-preview${node.unavailable ? ' rb-location-unavailable' : ''}`}
    aria-label={`Inspect change location: ${fullPath}`} onClick={() => onExplore(node.id)} title={fullPath}>
    <FileCode2 size={15} aria-hidden="true" /><code>{basename}</code><span>{coordinate}</span><ArrowUpRight size={13} aria-hidden="true" />
  </button>;
}

/** A reading guide to the recorded recommendation, never an implementation or
 * verification plan generated from counts. Complete records live in the map and dossier. */
export default function RepairBrief({ graph, onExplore, onFinding }: RepairBriefProps) {
  const action = graph.nodes.find(node => node.kind === 'action');
  const finding = graph.nodes.find(node => node.kind === 'finding');
  const locations = graph.nodes.filter(node => node.kind === 'location' && node.scope === 'action');
  const components = graph.nodes.filter(node => node.kind === 'component' && node.scope === 'action');
  const steps = graph.nodes.filter(node => node.kind === 'step' && node.scope === 'action');
  const examples = graph.nodes.filter(node => node.kind === 'example' && node.scope === 'action');
  const checks = graph.nodes.filter(node => node.kind === 'check' && node.scope === 'finding');
  const rationale = typeof graph.entry.action.rationale === 'string' && graph.entry.action.rationale.trim() ? graph.entry.action.rationale : null;
  const statuses = new Map<string, number>();
  for (const check of checks) statuses.set(check.status || 'not_recorded', (statuses.get(check.status || 'not_recorded') ?? 0) + 1);
  const interruption = steps[0] ?? examples[0];
  return <section className="repair-brief" aria-label="Repair brief">
    <Rationale key={graph.entry.key} text={rationale} />

    <Card className="rb-locate" role="region" aria-label="Locate the change">
      <header className="rb-route-heading"><span className="rb-route-number" aria-hidden="true">01</span><div><h3>Locate the change</h3>
        <p>{count(locations.length, 'change location')} · {count(components.length, 'linked component')}</p></div><FileCode2 size={19} aria-hidden="true" /></header>
      {locations.length ? <ul className="rb-locations">{locations.slice(0, 3).map(node => <li key={node.id}><LocationPreview node={node} onExplore={onExplore} /></li>)}</ul>
        : <p className="rb-empty-context">No change locations recorded. The proposed control change and any linked components remain available in the map.</p>}
      <div className="rb-locate-notes">
        {locations.length > 3 && <button type="button" className="rb-text-link" onClick={() => onExplore(locations[0].id)}>Explore all {locations.length} change locations<ArrowRight size={13} aria-hidden="true" /></button>}
        <MissingReferences records={[...locations, ...components]} label="target" onExplore={onExplore} />
      </div>
      <footer><span>Explore the source targets and their recorded relationships.</span><Button onClick={() => onExplore(locations[0]?.id ?? action?.id)}>Explore repair map<ArrowRight size={14} aria-hidden="true" /></Button></footer>
    </Card>

    <div className="rb-secondary-routes">
      <section className="rb-secondary-route" aria-label="Understand interruption"><div className="rb-route-number" aria-hidden="true">02</div><div className="rb-route-body">
        <h3><GitBranch size={15} aria-hidden="true" />Understand interruption</h3><p className="rb-route-counts">{count(steps.length, 'interrupted step')} · {count(examples.length, 'linked example')}</p>
        {interruption ? <p className="rb-record-preview" title={interruption.title}><span>{steps.length ? 'Recorded step' : 'Linked example'} · {interruption.localId}</span>{interruption.title}</p>
          : <p className="rb-empty-context">No interrupted steps or linked examples recorded for this action.</p>}
        <MissingReferences records={[...steps, ...examples]} label="interruption" onExplore={onExplore} />
      </div><Button variant="ghost" size="sm" onClick={() => onExplore(interruption?.id ?? action?.id)}>Explore interruption<ArrowUpRight size={13} aria-hidden="true" /></Button></section>

      <section className="rb-secondary-route" aria-label="Review verification"><div className="rb-route-number" aria-hidden="true">03</div><div className="rb-route-body">
        <h3><ListChecks size={15} aria-hidden="true" />Review verification</h3><p className="rb-route-counts">{count(checks.length, 'finding-level check')}</p>
        {checks.length > 0 ? <div className="rb-check-statuses" aria-label="Recorded verification check statuses">{[...statuses].map(([status, total]) => <span key={status}><code>{status}</code><strong>{total}</strong></span>)}</div>
          : <p className="rb-empty-context">No verification checks recorded for the finding.</p>}
        <p className="rb-context-note">Checks belong to the finding; no action-specific check link is recorded.</p>
        <MissingReferences records={checks} label="check" onExplore={onExplore} />
      </div><Button variant="ghost" size="sm" onClick={() => onExplore(checks[0]?.id ?? finding?.id ?? action?.id)}>Review finding checks<ArrowUpRight size={13} aria-hidden="true" /></Button></section>
    </div>

    <footer className="rb-dossier-link"><span>Complete repair guidance, evidence and finding context.</span><Button variant="outline" size="sm" onClick={onFinding}>Open full repair dossier<ArrowUpRight size={13} aria-hidden="true" /></Button></footer>
  </section>;
}
