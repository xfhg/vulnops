import { ArrowUpRight, FileText, GitBranch, Wrench } from 'lucide-react';
import type { EvidenceCallback } from '../attack-explorer/projection';
import { codeRoleLabel, uniqueCodeEvidence, type CodeAssociation, type CodeEvidence, type CodeFileGraph, type CodeGraphNode } from './projection';

function referenceLabel(reference: unknown): string {
  if (typeof reference === 'string') return reference;
  const record = reference && typeof reference === 'object' ? reference as Record<string, unknown> : {};
  return [record.artifact_ref, record.record_id ?? record.selector, record.execution_id].filter(value => typeof value === 'string' && value).join(' · ') || 'Recorded evidence reference';
}
function Evidence({ entries, onEvidence }: { entries: CodeEvidence[]; onEvidence?: EvidenceCallback }) {
  const references = uniqueCodeEvidence(entries);
  if (!references.length) return <p className="cg-muted">No evidence references are recorded for this connection.</p>;
  const render = (items: CodeEvidence[]) => <ul className="cg-evidence">{items.map((item, index) => <li key={index}><button type="button" disabled={!onEvidence}
    onClick={() => onEvidence?.(item.reference, item.runId)} title={referenceLabel(item.reference)}><FileText size={13}/><span>{referenceLabel(item.reference)}</span><ArrowUpRight size={12}/></button></li>)}</ul>;
  return <>{render(references.slice(0, 3))}{references.length > 3 && <details className="cg-more"><summary>Show {references.length - 3} more original references</summary>{render(references.slice(3))}</details>}</>;
}
function Associations({ rows }: { rows: CodeAssociation[] }) {
  const entries = [...new Map(rows.map(row => [JSON.stringify([row.findingKey, row.entityKey, row.role, row.explanation]), row])).values()];
  const render = (items: CodeAssociation[]) => <ul className="cg-associations">{items.map((item, index) => <li key={index}>
    <div><strong>{item.findingId}</strong><span>{codeRoleLabel(item.role)}</span></div><p>{item.label}</p>{item.explanation && <small>{item.explanation}</small>}
  </li>)}</ul>;
  return <>{render(entries.slice(0, 3))}{entries.length > 3 && <details className="cg-more"><summary>Show all {entries.length} recorded associations</summary>{render(entries.slice(3))}</details>}</>;
}
export function CodeInspector({ graph, selected, onFinding, onEvidence }: { graph: CodeFileGraph; selected: string; onFinding: (key: string) => void; onEvidence?: EvidenceCallback }) {
  const node = graph.nodes.find(item => item.id === selected);
  const edge = graph.edges.find(item => item.id === selected);
  if (!node && !edge) return <section className="cg-inspector cg-inspector-empty" aria-label="Code connection details"><GitBranch size={22}/><div><strong>Inspect a connection</strong><p>Select a finding, source range, proposed repair, or connecting line to see the exact recorded relationship.</p></div></section>;
  const associations = edge?.associations ?? node!.associations;
  const evidence = edge?.evidence ?? node!.evidence;
  const findingKey = edge?.findingKey ?? (node?.kind !== 'location' ? node?.findingKeys[0] : undefined);
  const title = edge ? `${edge.findingId} · ${edge.label}` : node!.kind === 'location' ? `${node!.label} · ${node!.title}` : node!.title;
  return <section className="cg-inspector" aria-label="Code connection details">
    <div className="cg-inspector-header"><div><span className="graph-eyebrow">{edge ? 'RECORDED ASSOCIATION' : node!.kind === 'repair' ? `PROPOSED REPAIR · ${node!.findingId} / ${node!.label}` : node!.kind === 'finding' ? `FINDING · ${node!.label}` : 'CITED SOURCE RANGE'}</span><h4>{title}</h4></div>
      {findingKey && <button className="cg-open-finding" type="button" onClick={() => onFinding(findingKey)}>Open finding<ArrowUpRight size={13}/></button>}</div>
    {edge && <p className="cg-relationship-meaning">{edge.kind === 'repair' ? 'This action explicitly lists this coordinate in its proposed repair locations.' : edge.kind === 'repair_evidence' ? 'This coordinate is cited as support for the action. It is not an explicit instruction to change this location.' : 'This finding explicitly records or cites this coordinate. The connection is not an inferred call or execution edge.'}</p>}
    {node?.kind === 'repair' && <RepairLinks node={node}/>}
    <div className="cg-inspector-columns"><div><h5>Why these records connect</h5><Associations rows={associations}/></div><div><h5>Original evidence</h5><Evidence entries={evidence} onEvidence={onEvidence}/></div></div>
  </section>;
}
function RepairLinks({ node }: { node: CodeGraphNode }) {
  return <div className="cg-repair-detail"><p>{node.rationale || 'No separate repair rationale is recorded.'}</p>
    <div className="cg-repair-links"><div><h5><Wrench size={13}/>Recorded interruption targets</h5>{node.steps?.length ? <ul>{node.steps.map(step => <li key={step.id}><strong>{step.id}</strong><span>{step.title ?? 'Target step unavailable in this finding'}</span>{step.title === null && <small>Unresolved reference</small>}</li>)}</ul> : <p>No interrupted step IDs are recorded.</p>}</div>
      <div><h5>Explicit component IDs</h5>{node.components?.length ? <ul>{node.components.map(component => <li key={component.id}><strong>{component.id}</strong><span>{component.title ?? 'Component unavailable in this finding'}</span></li>)}</ul> : <p>No affected component IDs are recorded.</p>}</div></div>
    <p className="cg-muted">A proposed interruption is guidance; this view does not establish that a change was applied or verified.</p>
  </div>;
}
