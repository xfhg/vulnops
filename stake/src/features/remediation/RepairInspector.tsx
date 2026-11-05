import { ArrowUpRight, FileCode2, GitBranch, Wrench } from 'lucide-react';
import type { EvidenceHandler } from '../../components/RecordView';
import { Badge, Button } from '../../components/ui';
import { human } from '../../app/state';
import { EvidenceList, NarrativeList, RawDisclosure } from '../findings/DossierPrimitives';
import type { RepairGraph, RepairNode } from './model';

export const repairKindLabel = (kind: RepairNode['kind']) => ({ action: 'Control change', finding: 'Finding context', location: 'Change locations', component: 'Linked components', step: 'Interrupted attack steps', example: 'Technical examples', check: 'Verification checks', guidance: 'Supporting guidance' })[kind];

function visibleFields(node: RepairNode) {
  return node.fields.filter(field => {
    // Identity, status and explicit connections already have dedicated controls.
    // Preserve the complete original record in the disclosure below.
    if (field.value === node.title || field.label === 'Association' || field.label.startsWith('Recorded ') && field.label.endsWith('status')) return false;
    if (node.kind === 'action' && ['Proposed locations', 'Affected component IDs', 'Interrupted step IDs', 'Example IDs'].includes(field.label)) return false;
    if (node.kind === 'example' && field.label === 'Content' && typeof node.raw.content === 'string') return false;
    return true;
  });
}

function Field({ label, value }: { label: string; value: unknown }) {
  const text = typeof value === 'string' ? value : null;
  return <div className="rm-detail-field"><dt>{label}</dt><dd>{text && text.length > 500 ? <details><summary>{text.slice(0, 220)}… <span>Read complete field</span></summary><p>{text}</p></details> : value && typeof value === 'object' ? <RawDisclosure value={value} label={`View ${label.toLowerCase()}`}/> : <NarrativeList value={value} empty="Not recorded."/>}</dd></div>;
}
export default function RepairInspector({ graph, selected, onSelect, onOpen, onEvidence, onCode }: {
  graph: RepairGraph; selected: string; onSelect: (id: string) => void; onOpen: (node: RepairNode) => void; onEvidence: EvidenceHandler; onCode: (file: string) => void;
}) {
  const node = graph.nodes.find(node => node.id === selected), edge = graph.edges.find(edge => edge.id === selected);
  const endpoint = (id: string) => graph.nodes.find(node => node.id === id);
  const related = node ? graph.edges.filter(edge => edge.source === node.id || edge.target === node.id) : [];
  const evidenceGroups = new Map<string, unknown[]>();
  for (const evidence of node?.evidence ?? []) evidenceGroups.set(evidence.runId, [...(evidenceGroups.get(evidence.runId) ?? []), evidence.reference]);
  return <section className="rm-inspector" id="repair-inspector" aria-label="Repair record details">
    {!node && !edge ? <div className="rm-inspector-empty"><GitBranch size={23}/><h3>Selected record unavailable</h3><p>Select an available record in this repair map.</p><Button variant="outline" onClick={() => { const action = graph.nodes.find(item => item.kind === 'action'); if (action) onSelect(action.id); }}>Show control change</Button></div> : edge ? <>
      <header><div><span className="eyebrow">RECORDED RELATIONSHIP</span><h3>{edge.label}</h3></div><Badge>{edge.kind === 'context' ? 'Finding-level context' : 'Action relationship'}</Badge></header><p className="rm-edge-description">{edge.description}</p>
      <div className="rm-edge-endpoints">{[edge.source, edge.target].map(id => { const record = endpoint(id); return record && <button key={id} onClick={() => onSelect(id)}><span>{repairKindLabel(record.kind)} · {record.localId}</span><strong>{record.title}</strong><ArrowUpRight size={14}/></button>; })}</div>
    </> : node && <>
      <header><div><span className="eyebrow">{repairKindLabel(node.kind)} · {node.localId}</span><h3>{node.title}</h3></div><div className="rm-inspector-actions"><Badge>{node.unavailable ? 'Unavailable record' : node.status === 'not_recorded' ? node.kind === 'action' ? 'Proposed guidance' : 'Status not recorded' : human(node.status)}</Badge>
        {!node.unavailable && ['action', 'finding', 'step', 'example', 'check'].includes(node.kind) && <Button variant="outline" size="sm" onClick={() => onOpen(node)}>{node.kind === 'step' ? 'Open attack step' : node.kind === 'check' ? 'Open verification' : node.kind === 'example' ? 'Open reproduction' : node.kind === 'action' ? 'Open repair details' : 'Open finding'}<ArrowUpRight size={13}/></Button>}
        {!node.unavailable && node.kind === 'location' && <Button size="sm" onClick={() => onOpen(node)}>Read implementation instructions<ArrowUpRight size={13}/></Button>}
        {!node.unavailable && node.kind === 'location' && node.file && <Button variant="outline" size="sm" onClick={() => onCode(node.file!)}><FileCode2 size={14}/>Open in Code Map</Button>}
      </div></header>
      {node.scope === 'finding' && node.kind !== 'finding' && <p className="rm-context-label">Finding-level context · recorded for {graph.entry.finding.id}; no action-specific link is recorded.</p>}
      <div className="rm-inspector-grid"><div><dl className="rm-detail-fields">{visibleFields(node).map((field, index) => <Field key={index} {...field}/>)}</dl>{node.kind === 'example' && typeof node.raw.content === 'string' && <pre className="rm-example-content">{node.raw.content}</pre>}
        <RawDisclosure value={node.raw} label="Complete selected record"/></div><aside className="rm-evidence-column">{evidenceGroups.size ? [...evidenceGroups].map(([runId, refs]) => <EvidenceList key={runId} refs={refs} runId={runId} onEvidence={onEvidence} label="Original evidence"/>) : <div className="rm-no-evidence"><FileCode2 size={17}/><p>No supporting references recorded for this item.</p></div>}
        {!!related.length && <div className="rm-related"><h4><Wrench size={13}/>Recorded connections <span>{related.length}</span></h4><div className="rm-related-list">{related.map(link => { const other = endpoint(link.source === node.id ? link.target : link.source); return <button type="button" key={link.id} aria-pressed={selected === link.id} onClick={() => onSelect(link.id)}><span>{link.label}</span><strong>{other?.title || 'Record unavailable'}</strong></button>; })}</div></div>}
      </aside></div>
    </>}
  </section>;
}
