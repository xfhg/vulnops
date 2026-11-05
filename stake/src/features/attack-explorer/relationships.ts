import type { FindingRecord } from '../../domain';
import {
  graphId, humanize, locationReference, object, outputCapabilityLabel, records, repairActions, string, strings, values,
  type GraphItem, type GraphLink, type GraphMode, type GraphRecordKind, type Projection,
} from './projection';

export interface ConnectedRecords {
  anchorId: string | null;
  nodes: GraphItem[];
  edges: GraphLink[];
  diagnostics: string[];
}

/** The complete original reference and anchor are encoded, so a URL can restore
 * a metadata selection without guessing a relationship or borrowing another run. */
function connectionId(key: string, mode: GraphMode, anchor: string, kind: string, localId: string) {
  return graphId(key, 'connected', JSON.stringify([mode, anchor, kind, localId]));
}
export function connectedAnchor(key: string, mode: GraphMode, selected: string): string | null {
  try {
    const [entity, owner, type, value] = JSON.parse(selected);
    if (entity !== 'entity' || owner !== key || type !== 'connected') return null;
    const [recordedMode, anchor] = JSON.parse(value);
    return recordedMode === mode && typeof anchor === 'string' ? anchor : null;
  } catch { return null; }
}
function referenceLabel(reference: unknown): string {
  if (typeof reference === 'string') return reference;
  const value = object(reference);
  return [value.execution_id, value.artifact_ref, value.record_id ?? value.selector].filter(Boolean).join(' · ') || 'Recorded reference';
}
function evidence(raw: Record<string, unknown>): unknown[] { return [...values(raw.evidence_refs), ...values(raw.observation_refs)]; }

/** Optional associations only. These edges never enter the primary attack
 * projection, never imply flow, and never match records by ordinal or title. */
export function connectedRecords(finding: Pick<FindingRecord, 'key' | 'raw'>, mode: GraphMode, projection: Projection, selected: string): ConnectedRecords {
  const requested = connectedAnchor(finding.key, mode, selected) ?? selected;
  const selectedNode = projection.nodes.find(node => node.id === requested);
  const selectedEdge = projection.edges.find(edge => edge.id === requested);
  if (!selectedNode && !selectedEdge) return { anchorId: null, nodes: [], edges: [], diagnostics: [] };
  const anchorId = requested;
  const nodes: GraphItem[] = [], edges: GraphLink[] = [], diagnostics: string[] = [];
  const anchor = selectedNode ?? {
    id: connectionId(finding.key, mode, anchorId, 'transition', selectedEdge!.id),
    kind: selectedEdge!.kind === 'sequence' ? mode : 'transition' as const,
    localId: selectedEdge!.kind === 'sequence' ? 'Selected recorded order' : 'Selected transition', label: selectedEdge!.label,
    caption: selectedEdge!.summary ?? 'Recorded sequence relationship', status: selectedEdge!.status,
    ordinal: 0, group: 'connected', groupLabel: 'Connected records', highlighted: false,
    repairIds: [], details: selectedEdge!.details, evidence: selectedEdge!.evidence, raw: {},
  };
  if (!selectedNode) nodes.push(anchor);
  const link = (target: GraphItem, label: string, source = anchor.id) => {
    const id = connectionId(finding.key, mode, anchorId, 'association', JSON.stringify([source, target.id, label]));
    if (!edges.some(edge => edge.id === id)) edges.push({ id, source, target: target.id, label,
      status: 'recorded_association', kind: 'association', evidence: [],
      details: [{ label: 'Relationship', value: label }, { label: 'Meaning', value: 'An explicit recorded association, not an execution or data-flow edge.' }],
    });
  };
  if (selectedEdge) {
    link(projection.nodes.find(node => node.id === selectedEdge.source)!, selectedEdge.kind === 'sequence' ? 'Previous recorded item' : 'Recorded producer');
    link(projection.nodes.find(node => node.id === selectedEdge.target)!, selectedEdge.kind === 'sequence' ? 'Next recorded item' : 'Recorded consumer');
  }
  const add = (kind: GraphRecordKind, localId: string, raw: Record<string, unknown> | undefined, label: string, relation: string,
    status = 'recorded_metadata', caption = localId, references?: unknown[], identity = localId) => {
    const id = connectionId(finding.key, mode, anchorId, kind, identity);
    let node = nodes.find(item => item.id === id);
    if (!node) {
      const missing = !raw;
      if (missing) diagnostics.push(`${humanize(kind)} ${localId} is referenced but unavailable in this finding.`);
      node = { id, kind, localId, label, caption, status: missing ? 'unavailable' : status,
        ordinal: nodes.length, group: 'connected', groupLabel: 'Connected records', highlighted: false,
        repairIds: kind === 'repair' && raw ? [localId] : [], raw: raw ?? { id: localId },
        evidence: references ?? evidence(raw ?? {}),
        details: raw ? Object.entries(raw).map(([field, value]) => ({ label: humanize(field), value }))
          : [{ label: 'Unavailable record', value: `The recorded ID ${localId} has no corresponding record in this finding.` }],
      };
      if (kind === 'component' && raw) {
        node.preview = [{ label: 'Repository', value: raw.repository ?? 'Not recorded' },
          { label: 'Service binding', value: object(raw.service).binding ?? 'Not recorded' }];
      }
      if (kind === 'composition' && raw) node.preview = [{ label: 'Input capability', value: raw.input_capability }, { label: 'Output capability', value: outputCapabilityLabel(raw.output_capability) }];
      if (kind === 'procedure' && raw) node.preview = [{ label: 'Controlled input', value: raw.controlled_input }, { label: 'Expected effect', value: raw.expected_result }];
      if (kind === 'example' && raw) node.preview = [{ label: 'Recorded example', value: raw.content }];
      if (kind === 'repair' && raw) node.preview = [{ label: 'Recommendation', value: raw.change }];
      if (kind === 'evidence') node.preview = [{ label: 'Reference availability', value: 'Open the reference to resolve its recorded content.' }];
      nodes.push(node);
    }
    link(node, relation);
  };
  const raw = selectedNode?.raw ?? {};
  const components = records(finding.raw.affected_components);
  for (const id of strings(raw.component_ids)) {
    const component = components.find(record => record.id === id);
    add('component', id, component, string(component?.name, id), 'References component', 'recorded_component',
      component ? [component.repository, object(component.service).name ?? 'Service not recorded'].filter(Boolean).join(' · ') : id);
  }
  for (const id of strings(raw.primitive_ids)) {
    const primitive = records(finding.raw.primitive_steps).find(record => record.primitive_id === id);
    add('composition', id, primitive, outputCapabilityLabel(primitive?.output_capability), 'References primitive', 'recorded_primitive', string(primitive?.boundary_crossed, id));
  }
  for (const id of strings(raw.example_ids)) {
    const example = records(finding.raw.technical_examples).find(record => record.id === id);
    add('example', id, example, `${id} · ${humanize(string(example?.kind, 'example'))}`, 'References example', string(example?.execution_status, 'unknown'));
  }
  if (selectedNode?.kind === 'composition') {
    for (const step of records(object(finding.raw.exploitation).steps).filter(step => strings(step.primitive_ids).includes(selectedNode.localId))) {
      add('procedure', string(step.id), step, string(step.action, string(step.id)), 'Referenced by procedure step', string(step.evidence_status, 'unknown'));
    }
  }
  for (const action of repairActions(finding)) {
    const interrupts = selectedNode?.kind === 'procedure' && strings(action.breaks_steps).includes(selectedNode.localId);
    const sameLocation = selectedNode?.kind === 'trace' && Boolean(locationReference(raw))
      && records(action.locations).some(location => locationReference(location) === locationReference(raw));
    if (interrupts || sameLocation) add('repair', string(action.id), action, string(action.change, string(action.id)),
      interrupts ? 'Proposes interrupting step' : 'Repair cites same location', 'proposed_repair');
  }
  for (const reference of anchor.evidence) {
    add('evidence', referenceLabel(reference), { reference }, referenceLabel(reference), 'Cites evidence', 'recorded_reference',
      typeof reference === 'string' ? 'Original recorded reference' : 'Execution-qualified reference', [reference], JSON.stringify(reference));
  }
  return { anchorId, nodes: [...new Map(nodes.map(node => [node.id, node])).values()], edges: [...new Map(edges.map(edge => [edge.id, edge])).values()], diagnostics };
}

/** One-hop focus filters existing records without creating a shortcut edge. */
export function neighborhood(projection: Projection, selected: string): Projection {
  const edge = projection.edges.find(item => item.id === selected);
  const seeds = new Set(edge ? [edge.source, edge.target] : [selected]);
  const keep = new Set(seeds);
  for (const item of projection.edges) if (seeds.has(item.source) || seeds.has(item.target)) { keep.add(item.source); keep.add(item.target); }
  if (!projection.nodes.some(node => seeds.has(node.id))) return projection;
  return { ...projection, nodes: projection.nodes.filter(node => keep.has(node.id)), edges: projection.edges.filter(item => keep.has(item.source) && keep.has(item.target)) };
}
