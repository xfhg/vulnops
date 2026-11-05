import { localEntityKey, type FindingRecord } from '../../domain/index';

export type GraphMode = 'procedure' | 'trace' | 'composition';
export type EvidenceCallback = (reference: unknown, runId: string) => void;
export type DetailField = { label: string; value: unknown };
export type GraphRecordKind = GraphMode | 'component' | 'example' | 'evidence' | 'repair' | 'transition';
export type GraphItem = {
  kind?: GraphRecordKind;
  /** Concise recorded fields for the canvas; details retain the full values. */
  preview?: DetailField[];
  id: string;
  localId: string;
  label: string;
  caption: string;
  status: string;
  ordinal: number;
  group: string;
  groupLabel: string;
  details: DetailField[];
  evidence: unknown[];
  highlighted: boolean;
  repairIds: string[];
  raw: Record<string, unknown>;
  hiddenCount?: number;
};
export type GraphLink = {
  kind?: 'sequence' | 'transition' | 'association';
  summary?: string;
  id: string;
  source: string;
  target: string;
  label: string;
  status: string;
  details: DetailField[];
  evidence: unknown[];
};
export type Projection = {
  nodes: GraphItem[];
  edges: GraphLink[];
  diagnostics: string[];
  groups: { id: string; label: string; count: number }[];
};

export const object = (value: unknown): Record<string, unknown> =>
  value !== null && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown> : {};
export const records = (value: unknown): Record<string, unknown>[] =>
  Array.isArray(value) ? value.map(object) : [];
export const values = (value: unknown): unknown[] => Array.isArray(value) ? value : [];
export const string = (value: unknown, fallback = ''): string => typeof value === 'string' ? value : fallback;
export const strings = (value: unknown): string[] => values(value).filter((v): v is string => typeof v === 'string');
export const humanize = (value: string): string => value.replaceAll('_', ' ').replaceAll('-', ' ');
export const graphId = (findingKey: string, mode: string, localId: string): string =>
  localEntityKey(findingKey, mode, localId);

function refs(record: Record<string, unknown>): unknown[] {
  return [...values(record.evidence_refs), ...values(record.observation_refs)];
}
/** Shared citation spelling for display, navigation and exact repair matching.
 * Missing line coordinates remain a file reference, never a dangling colon. */
export function locationReference(record: Record<string, unknown>): string {
  const file = string(record.file);
  if (!file) return '';
  const start = record.line ?? record.start_line;
  if (typeof start !== 'number' || !Number.isInteger(start) || start < 1) return file;
  const end = record.end_line;
  return `${file}:${start}${typeof end === 'number' && Number.isInteger(end) && end > 0 && end !== start ? `-${end}` : ''}`;
}
export const outputCapabilityLabel = (value: unknown): string =>
  typeof value === 'string' && value.trim() ? value : 'Output capability not recorded';
function nonemptyFields(fields: DetailField[]): DetailField[] {
  return fields.filter(({ value }) => value !== undefined && value !== null && value !== '' && !(Array.isArray(value) && value.length === 0));
}
function shortPath(path: string): string {
  return path.split('/').slice(-2).join('/');
}

export function repairActions(finding: Pick<FindingRecord, 'raw'>): Record<string, unknown>[] {
  return records(object(object(finding.raw).remediation).actions);
}

export function projectFinding(finding: Pick<FindingRecord, 'key' | 'raw'>, mode: GraphMode, repairId = ''): Projection {
  const raw = object(finding.raw);
  const actions = repairActions(finding);
  const repair = actions.find(action => action.id === repairId);
  const interruptedSteps = new Set(strings(repair?.breaks_steps));
  const repairLocations = new Set(records(repair?.locations).map(locationReference).filter(Boolean));
  const components = records(raw.affected_components);
  const componentNames = new Map(components.map(component => [string(component.id), string(component.name, string(component.id))]));
  const diagnostics: string[] = [];
  const nodes: GraphItem[] = [];
  const edges: GraphLink[] = [];
  const steps = records(object(raw.exploitation).steps);
  const availableSteps = new Set(steps.map(step => string(step.id)));
  for (const id of interruptedSteps) {
    if (!availableSteps.has(id)) diagnostics.push(`Proposed repair references unavailable step ${id}.`);
  }
  if (repairId && !repair) diagnostics.push('The selected repair is unavailable in this finding.');

  if (mode === 'procedure') {
    steps.forEach((step, ordinal) => {
      const localId = string(step.id, `step-${ordinal + 1}`);
      const componentIds = strings(step.component_ids);
      const group = componentIds[0] ?? 'unassigned';
      const repairIds = actions.filter(action => strings(action.breaks_steps).includes(localId)).map(action => string(action.id));
      nodes.push({
        id: graphId(finding.key, mode, localId), localId, ordinal, kind: mode,
        preview: nonemptyFields([{ label: 'Controlled input', value: step.controlled_input }, { label: 'Expected effect', value: step.expected_result }]),
        label: string(step.action, localId), caption: componentIds.map(id => componentNames.get(id) ?? id).join(' · '),
        status: string(step.evidence_status, 'unknown'), group,
        groupLabel: componentNames.get(group) ?? 'Component not recorded',
        highlighted: interruptedSteps.has(localId), repairIds, evidence: refs(step), raw: step,
        details: nonemptyFields([
          { label: 'Action', value: step.action }, { label: 'Controlled input', value: step.controlled_input },
          { label: 'Why it works', value: step.why_it_works }, { label: 'Expected effect', value: step.expected_result },
          { label: 'Observed effect', value: step.observed_result ?? 'No observation recorded' },
          { label: 'Evidence status', value: step.evidence_status ?? 'Unknown' },
          { label: 'Components', value: componentIds }, { label: 'Composition primitives', value: step.primitive_ids },
          { label: 'Missing prerequisite', value: step.missing_fact ?? step.missing_prerequisite },
          { label: 'Next action', value: step.next_action }, { label: 'Examples', value: step.example_ids },
        ]),
      });
    });
  } else if (mode === 'trace') {
    records(raw.trace).forEach((trace, ordinal) => {
      const localId = `trace-${ordinal + 1}`;
      const file = string(trace.file);
      const repository = file.includes('/') ? file.split('/')[0] : 'Source references';
      nodes.push({
        id: graphId(finding.key, mode, localId), localId, ordinal, kind: mode,
        preview: nonemptyFields([{ label: 'Source explanation', value: trace.description }]),
        label: string(trace.scope, shortPath(file) || localId), caption: locationReference(trace),
        status: string(trace.kind, 'assessed_trace'), group: repository, groupLabel: repository,
        highlighted: repairLocations.has(locationReference(trace)), repairIds: [],
        evidence: [...refs(trace), ...(file ? [locationReference(trace)] : [])], raw: trace,
        details: nonemptyFields([
          { label: 'Recorded explanation', value: trace.description }, { label: 'Source location', value: locationReference(trace) },
          { label: 'Symbol or scope', value: trace.scope }, { label: 'Trace role', value: trace.kind },
          { label: 'Interpretation', value: 'Ordered assessed trace; this is not a complete application call graph.' },
        ]),
      });
    });
  } else {
    const primitives = records(raw.primitive_steps);
    primitives.forEach((primitive, ordinal) => {
      const localId = string(primitive.primitive_id, string(primitive.id, `primitive-${ordinal + 1}`));
      const stepComponents = steps.filter(step => strings(step.primitive_ids).includes(localId)).flatMap(step => strings(step.component_ids));
      const group = stepComponents[0] ?? 'primitives';
      const output = outputCapabilityLabel(primitive.output_capability);
      nodes.push({
        id: graphId(finding.key, mode, localId), localId, ordinal, kind: mode,
        preview: nonemptyFields([{ label: 'Input capability', value: primitive.input_capability }, { label: 'Output capability', value: output }]),
        label: output, caption: string(primitive.boundary_crossed),
        status: 'recorded_primitive', group, groupLabel: componentNames.get(group) ?? 'Recorded capabilities',
        highlighted: false, repairIds: [], evidence: refs(primitive), raw: primitive,
        details: nonemptyFields([
          { label: 'Input capability', value: primitive.input_capability },
          { label: 'Output capability', value: output },
          { label: 'Boundary crossed', value: primitive.boundary_crossed },
        ]),
      });
    });
    const ids = new Set(nodes.map(node => node.localId));
    records(raw.transitions).forEach((transition, ordinal) => {
      const producer = string(transition.producer_id);
      const consumer = string(transition.consumer_id);
      if (!ids.has(producer) || !ids.has(consumer)) {
        diagnostics.push(`Transition ${ordinal + 1} has an unavailable primitive; no substitute edge was drawn.`);
        return;
      }
      const resolution = object(transition.resolution);
      const obligations = object(transition.obligations);
      const status = string(resolution.outcome, 'unknown');
      const obligationEntries = Object.values(obligations).map(object);
      const openObligations = obligationEntries.filter(entry => string(entry.outcome) !== 'established');
      edges.push({
        kind: 'transition',
        summary: obligationEntries.length ? `${obligationEntries.length} recorded ${obligationEntries.length === 1 ? 'obligation' : 'obligations'} · ${openObligations.length} not established` : 'No obligations recorded',
        id: graphId(finding.key, 'transition', String(ordinal)),
        source: graphId(finding.key, mode, producer), target: graphId(finding.key, mode, consumer),
        label: humanize(status), status,
        evidence: [...refs(transition), ...refs(resolution), ...Object.values(obligations).flatMap(value => refs(object(value)))],
        details: nonemptyFields([
          { label: 'Producer', value: producer }, { label: 'Consumer', value: consumer },
          { label: 'Resolution', value: resolution },
          ...Object.entries(obligations).map(([label, value]) => ({ label: humanize(label), value })),
        ]),
      });
    });
  }
  if (mode !== 'composition') {
    for (let ordinal = 1; ordinal < nodes.length; ordinal++) {
      edges.push({
        kind: 'sequence',
        id: graphId(finding.key, `${mode}-sequence`, String(ordinal)), source: nodes[ordinal - 1].id, target: nodes[ordinal].id,
        label: mode === 'procedure' ? 'Next action' : 'Next trace entry', status: 'recorded_sequence', evidence: [],
        details: [{ label: 'Meaning', value: mode === 'procedure' ? 'Next action in the recorded procedure.' : 'Next location in the recorded assessed trace; not an inferred call edge.' }],
      });
    }
  }
  const groups = new Map<string, { id: string; label: string; count: number }>();
  nodes.forEach(node => {
    const group = groups.get(node.group) ?? { id: node.group, label: node.groupLabel, count: 0 };
    group.count++; groups.set(node.group, group);
  });
  return { nodes, edges, diagnostics, groups: [...groups.values()] };
}

/** Collapse only visual groups; the original projection remains the inspector/list authority. */
export function collapseProjection(projection: Projection, collapsed: Set<string>): Projection {
  const nodes: GraphItem[] = [];
  const replacement = new Map<string, string>();
  const created = new Set<string>();
  for (const node of projection.nodes) {
    if (!collapsed.has(node.group)) { nodes.push(node); continue; }
    const id = JSON.stringify(['collapsed', node.group, projection.nodes[0]?.id]);
    replacement.set(node.id, id);
    if (created.has(node.group)) continue;
    created.add(node.group);
    const members = projection.nodes.filter(item => item.group === node.group);
    nodes.push({ ...node, id, localId: node.group, label: node.groupLabel,
      caption: `${members.length} records · select to expand`, status: 'collapsed_group',
      highlighted: members.some(item => item.highlighted), hiddenCount: members.length, evidence: [],
      details: [{ label: 'Hidden records', value: members.map(item => item.localId) }],
    });
  }
  const edges = projection.edges.map(edge => ({ ...edge, source: replacement.get(edge.source) ?? edge.source, target: replacement.get(edge.target) ?? edge.target }))
    .filter(edge => edge.source !== edge.target);
  return { ...projection, nodes, edges };
}
