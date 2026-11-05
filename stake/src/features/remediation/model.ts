import { canonicalJson, qualifiedKey, type FindingRecord, type JsonRecord, type RepairAction, type SourceLocation } from '../../domain';

export interface RepairEntry { key: string; finding: FindingRecord; action: RepairAction }
export interface RepairNode {
  id: string;
  kind: 'finding' | 'action' | 'location' | 'component' | 'step' | 'example' | 'check' | 'guidance';
  localId: string;
  title: string;
  caption: string;
  /** Literal recorded status, or not_recorded/unavailable. Never a computed fix status. */
  status: string;
  scope: 'action' | 'finding';
  raw: Record<string, unknown>;
  fields: Array<{ label: string; value: unknown }>;
  evidence: Array<{ reference: unknown; runId: string }>;
  unavailable?: boolean;
  file?: string;
  line?: number | null;
  endLine?: number | null;
  /** Original index in the selected action's locations array. */
  locationIndex?: number;
}
export interface RepairEdge {
  id: string;
  source: string;
  target: string;
  label: string;
  kind: 'target' | 'interruption' | 'context' | 'evidence';
  description: string;
}
export interface RepairGraph { entry: RepairEntry; nodes: RepairNode[]; edges: RepairEdge[]; diagnostics: string[] }

const cohorts = ['confirmed', 'needs_environment', 'unconfirmed', 'non_promoted', 'rejected'];
const severities = ['critical', 'high', 'medium', 'low', 'info', 'unknown'];
const natural = new Intl.Collator('en', { numeric: true, sensitivity: 'variant' });
const text = (value: unknown): string | null => typeof value === 'string' && value.length ? value : null;
const object = (value: unknown): JsonRecord => value !== null && typeof value === 'object' && !Array.isArray(value) ? value as JsonRecord : {};
const list = (value: unknown): unknown[] => Array.isArray(value) ? value : [];
const positive = (value: unknown): number | null => typeof value === 'number' && Number.isInteger(value) && value > 0 ? value : null;
const priority = (order: string[], value: string) => order.includes(value) ? order.indexOf(value) : order.length;
const compareText = (a: string | null, b: string | null): number => a === b ? 0 : a === null ? 1 : b === null ? -1 : natural.compare(a, b) || (a < b ? -1 : 1);
const status = (value: unknown): string => text(value) ?? 'not_recorded';
const field = (label: string, value: unknown) => ({ label, value });

/** Scope comes from the caller. Deduplicate exact qualified actions only; never merge similar repair text. */
export function buildRepairEntries(findings: readonly FindingRecord[]): RepairEntry[] {
  const entries = new Map<string, RepairEntry>();
  for (const finding of findings) {
    if (!finding.hasDossier || finding.conflicted) continue;
    for (const action of finding.raw.remediation?.actions ?? []) {
      const key = qualifiedKey('repair-entry', finding.key, finding.runId, finding.scopeId, finding.sourceView, action.id);
      if (!entries.has(key)) entries.set(key, { key, finding, action });
    }
  }
  return [...entries.values()].sort((a, b) =>
    priority(cohorts, a.finding.cohort) - priority(cohorts, b.finding.cohort)
    || priority(severities, a.finding.severity) - priority(severities, b.finding.severity)
    || compareText(a.finding.id, b.finding.id)
    || compareText(a.action.id, b.action.id)
    || compareText(a.finding.runId, b.finding.runId)
    || compareText(a.finding.scopeId, b.finding.scopeId)
    || compareText(a.finding.sourceView, b.finding.sourceView)
    || compareText(a.finding.key, b.finding.key)
    || compareText(a.key, b.key));
}

function sourceCoordinate(location: SourceLocation): { file: string; line: number | null; endLine: number | null; reference: string | null } {
  const file = text(location.file) ?? '';
  const line = positive(location.line) ?? positive(location.start_line);
  const endLine = positive(location.end_line) ?? line;
  const invalid = !file || ['line', 'start_line', 'end_line'].some(key => location[key] !== undefined && positive(location[key]) === null)
    || (line !== null && endLine !== null && endLine < line);
  return { file, line, endLine, reference: invalid ? null : file + (line === null ? '' : `:${line}${endLine !== null && endLine !== line ? `-${endLine}` : ''}`) };
}

/**
 * Project one recommendation using explicit action references only. Verification
 * checks and defensive guidance belong to the finding: the canonical dossier
 * schema does not provide action_ids for those records.
 */
export function projectRepair(entry: RepairEntry): RepairGraph {
  const { finding, action } = entry;
  const raw = finding.raw;
  const remediation = raw.remediation;
  const nodes: RepairNode[] = [];
  const edges: RepairEdge[] = [];
  const diagnostics: string[] = [];
  const id = (kind: RepairNode['kind'], ...parts: Array<string | number>) => qualifiedKey('repair-node', entry.key, kind, ...parts);
  const evidence = (...sources: unknown[][]): RepairNode['evidence'] => {
    const unique = new Map<string, { reference: unknown; runId: string }>();
    for (const reference of sources.flat()) {
      // Preserve typed execution ownership and the original object identity.
      const key = canonicalJson([finding.runId, reference]);
      if (!unique.has(key)) unique.set(key, { reference, runId: finding.runId });
    }
    return [...unique.values()];
  };
  const findingNode: RepairNode = {
    id: id('finding', finding.id), kind: 'finding', localId: finding.id, title: finding.title,
    caption: `${finding.runId} · ${finding.cohort.replaceAll('_', ' ')}`, status: status(finding.status), scope: 'finding', raw,
    fields: [field('Finding ID', finding.id), field('Owning execution', finding.runId), field('Assessment scope', finding.scopeId), field('Source view', finding.sourceView),
      field('Disposition', finding.cohort), field('Recorded verdict', finding.verdict), field('Recorded status', finding.status), field('Severity', finding.severity), field('Origin', finding.origin), field('Advantage classification', finding.classification),
      field('Intended behavior', raw.intended_behavior), field('Impact', raw.impact), field('Impact limits', raw.impact_limits), field('Conditions', raw.conditions),
      field('Root causes — finding context', raw.root_causes), field('Assessed trace — finding context', raw.trace)],
    evidence: evidence(list(raw.source_refs), list(raw.graph_receipt_refs), list(raw.verification?.source_validation_refs), raw.verification?.reproduction_ref ? [raw.verification.reproduction_ref] : [], text(raw.independent_verification_ref) ? [raw.independent_verification_ref] : []),
  };
  const actionNode: RepairNode = {
    id: id('action', action.id), kind: 'action', localId: action.id, title: action.change, caption: `${finding.id} · Proposed repair`,
    status: status(action.status), scope: 'action', raw: action,
    fields: [field('Change', action.change), field('Rationale', action.rationale), field('Recorded action status', action.status),
      field('Proposed locations', action.locations), field('Affected component IDs', action.component_ids), field('Interrupted step IDs', action.breaks_steps), field('Example IDs', action.example_ids)],
    evidence: evidence(list(action.evidence_refs)),
  };
  nodes.push(findingNode, actionNode);
  const link = (source: RepairNode, target: RepairNode, kind: RepairEdge['kind'], label: string, description: string) => {
    edges.push({ id: qualifiedKey('repair-edge', entry.key, source.id, target.id, kind), source: source.id, target: target.id, kind, label, description });
  };
  link(findingNode, actionNode, 'context', 'Recorded repair proposal', 'The owning finding records this action in remediation.actions. Its inclusion records a recommendation, not an applied or verified fix.');

  for (const [index, location] of (action.locations ?? []).entries()) {
    const coordinate = sourceCoordinate(location);
    const localId = `location-${index + 1}`;
    const node: RepairNode = {
      id: id('location', index, localId), kind: 'location', localId, locationIndex: index,
      title: coordinate.file || 'Source path unavailable', caption: coordinate.line === null ? 'File-level proposed location' : `Line ${coordinate.line}${coordinate.endLine !== null && coordinate.endLine !== coordinate.line ? `–${coordinate.endLine}` : ''} · Proposed location`,
      status: coordinate.reference === null ? 'unavailable' : status(location.status), scope: 'action', raw: location,
      file: coordinate.file, line: coordinate.line, endLine: coordinate.endLine, ...(coordinate.reference === null ? { unavailable: true } : {}),
      fields: [field('File', location.file), field('Line', location.line), field('Start line', location.start_line), field('End line', location.end_line), field('Symbol or scope', location.scope), field('Mechanism', location.mechanism), field('Description', location.description)],
      evidence: evidence(coordinate.reference === null ? [] : [coordinate.reference], list(location.evidence_refs)),
    };
    nodes.push(node);
    link(actionNode, node, 'target', 'Proposed change location', `This coordinate is explicitly listed in ${action.id}.locations.`);
    if (node.unavailable) diagnostics.push(`${action.id}: proposed location ${index + 1} has an unavailable or invalid source coordinate.`);
  }

  const missing = (kind: 'component' | 'step' | 'example', target: string, sourceField: string): RepairNode => {
    const node: RepairNode = { id: id(kind, target), kind, localId: target, title: `Unavailable ${kind}: ${target}`, caption: `${finding.id} · Unresolved reference`,
      status: 'unavailable', scope: 'action', unavailable: true, raw: { referenced_id: target, source_field: sourceField },
      fields: [field('Referenced ID', target), field('Source field', sourceField), field('Limitation', `No ${kind} with this ID is available in the owning finding.`)], evidence: [] };
    diagnostics.push(`${action.id}: referenced ${kind} ${target} is unavailable in finding ${finding.id}.`);
    return node;
  };
  for (const target of new Set(action.component_ids ?? [])) {
    const component = raw.affected_components?.find(item => item.id === target);
    const node: RepairNode = component ? { id: id('component', target), kind: 'component', localId: target, title: component.name,
      caption: component.repository ?? 'Repository not recorded', status: status(component.status), scope: 'action', raw: component,
      fields: [field('Component ID', target), field('Repository', component.repository), field('Entrypoints', component.entrypoints), field('Service binding', component.service), field('Component source context', component.locations)],
      evidence: evidence(list(component.evidence_refs), list(component.service?.evidence_refs)),
    } : missing('component', target, 'component_ids');
    nodes.push(node);
    link(actionNode, node, 'target', 'Explicit affected component', `The action names ${target} in component_ids.`);
  }
  for (const target of new Set(action.breaks_steps ?? [])) {
    const step = raw.exploitation?.steps.find(item => item.id === target);
    const node: RepairNode = step ? { id: id('step', target), kind: 'step', localId: target, title: step.action,
      caption: `${finding.id} · Recorded exploitation step`, status: status(step.evidence_status), scope: 'action', raw: step,
      fields: [field('Action', step.action), field('Controlled input', step.controlled_input), field('Why it works', step.why_it_works), field('Expected result', step.expected_result),
        field('Observed result', step.observed_result), field('Evidence status', step.evidence_status), field('Component IDs', step.component_ids), field('Primitive IDs', step.primitive_ids), field('Example IDs', step.example_ids)],
      evidence: evidence(list(step.evidence_refs), list(step.observation_refs)),
    } : missing('step', target, 'breaks_steps');
    nodes.push(node);
    link(actionNode, node, 'interruption', 'Proposed interruption', `The action explicitly names ${target} in breaks_steps. This is a proposed interruption, not a claim of verified remediation.`);
  }
  for (const target of new Set(action.example_ids ?? [])) {
    const example = raw.technical_examples?.find(item => item.id === target);
    const node: RepairNode = example ? { id: id('example', target), kind: 'example', localId: target,
      title: text(example.title) ?? `${target} · ${example.kind}`, caption: `${finding.id} · Linked technical example`, status: status(example.execution_status), scope: 'action', raw: example,
      fields: [field('Example kind', example.kind), field('Execution status', example.execution_status), field('Content', example.content), field('Substitutions', example.substitutions)],
      evidence: evidence(list(example.evidence_refs), list(example.observation_refs)),
    } : missing('example', target, 'example_ids');
    nodes.push(node);
    link(actionNode, node, 'evidence', 'Explicit linked example', `The action names ${target} in example_ids. Its recorded execution status remains independent of the recommendation.`);
  }

  // Checks have no action_ids in the canonical schema. Shared finding context
  // must not become an action-specific verification edge, even for one action.
  for (const [index, check] of (remediation?.verification_checks ?? []).entries()) {
    const node: RepairNode = { id: id('check', index, check.id), kind: 'check', localId: check.id, title: text(check.description) ?? check.id,
      caption: `${finding.id} · Finding-level verification check`, status: status(check.status), scope: 'finding', raw: check,
      fields: [field('Description', check.description), field('Attack expected', check.attack_expected), field('Legitimate expected', check.legitimate_expected), field('Recorded check status', check.status),
        field('Association', 'This check belongs to the finding; no action-specific check association is recorded.')],
      evidence: evidence(list(check.evidence_refs)),
    };
    nodes.push(node);
    link(findingNode, node, 'context', 'Finding-level check', 'The owning finding records this verification check. No action-specific check association is recorded.');
  }
  const guidanceFields = [
    ['containment', 'Containment'], ['detection', 'Detection'], ['limitations', 'Limitation'], ['unresolved_decisions', 'Unresolved decision'],
  ] as const;
  for (const [name, label] of guidanceFields) for (const [index, value] of list(remediation?.[name]).entries()) {
    const record = object(value);
    const localId = text(record.id) ?? `${name}-${index + 1}`;
    const node: RepairNode = { id: id('guidance', name, index, localId), kind: 'guidance', localId,
      title: text(value) ?? text(record.description) ?? text(record.decision) ?? `${label} ${index + 1}`,
      caption: `${finding.id} · Finding-level ${label.toLowerCase()}`, status: status(record.status), scope: 'finding', raw: value !== null && typeof value === 'object' && !Array.isArray(value) ? record : { value },
      fields: [field('Guidance type', name), field('Recorded guidance', value), field('Association', 'Finding-level context; no action-specific association is recorded.')],
      evidence: evidence(list(record.evidence_refs), list(record.observation_refs)),
    };
    nodes.push(node);
    link(findingNode, node, 'context', `Finding-level ${label.toLowerCase()}`, `The owning finding records this ${label.toLowerCase()} in remediation.${name}.`);
  }
  return { entry, nodes, edges, diagnostics };
}
