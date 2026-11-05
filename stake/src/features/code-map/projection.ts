import { canonicalJson, localEntityKey, qualifiedKey, type CodeLocation, type FindingRecord, type SourceLocation } from '../../domain/index';

export interface CodeFile {
  key: string;
  file: string;
  repository: string;
  runId: string;
  sourceView: string | null;
  scopeId: string | null;
  locations: CodeLocation[];
}
export type CodeRole = CodeLocation['roles'][number];
export interface CodeEvidence { reference: unknown; runId: string; label: string }
/** The origin of one association; roles never migrate to another finding. */
export interface CodeAssociation {
  findingKey: string;
  findingId: string;
  entityKey: string;
  entityId: string;
  role: CodeRole;
  label: string;
  explanation: string | null;
  evidence: CodeEvidence[];
}
export interface CodeGraphNode {
  id: string;
  kind: 'finding' | 'location' | 'repair';
  title: string;
  label: string;
  caption: string;
  runId: string;
  findingKeys: string[];
  findingId?: string;
  severity?: string;
  status?: string;
  line?: number | null;
  endLine?: number | null;
  roles: CodeRole[];
  associations: CodeAssociation[];
  evidence: CodeEvidence[];
  rationale?: string;
  steps?: Array<{ id: string; title: string | null }>;
  components?: Array<{ id: string; title: string | null }>;
}
export interface CodeGraphEdge {
  id: string;
  source: string;
  target: string;
  kind: 'citation' | 'repair' | 'repair_evidence';
  label: string;
  findingKey: string;
  findingId: string;
  associations: CodeAssociation[];
  evidence: CodeEvidence[];
}
export interface CodeFileGraph {
  file: CodeFile;
  nodes: CodeGraphNode[];
  edges: CodeGraphEdge[];
  diagnostics: string[];
}

const natural = new Intl.Collator('en', { numeric: true, sensitivity: 'base' });
const compare = (a: string, b: string) => natural.compare(a, b) || (a < b ? -1 : a > b ? 1 : 0);
const unique = <T,>(values: T[]): T[] => [...new Set(values)];
const positive = (value: unknown): number | null => typeof value === 'number' && Number.isInteger(value) && value > 0 ? value : null;
const text = (value: unknown) => typeof value === 'string' && value.length ? value : null;
const roleOrder: CodeRole[] = ['root_cause', 'repair', 'trace', 'component', 'citation'];
const severityOrder = ['critical', 'high', 'medium', 'low', 'info', 'unknown'];
export const codeRoleLabel = (role: CodeRole) => ({ root_cause: 'Root cause', repair: 'Repair location', trace: 'Assessed trace', component: 'Component location', citation: 'Source citation' })[role];
export function codeCoordinate(file: string, line: number | null, endLine: number | null): string {
  return file + (line === null ? '' : `:${line}${endLine !== null && endLine !== line ? `-${endLine}` : ''}`);
}
export function codeRangeLabel(line: number | null | undefined, endLine: number | null | undefined): string {
  return line == null ? 'File reference' : `Line ${line}${endLine != null && endLine !== line ? `–${endLine}` : ''}`;
}
export function uniqueCodeEvidence(evidence: CodeEvidence[]): CodeEvidence[] {
  return [...new Map(evidence.map(item => [canonicalJson([item.runId, item.reference]), item])).values()]
    .sort((a, b) => compare(canonicalJson([a.runId, a.reference]), canonicalJson([b.runId, b.reference])));
}
/** Open this coordinate, never an unrelated support reference on the same file. */
export function evidenceForCodeRange(node: CodeGraphNode, file: string): CodeEvidence | undefined {
  const coordinate = codeCoordinate(file, node.line ?? null, node.endLine ?? null);
  const exact = node.evidence.find(item => item.reference === coordinate);
  if (exact) return exact;
  if (node.line == null) return undefined;
  return node.evidence.find(item => {
    if (typeof item.reference !== 'string' || !item.reference.startsWith(`${file}:`)) return false;
    const selector = item.reference.slice(file.length + 1);
    if (!/^[1-9]\d*(?:-[1-9]\d*)?(?:,[1-9]\d*(?:-[1-9]\d*)?)*$/.test(selector)) return false;
    return selector.split(',').some(range => {
      const [start, end = start] = range.split('-').map(Number);
      return start === node.line && end === (node.endLine ?? node.line);
    });
  });
}
export function groupCodeLocations(locations: CodeLocation[]): CodeFile[] {
  const files = new Map<string, CodeFile>();
  for (const location of locations) {
    const key = JSON.stringify([location.runId, location.scopeId, location.sourceView, location.file]);
    const file = files.get(key) ?? { key, file: location.file, repository: location.repository ?? 'Repository not recorded',
      runId: location.runId, sourceView: location.sourceView, scopeId: location.scopeId, locations: [] };
    file.locations.push(location); files.set(key, file);
  }
  return [...files.values()].sort((a, b) => compare(a.repository, b.repository) || compare(a.file, b.file) || compare(a.key, b.key));
}

/** Same bounded source-coordinate grammar as the citation index. Artifact objects stay evidence. */
function sourceRanges(reference: unknown, finding: FindingRecord): SourceLocation[] {
  if (typeof reference !== 'string') return [];
  const match = /^([^:#]+):([1-9]\d*(?:-[1-9]\d*)?(?:,[1-9]\d*(?:-[1-9]\d*)?)*)$/.exec(reference);
  if (!match || match[1].startsWith('/') || match[1].split('/').includes('..')) return [];
  const explicitRepository = finding.repositories.some(repo => match[1].startsWith(`${repo}/`));
  const phases = ['report', 'sast', 'repo-context', 'tool-collection', 'campaign-planning', 'intrusion', 'gap-exploration', 'synthesis', 'final-verification', 'planning', 'investigation', 'baseline', 'handoff'];
  if (!explicitRepository && (finding.repositories.length !== 1 || phases.includes(match[1].split('/')[0]))) return [];
  return match[2].split(',').flatMap(selector => {
    const [start, end = start] = selector.split('-').map(Number);
    return end < start ? [] : [{ file: match[1], start_line: start, end_line: end }];
  });
}

/**
 * A provenance graph of this file's citations, not an application call graph.
 * Read each finding separately: the aggregate code index deliberately loses
 * the action/step owner of a role and cannot be used to infer these edges.
 */
export function projectCodeFile(file: CodeFile, input: readonly FindingRecord[]): CodeFileGraph {
  const nodes = new Map<string, CodeGraphNode>();
  const edges = new Map<string, CodeGraphEdge>();
  const diagnostics: string[] = [];
  const findings = [...new Map(input.filter(finding => finding.hasDossier && !finding.conflicted && finding.runId === file.runId && finding.scopeId === file.scopeId && finding.sourceView === file.sourceView).map(finding => [finding.key, finding])).values()]
    .sort((a, b) => severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity) || compare(a.id, b.id) || compare(a.key, b.key));
  for (const finding of findings) {
    const findingId = localEntityKey(finding.key, 'code-map', 'finding');
    const evidence = (references: unknown[], label: string): CodeEvidence[] => references.map(reference => ({ reference, runId: finding.runId, label }));
    const add = (location: SourceLocation, association: CodeAssociation, repair?: CodeGraphNode) => {
      if (location.file !== file.file) return;
      const line = positive(location.line) ?? positive(location.start_line);
      const endLine = positive(location.end_line) ?? line;
      if (line !== null && endLine !== null && endLine < line) return;
      // Unknown source attribution cannot establish that two finding records
      // observed the same source. Their coordinates remain separate nodes.
      const unknownOwner = file.scopeId === null || file.sourceView === null ? finding.key : null;
      const id = qualifiedKey('code-map-location', file.runId, file.scopeId, file.sourceView, unknownOwner, file.file, line, endLine);
      const current = nodes.get(id) ?? { id, kind: 'location', title: text(location.scope) ?? file.file.split('/').at(-1)!, label: codeRangeLabel(line, endLine), caption: file.file,
        runId: file.runId, line, endLine, roles: [], findingKeys: [], associations: [], evidence: [] };
      current.findingKeys = unique([...current.findingKeys, finding.key]);
      current.roles = unique([...current.roles, association.role]);
      current.associations.push(association);
      current.evidence = uniqueCodeEvidence([...current.evidence, ...association.evidence]);
      // Symbol names are supporting metadata, never an identity or a join key.
      if (text(location.scope)) current.title = text(location.scope)!;
      nodes.set(id, current);
      if (!nodes.has(findingId)) nodes.set(findingId, { id: findingId, kind: 'finding', title: finding.title, label: finding.id,
        caption: finding.cohort.replaceAll('_', ' '), runId: finding.runId, findingKeys: [finding.key], findingId: finding.id,
        severity: finding.severity, status: finding.cohort, roles: [], associations: [], evidence: evidence(finding.raw.source_refs ?? [], 'Contributing finding record') });
      const linkId = qualifiedKey('code-map-citation', finding.key, id);
      const link = edges.get(linkId) ?? { id: linkId, source: findingId, target: id, kind: 'citation', label: '', findingKey: finding.key, findingId: finding.id, associations: [], evidence: [] };
      link.associations.push(association); link.evidence = uniqueCodeEvidence([...link.evidence, ...association.evidence]);
      edges.set(linkId, link);
      nodes.get(findingId)!.associations.push(association);
      nodes.get(findingId)!.evidence = uniqueCodeEvidence([...nodes.get(findingId)!.evidence, ...association.evidence]);
      if (repair) {
        nodes.set(repair.id, repair);
        const repairLinkId = qualifiedKey('code-map-repair-location', repair.id, id);
        const repairLink = edges.get(repairLinkId) ?? { id: repairLinkId, source: id, target: repair.id, kind: association.role === 'repair' ? 'repair' : 'repair_evidence',
          label: '', findingKey: finding.key, findingId: finding.id, associations: [], evidence: [] };
        if (association.role === 'repair') repairLink.kind = 'repair';
        repairLink.associations.push(association); repairLink.evidence = uniqueCodeEvidence([...repairLink.evidence, ...association.evidence]);
        edges.set(repairLinkId, repairLink);
        repair.associations.push(association);
      }
    };
    const association = (role: CodeRole, entityKind: string, entityId: string, label: string, location?: SourceLocation, references: unknown[] = []): CodeAssociation => ({
      findingKey: finding.key, findingId: finding.id, entityKey: localEntityKey(finding.key, entityKind, entityId), entityId, role, label,
      explanation: text(location?.mechanism) ?? text(location?.description), evidence: evidence(references, label),
    });
    const direct = (location: SourceLocation, role: CodeRole, kind: string, id: string, label: string, references: unknown[] = [], repair?: CodeGraphNode) => {
      const coordinate = codeCoordinate(location.file, positive(location.line) ?? positive(location.start_line), positive(location.end_line) ?? positive(location.line) ?? positive(location.start_line));
      add(location, association(role, kind, id, label, location, [coordinate, ...references]), repair);
    };
    const citations = (references: unknown[], kind: string, id: string, label: string, repair?: CodeGraphNode) => {
      for (const reference of references) for (const location of sourceRanges(reference, finding)) add(location, association('citation', kind, id, label, location, [reference]), repair);
    };
    for (const [index, location] of (finding.raw.trace ?? []).entries()) direct(location, 'trace', 'trace', String(index), `Trace ${index + 1} · ${location.kind}`);
    for (const [index, location] of (finding.raw.root_causes ?? []).entries()) direct(location, 'root_cause', 'root-cause', String(index), `Root cause ${index + 1}`);
    for (const component of finding.raw.affected_components ?? []) {
      for (const location of component.locations ?? []) direct(location, 'component', 'component', component.id, `Component ${component.id} · ${component.name}`);
      citations(component.evidence_refs ?? [], 'component', component.id, `Component ${component.id} evidence`);
    }
    for (const step of finding.raw.exploitation?.steps ?? []) citations(step.evidence_refs ?? [], 'step', step.id, `Step ${step.id} · ${step.action}`);
    for (const example of finding.raw.technical_examples ?? []) citations(example.evidence_refs ?? [], 'example', example.id, `Example ${example.id} evidence`);
    citations(finding.raw.verification?.source_validation_refs ?? [], 'verification', 'source', 'Source verification citation');
    for (const action of finding.raw.remediation?.actions ?? []) {
      const repair: CodeGraphNode = { id: localEntityKey(finding.key, 'code-map-repair', action.id), kind: 'repair', title: action.change, label: action.id,
        caption: `${finding.id} · Proposed repair`, runId: finding.runId, findingKeys: [finding.key], findingId: finding.id,
        status: text(action.status) ?? 'proposed', roles: [], associations: [], evidence: evidence(action.evidence_refs ?? [], `Repair ${action.id} evidence`), rationale: action.rationale,
        steps: (action.breaks_steps ?? []).map(id => ({ id, title: finding.raw.exploitation?.steps.find(step => step.id === id)?.action ?? null })),
        components: (action.component_ids ?? []).map(id => ({ id, title: finding.components.find(component => component.id === id)?.name ?? null })),
      };
      for (const location of action.locations ?? []) direct(location, 'repair', 'repair', action.id, `Repair ${action.id} location`, action.evidence_refs, repair);
      citations(action.evidence_refs ?? [], 'repair', action.id, `Repair ${action.id} supporting citation`, repair);
      if (nodes.has(repair.id)) {
        for (const step of repair.steps ?? []) if (step.title === null) diagnostics.push(`${finding.id} / ${action.id}: interrupted step ${step.id} is not available in this finding.`);
        for (const component of repair.components ?? []) if (component.title === null) diagnostics.push(`${finding.id} / ${action.id}: component ${component.id} is not available in this finding.`);
      }
    }
  }
  const order = new Map(findings.map((finding, index) => [finding.key, index]));
  const associationOrder = (a: CodeAssociation, b: CodeAssociation) => compare(a.findingKey, b.findingKey) || roleOrder.indexOf(a.role) - roleOrder.indexOf(b.role) || compare(a.entityKey, b.entityKey) || compare(canonicalJson(a), canonicalJson(b));
  for (const node of nodes.values()) {
    node.roles.sort((a, b) => roleOrder.indexOf(a) - roleOrder.indexOf(b));
    node.findingKeys.sort(compare);
    node.associations.sort(associationOrder);
  }
  for (const edge of edges.values()) {
    edge.associations.sort(associationOrder);
    edge.label = edge.kind === 'repair' ? 'Proposed change here' : edge.kind === 'repair_evidence' ? 'Supporting citation' : unique(edge.associations.map(item => codeRoleLabel(item.role))).join(' · ');
  }
  const sortedNodes = [...nodes.values()].sort((a, b) => {
    if (a.kind !== b.kind) return ['finding', 'location', 'repair'].indexOf(a.kind) - ['finding', 'location', 'repair'].indexOf(b.kind);
    if (a.kind === 'location') return (a.line ?? 0) - (b.line ?? 0) || (a.endLine ?? 0) - (b.endLine ?? 0) || compare(a.id, b.id);
    return (order.get(a.findingKeys[0]) ?? 0) - (order.get(b.findingKeys[0]) ?? 0) || compare(a.label, b.label) || compare(a.id, b.id);
  });
  return { file, nodes: sortedNodes, edges: [...edges.values()].sort((a, b) => compare(a.id, b.id)), diagnostics: unique(diagnostics).sort(compare) };
}

/** Explicit range windows keep large files readable without silently losing citations. */
export function codeGraphWindow(graph: CodeFileGraph, requestedPage: number, size = 5): { nodes: CodeGraphNode[]; edges: CodeGraphEdge[]; page: number; pages: number; start: number; end: number; total: number } {
  const locations = graph.nodes.filter(node => node.kind === 'location');
  const pageSize = Number.isInteger(size) && size > 0 ? size : 5;
  const pages = Math.max(1, Math.ceil(locations.length / pageSize));
  const page = Math.min(pages - 1, Math.max(0, Number.isFinite(requestedPage) ? Math.floor(requestedPage) : 0));
  const visible = new Set(locations.slice(page * pageSize, (page + 1) * pageSize).map(node => node.id));
  const edges = graph.edges.filter(edge => visible.has(edge.source) || visible.has(edge.target));
  for (const edge of edges) { visible.add(edge.source); visible.add(edge.target); }
  return { nodes: graph.nodes.filter(node => visible.has(node.id)), edges, page, pages, start: locations.length ? page * pageSize + 1 : 0, end: Math.min(locations.length, (page + 1) * pageSize), total: locations.length };
}
