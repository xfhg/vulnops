import { qualifiedKey, type FindingRecord, type SourceLocation } from '../../domain';
import { projectFinding } from '../attack-explorer/projection';

export type OverviewMode = 'entrypoints' | 'composed';
export type EntrypointSort = 'shared' | 'priority' | 'route';
export type CompositionSort = 'priority' | 'id';
export interface EntrypointCitation {
  findingKey: string;
  componentId: string;
  componentName: string;
  recordedLabel: string;
  evidence: unknown[];
}
export interface EntrypointCluster {
  id: string;
  label: string;
  runId: string;
  scopeId: string | null;
  sourceView: string | null;
  repository: string | null;
  incompleteScope: boolean;
  findingKeys: string[];
  citations: EntrypointCitation[];
}
export interface EntrypointAssociation {
  id: string;
  entrypointId: string;
  findingKey: string;
}
export interface EntrypointIndex {
  clusters: EntrypointCluster[];
  associations: EntrypointAssociation[];
  unassigned: FindingRecord[];
  findings: FindingRecord[];
  chains: FindingRecord[];
}

/** Only outer whitespace is normalized; method, case, slash and parameters retain meaning. */
export const normalizeEntrypoint = (label: string): string => label.trim();
export const overviewFindingId = (findingKey: string): string => qualifiedKey('overview-finding', findingKey);
export const overviewChainId = (findingKey: string): string => qualifiedKey('overview-chain', findingKey);
export const overviewUnassignedId = qualifiedKey('overview-unassigned');

/** Match evidence-registry coordinates, including legacy start_line ranges. */
function sourceCoordinate(location: SourceLocation): string {
  const line = location.line ?? location.start_line;
  if (line === undefined) return location.file;
  const end = location.end_line;
  return `${location.file}:${line}${end !== undefined && end !== line ? `-${end}` : ''}`;
}

const cohortOrder: Record<FindingRecord['cohort'], number> = { confirmed: 0, needs_environment: 1, unconfirmed: 2, non_promoted: 3, rejected: 4 };
const severityOrder: Record<FindingRecord['severity'], number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4, unknown: 5 };
const natural = new Intl.Collator('en', { numeric: true, sensitivity: 'variant' });

/** A final exact-text tiebreak prevents equal numeric spellings from relying on input order. */
function compareText(a: string | null, b: string | null): number {
  if (a === b) return 0;
  if (a === null) return 1;
  if (b === null) return -1;
  return natural.compare(a, b) || (a < b ? -1 : 1);
}

/** Ordering is a reading aid; it never changes a finding's recorded disposition. */
export function compareFindings(a: FindingRecord, b: FindingRecord, sort: CompositionSort = 'priority'): number {
  return (sort === 'priority' ? cohortOrder[a.cohort] - cohortOrder[b.cohort] || severityOrder[a.severity] - severityOrder[b.severity] : 0)
    || compareText(a.id, b.id)
    || compareText(a.runId, b.runId)
    || compareText(a.scopeId, b.scopeId)
    || compareText(a.sourceView, b.sourceView)
    || compareText(a.key, b.key);
}

function compareClusterIdentity(a: EntrypointCluster, b: EntrypointCluster): number {
  return compareText(a.repository, b.repository)
    || compareText(a.label, b.label)
    || compareText(a.runId, b.runId)
    || compareText(a.scopeId, b.scopeId)
    || compareText(a.sourceView, b.sourceView)
    || compareText(a.id, b.id);
}

/** A graphable dossier is not required for a recorded chain to remain discoverable. */
export function hasRecordedComposition(finding: FindingRecord): boolean {
  return finding.kind === 'chain' || Boolean(finding.raw.primitive_steps?.length || finding.raw.transitions?.length);
}

export function buildEntrypointIndex(input: FindingRecord[], sort: EntrypointSort = 'shared', compositionSort: CompositionSort = 'priority'): EntrypointIndex {
  const findings = [...new Map(input.map(finding => [finding.key, finding])).values()].sort(compareFindings);
  const findingByKey = new Map(findings.map(finding => [finding.key, finding]));
  const compareFindingKeys = (a: string, b: string) => compareFindings(findingByKey.get(a)!, findingByKey.get(b)!);
  const clusters = new Map<string, EntrypointCluster>();
  const associationMap = new Map<string, EntrypointAssociation>();
  const assigned = new Set<string>();
  for (const finding of findings) {
    for (const component of finding.raw.affected_components ?? []) {
      const repository = typeof component.repository === 'string' && component.repository.trim() ? component.repository.trim() : null;
      const scopeId = finding.scopeId;
      const sourceView = finding.sourceView;
      const incompleteScope = !scopeId || !sourceView || !repository;
      // Unknown scope metadata cannot establish that two identically named routes coincide.
      const isolation = incompleteScope ? finding.key : null;
      for (const recordedLabel of component.entrypoints ?? []) {
        if (typeof recordedLabel !== 'string') continue;
        const label = normalizeEntrypoint(recordedLabel);
        if (!label) continue;
        const id = qualifiedKey('entrypoint', finding.runId, scopeId, sourceView, repository, label, isolation);
        let cluster = clusters.get(id);
        if (!cluster) {
          cluster = { id, label, runId: finding.runId, scopeId, sourceView, repository, incompleteScope, findingKeys: [], citations: [] };
          clusters.set(id, cluster);
        }
        if (!cluster.findingKeys.includes(finding.key)) cluster.findingKeys.push(finding.key);
        if (!cluster.citations.some(citation => citation.findingKey === finding.key && citation.componentId === component.id && citation.recordedLabel === recordedLabel)) {
          cluster.citations.push({ findingKey: finding.key, componentId: component.id, componentName: component.name,
            recordedLabel, evidence: [...(component.evidence_refs ?? []), ...(component.locations ?? []).map(sourceCoordinate)] });
        }
        const associationId = qualifiedKey('entrypoint-citation', id, finding.key);
        associationMap.set(associationId, { id: associationId, entrypointId: id, findingKey: finding.key });
        assigned.add(finding.key);
      }
    }
  }
  for (const cluster of clusters.values()) {
    cluster.findingKeys.sort(compareFindingKeys);
    cluster.citations.sort((a, b) => compareFindingKeys(a.findingKey, b.findingKey)
      || compareText(a.componentId, b.componentId)
      || compareText(a.recordedLabel, b.recordedLabel)
      || compareText(a.componentName, b.componentName));
  }
  const sortedClusters = [...clusters.values()].sort((a, b) => {
    const sharing = b.findingKeys.length - a.findingKeys.length;
    const priority = compareFindingKeys(a.findingKeys[0], b.findingKeys[0]);
    if (sort === 'route') return compareClusterIdentity(a, b);
    return (sort === 'shared' ? sharing || priority : priority || sharing) || compareClusterIdentity(a, b);
  });
  const clusterPosition = new Map(sortedClusters.map((cluster, index) => [cluster.id, index]));
  return {
    clusters: sortedClusters,
    associations: [...associationMap.values()].sort((a, b) => clusterPosition.get(a.entrypointId)! - clusterPosition.get(b.entrypointId)!
      || compareFindingKeys(a.findingKey, b.findingKey) || compareText(a.id, b.id)),
    unassigned: findings.filter(finding => !assigned.has(finding.key)), findings,
    chains: findings.filter(hasRecordedComposition).sort((a, b) => compareFindings(a, b, compositionSort)),
  };
}

export function chainForSelection(chains: FindingRecord[], selected: string): FindingRecord | undefined {
  try {
    const tuple: unknown = JSON.parse(selected);
    if (!Array.isArray(tuple)) return undefined;
    // Child primitive / transition selections share the existing explorer's qualified identity.
    if (tuple[0] === 'overview-chain' || tuple[0] === 'entity') return chains.find(finding => finding.key === tuple[1]);
  } catch { /* Missing or unavailable URL selections remain explicit in the interface. */ }
  return undefined;
}

export function compositionCounts(finding: FindingRecord) {
  const primitives = finding.raw.primitive_steps ?? [];
  const transitions = finding.raw.transitions ?? [];
  const unresolved = transitions.filter(transition => transition.resolution?.outcome !== 'established').length;
  return { primitives: primitives.length, transitions: transitions.length, unresolved };
}

/** Union of recorded per-finding graphs. There is deliberately no cross-finding edge rule. */
export function buildCompositionOverview(findings: FindingRecord[], sort: CompositionSort = 'priority') {
  const chains = findings.filter(hasRecordedComposition).sort((a, b) => compareFindings(a, b, sort)).map(finding => ({ finding, projection: projectFinding(finding, 'composition') }));
  return {
    chains,
    nodes: chains.flatMap(({ finding, projection }) => projection.nodes.map(node => ({ ...node, finding }))),
    edges: chains.flatMap(({ finding, projection }) => projection.edges.map(edge => ({ ...edge, finding }))),
    unavailable: chains.filter(({ projection }) => projection.nodes.length === 0).map(({ finding }) => finding),
  };
}
