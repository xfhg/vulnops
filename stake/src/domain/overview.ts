import type { AssessmentSummary, Cohort, FindingSummary, Severity } from './types';
import { severityOrder } from './filters';

/** Counts in this model describe execution-qualified assessed records, not
 * unique vulnerabilities, completed fixes, deployment exposure or progress. */
export interface OverviewConfirmation {
  ordinary: FindingSummary[];
  /** Confirmed Advantage new_root, new_chain and impact_expansion outcomes. */
  additional: FindingSummary[];
  revalidations: FindingSummary[];
  corrections: FindingSummary[];
  /** Missing owner metadata or an unclassified Advantage outcome stays explicit. */
  other: FindingSummary[];
}
export interface OverviewSeverityBucket {
  severity: Severity;
  count: number;
  findings: FindingSummary[];
}
export interface OverviewRepositoryRow {
  /** Null is recorded attribution unavailable, not an invented repository. */
  repository: string | null;
  findingKeys: string[];
  findings: FindingSummary[];
  confirmed: number;
  highImpact: number;
  chains: number;
  /** Actions on associated findings, not actions proven to modify this repo.
   * A cross-repository finding contributes to each row: rows are nonadditive. */
  repairActionRecords: number;
}
export interface OverviewRepairGuidance {
  findings: FindingSummary[];
  withGuidance: number;
  /** Present dossiers with zero action records. */
  withoutGuidance: number;
  /** Missing dossiers cannot establish that repair guidance is absent. */
  unknownGuidance: number;
  actionRecords: number;
}
export interface OverviewEvidence {
  sourceVerified: FindingSummary[];
  dynamicallyVerified: FindingSummary[];
  /** Includes missing and unfamiliar recorded verification levels. */
  other: FindingSummary[];
}
export interface OverviewContext {
  loadedAssessmentCount: number;
  /** Distinct recorded inventory labels, not unique source/revision scopes. */
  inventoryRepositories: string[];
  inventoryRepositoryCount: number;
  /** Inventory entries without a usable path or name. */
  unknownInventoryRepositories: number;
  assessmentsWithoutRepositoryInventory: number;
}
export interface OverviewModel {
  /** Already scoped assessed records, deduplicated by key; no historical copies
   * or conflicted identities. All cohort arrays below are subsets of this set. */
  findings: FindingSummary[];
  confirmed: FindingSummary[];
  highImpact: FindingSummary[];
  /** Only explicit finding.kind === 'chain'; step count is not composition. */
  chains: FindingSummary[];
  needsEnvironment: FindingSummary[];
  /** Confirmed records, ordered by assessed severity then natural finding ID. */
  priority: FindingSummary[];
  confirmation: OverviewConfirmation;
  severity: OverviewSeverityBucket[];
  repositories: OverviewRepositoryRow[];
  repairGuidance: OverviewRepairGuidance;
  evidence: OverviewEvidence;
  context: OverviewContext;
}

const natural = new Intl.Collator('en', { numeric: true, sensitivity: 'variant' });
const cohorts: Record<Cohort, number> = { confirmed: 0, needs_environment: 1, unconfirmed: 2, non_promoted: 3, rejected: 4 };
const severities: Severity[] = ['critical', 'high', 'medium', 'low', 'info', 'unknown'];
function compareText(a: string | null, b: string | null): number {
  if (a === b) return 0;
  if (a === null) return 1;
  if (b === null) return -1;
  return natural.compare(a, b) || (a < b ? -1 : 1);
}
function comparePriority(a: FindingSummary, b: FindingSummary): number {
  return severityOrder[a.severity] - severityOrder[b.severity]
    || compareText(a.id, b.id) || compareText(a.runId, b.runId)
    || compareText(a.scopeId, b.scopeId) || compareText(a.sourceView, b.sourceView)
    || compareText(a.key, b.key);
}
const isHighImpact = (finding: FindingSummary): boolean => finding.severity === 'critical' || finding.severity === 'high';
const text = (value: unknown): value is string => typeof value === 'string' && value.trim().length > 0;

/** Pure summary projection. The caller supplies findings already filtered to
 * the selected assessment/repository. Assessment-wide counts never replace
 * this scoped set. Assessment metadata provides ownership and inventory only;
 * historical identity merging remains the publication normalizer's job. */
export function buildOverviewModel(assessments: AssessmentSummary[], scopedFindings: FindingSummary[]): OverviewModel {
  const owners = new Map(assessments.map(assessment => [assessment.id, assessment]));
  const conflictedKeys = new Set(scopedFindings.filter(finding => finding.conflicted).map(finding => finding.key));
  const assessed = scopedFindings.filter(finding => finding.origin === 'assessed' && !conflictedKeys.has(finding.key));
  const findings = [...new Map(assessed.map(finding => [finding.key, finding])).values()]
    .sort((a, b) => cohorts[a.cohort] - cohorts[b.cohort] || comparePriority(a, b));
  const confirmed = findings.filter(finding => finding.cohort === 'confirmed');
  const highImpact = confirmed.filter(isHighImpact);
  const chains = confirmed.filter(finding => finding.kind === 'chain');
  const confirmation: OverviewConfirmation = { ordinary: [], additional: [], revalidations: [], corrections: [], other: [] };
  for (const finding of confirmed) {
    const owner = owners.get(finding.runId);
    if (owner?.kind === 'audit') confirmation.ordinary.push(finding);
    else if (owner?.kind !== 'advantage') confirmation.other.push(finding);
    else if (['new_root', 'new_chain', 'impact_expansion'].includes(finding.classification ?? '')) confirmation.additional.push(finding);
    else if (finding.classification === 'baseline_revalidation') confirmation.revalidations.push(finding);
    else if (finding.classification === 'baseline_correction') confirmation.corrections.push(finding);
    else confirmation.other.push(finding);
  }

  const associations = new Map<string | null, FindingSummary[]>();
  for (const finding of confirmed) {
    const repositories: Array<string | null> = [...new Set(finding.repositories.filter(text))];
    if (!repositories.length) repositories.push(null);
    for (const repository of repositories) associations.set(repository, [...(associations.get(repository) ?? []), finding]);
  }
  const repositories: OverviewRepositoryRow[] = [...associations].map(([repository, rows]) => ({
    repository, findings: rows, findingKeys: rows.map(finding => finding.key), confirmed: rows.length,
    highImpact: rows.filter(isHighImpact).length, chains: rows.filter(finding => finding.kind === 'chain').length,
    repairActionRecords: rows.reduce((total, finding) => total + finding.repairCount, 0),
  })).sort((a, b) => b.highImpact - a.highImpact || b.confirmed - a.confirmed || compareText(a.repository, b.repository));

  const withGuidance = confirmed.filter(finding => finding.repairCount > 0);
  const inventory = new Set<string>();
  let unknownInventoryRepositories = 0, assessmentsWithoutRepositoryInventory = 0;
  for (const assessment of owners.values()) {
    if (!assessment.repositories.length) assessmentsWithoutRepositoryInventory++;
    for (const repository of assessment.repositories) {
      const label = text(repository.path) ? repository.path : text(repository.name) ? repository.name : null;
      if (label === null) unknownInventoryRepositories++;
      else inventory.add(label);
    }
  }
  const inventoryRepositories = [...inventory].sort(compareText);
  return {
    findings, confirmed, highImpact, chains, needsEnvironment: findings.filter(finding => finding.cohort === 'needs_environment'),
    priority: [...confirmed], confirmation,
    severity: severities.map(severity => {
      const rows = confirmed.filter(finding => finding.severity === severity);
      return { severity, count: rows.length, findings: rows };
    }),
    repositories,
    repairGuidance: { findings: withGuidance, withGuidance: withGuidance.length,
      withoutGuidance: confirmed.filter(finding => finding.hasDossier && finding.repairCount === 0).length,
      unknownGuidance: confirmed.filter(finding => !finding.hasDossier && finding.repairCount === 0).length,
      actionRecords: confirmed.reduce((total, finding) => total + finding.repairCount, 0) },
    evidence: { sourceVerified: confirmed.filter(finding => finding.verificationLevel === 'source_verified'),
      dynamicallyVerified: confirmed.filter(finding => finding.verificationLevel === 'dynamic_verified'),
      other: confirmed.filter(finding => !['source_verified', 'dynamic_verified'].includes(finding.verificationLevel ?? '')) },
    context: { loadedAssessmentCount: owners.size, inventoryRepositories, inventoryRepositoryCount: inventoryRepositories.length,
      unknownInventoryRepositories, assessmentsWithoutRepositoryInventory },
  };
}
