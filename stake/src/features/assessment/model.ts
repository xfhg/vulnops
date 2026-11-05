import type { AssessmentSummary, JsonRecord } from '../../domain/types';

export const record = (value: unknown): JsonRecord => value && typeof value === 'object' && !Array.isArray(value) ? value as JsonRecord : {};
export const rows = (value: unknown): unknown[] => Array.isArray(value) ? value : [];
export const text = (value: unknown): string | null => typeof value === 'string' && value.length > 0 ? value : null;
export const count = (value: unknown): number | null => typeof value === 'number' && Number.isFinite(value) && value >= 0 ? value : null;
export const countLabel = (value: number | null | undefined): string => value == null ? 'Unknown' : value.toLocaleString();
export const titleCase = (value: string): string => value.replaceAll('_', ' ').replace(/\b\w/g, letter => letter.toUpperCase());

export interface Cohort { key: string; title: string; description: string; items: unknown[]; total: number | null; omitted: number | null }
function collectionCount(source: JsonRecord, key: string): number | null {
  const counts = record(source.counts);
  // A declared unknown total must not become the displayed array's length.
  if (Object.hasOwn(counts, key)) return count(counts[key]);
  return Array.isArray(source[key]) ? source[key].length : null;
}
export function investigationCount(assessment: AssessmentSummary, key: string): number | null {
  return collectionCount(record(assessment.accounting.investigation_accounting), key);
}
export function cohortsFor(assessment: AssessmentSummary): Cohort[] {
  const investigation = record(assessment.accounting.investigation_accounting), truncated = record(investigation.truncated);
  const definitions = [
    ['unresolved_paths', 'Unresolved attack paths', 'Recorded paths with a remaining proof obligation.'],
    ['evidence_limited', 'Evidence-limited claims', 'Claims whose missing evidence is recorded explicitly.'],
    ['unscheduled_work', 'Unscheduled investigation', 'Recorded work not completed within the investigation.'],
    ['historical_planning_deferrals', 'Historical planning deferrals', 'Planning history, separate from current failures and confirmed findings.'],
  ];
  const result: Cohort[] = definitions.map(([key, title, description]) => ({ key: key!, title: title!, description: description!, items: rows(investigation[key!]), total: collectionCount(investigation, key!), omitted: count(truncated[key!]) }));
  result.push({ key: 'later-applicability', title: 'Later-source applicability', description: 'Original findings whose applicability to another source assessment remains open.', items: assessment.unresolvedApplicability, total: assessment.counts.unresolvedApplicability, omitted: null });
  for (const [key, title, description, total] of [
    ['unconfirmed', 'Unconfirmed findings', 'Recorded conclusions without a confirmed verdict.', assessment.counts.unconfirmed],
    ['non_promoted', 'Non-promoted claims', 'Claims retained with their original disposition and missing proof.', assessment.counts.nonPromoted],
  ] as const) result.push({ key, title, description, total, items: rows(assessment.accounting[key]), omitted: null });
  const ancillary = record(assessment.accounting.ancillary);
  if (Object.hasOwn(ancillary, 'question_outcomes')) result.push({ key: 'question-outcomes', title: 'Investigation question outcomes', description: 'Both resolved and unresolved outcomes; not a vulnerability count.', items: rows(ancillary.question_outcomes), total: Object.hasOwn(ancillary, 'total') ? count(ancillary.total) : rows(ancillary.question_outcomes).length, omitted: count(ancillary.omitted) });
  const objectives = rows(assessment.accounting.objective_assessments);
  if (objectives.length) result.push({ key: 'objectives', title: 'Attacker objectives', description: 'Recorded success conditions, outcomes and remaining obligations.', items: objectives, total: objectives.length, omitted: null });
  return result.filter(cohort => cohort.items.length || cohort.total !== null);
}
export function accountingTotals(assessment: AssessmentSummary): Array<[string, number | null]> {
  const investigation = record(assessment.accounting.investigation_accounting);
  const source = Object.hasOwn(investigation, 'counts') ? record(investigation.counts) : investigation;
  return Object.entries(source).filter((entry): entry is [string, number | null] => entry[1] === null || typeof entry[1] === 'number');
}
