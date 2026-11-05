import type { FindingFilters, FindingSummary, Severity } from './types';

export const severityOrder: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4, unknown: 5 };
const selected = (value: string | undefined): value is string => !!value && value !== 'all';
const compareText = (a: string, b: string): number => a < b ? -1 : a > b ? 1 : 0;

/** Filters return a new array and never change assessment-wide totals. */
export function filterFindings<T extends FindingSummary>(findings: readonly T[], filters: FindingFilters = {}): T[] {
  const run = filters.assessment ?? filters.runId;
  const disposition = filters.disposition ?? filters.cohort;
  const historical = filters.origin === 'historical' || disposition === 'historical';
  const query = filters.query?.trim().toLocaleLowerCase();
  const severitySelection = selected(filters.severity) ? new Set(filters.severity.split(',').map(value => value.trim())) : null;
  const filtered = findings.filter(finding => {
    if (selected(run) && finding.runId !== run && !(historical && finding.historicalIn.includes(run))) return false;
    if (selected(filters.repository) && !finding.repositories.includes(filters.repository)) return false;
    if (selected(filters.component) && !finding.components.some(component => [component.id, component.key, component.name].includes(filters.component!))) return false;
    if (severitySelection && !severitySelection.has(finding.severity)) return false;
    if (selected(disposition) && disposition !== 'historical' && finding.cohort !== disposition && finding.verdict !== disposition) return false;
    if (historical && finding.origin !== 'historical' && finding.historicalIn.length === 0) return false;
    if (filters.origin === 'assessed' && finding.origin !== 'assessed') return false;
    if (selected(filters.kind) && finding.kind !== filters.kind) return false;
    if (selected(filters.classification) && finding.classification !== filters.classification) return false;
    if (query) {
      const haystack = [finding.id, finding.title, finding.runId, finding.attackSummary, finding.impact, ...finding.repositories, ...finding.components.flatMap(component => [component.name, ...component.entrypoints])].filter(Boolean).join(' ').toLocaleLowerCase();
      if (!haystack.includes(query)) return false;
    }
    return true;
  });
  const sign = filters.direction === 'desc' ? -1 : 1;
  return filtered.sort((a, b) => {
    let order: number;
    if (filters.sort === 'title') order = compareText(a.title, b.title);
    else if (filters.sort === 'id') order = compareText(a.id, b.id);
    else order = Number(b.cohort === 'confirmed') - Number(a.cohort === 'confirmed') || severityOrder[a.severity] - severityOrder[b.severity];
    return sign * order || compareText(a.runId, b.runId) || compareText(a.id, b.id) || compareText(a.key, b.key);
  });
}
