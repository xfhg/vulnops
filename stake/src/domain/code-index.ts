import type { CodeLocation, FindingRecord, SourceLocation } from './types';
import { localEntityKey, qualifiedKey } from './identity';

const unique = <T>(values: T[]): T[] => [...new Set(values)];
const positive = (value: unknown): number | null => typeof value === 'number' && Number.isInteger(value) && value > 0 ? value : null;
function repositoryFor(file: string, finding: FindingRecord): string | null {
  const matches = finding.repositories.filter(repo => file === repo || file.startsWith(`${repo}/`)).sort((a, b) => b.length - a.length);
  return matches[0] ?? (finding.repositories.length === 1 ? finding.repositories[0] : null);
}
/** Citations only: no target file access, inferred callers, or coverage denominator. */
export function buildCodeIndex(findings: readonly FindingRecord[]): CodeLocation[] {
  const index = new Map<string, CodeLocation>();
  for (const finding of findings) {
    if (!finding.hasDossier || finding.conflicted) continue;
    const add = (location: SourceLocation, role: CodeLocation['roles'][number], componentIds: string[] = []) => {
      if (typeof location.file !== 'string' || !location.file) return;
      const line = positive(location.line) ?? positive(location.start_line), endLine = positive(location.end_line) ?? line;
      const scope = typeof location.scope === 'string' ? location.scope : null;
      const key = qualifiedKey('location', finding.runId, finding.scopeId, finding.sourceView, location.file, line, endLine, scope);
      const current = index.get(key) ?? { key, runId: finding.runId, scopeId: finding.scopeId, sourceView: finding.sourceView, repository: repositoryFor(location.file, finding), file: location.file, line, endLine, scope, findingKeys: [], componentKeys: [], roles: [], explanations: [] };
      current.findingKeys = unique([...current.findingKeys, finding.key]);
      current.componentKeys = unique([...current.componentKeys, ...componentIds.map(id => localEntityKey(finding.key, 'component', id))]);
      current.roles = unique([...current.roles, role]);
      current.explanations = unique([...current.explanations, ...[location.description, location.mechanism].filter((value): value is string => typeof value === 'string' && !!value)]);
      index.set(key, current);
    };
    for (const trace of finding.raw.trace ?? []) add(trace, 'trace');
    for (const location of finding.raw.root_causes ?? []) add(location, 'root_cause');
    for (const component of finding.raw.affected_components ?? []) for (const location of component.locations ?? []) add(location, 'component', [component.id]);
    for (const action of finding.raw.remediation?.actions ?? []) for (const location of action.locations ?? []) add(location, 'repair', action.component_ids);
    const citation = (reference: unknown, componentIds: string[] = []) => {
      if (typeof reference !== 'string') return;
      const match = /^([^:#]+):([1-9]\d*(?:-[1-9]\d*)?(?:,[1-9]\d*(?:-[1-9]\d*)?)*)$/.exec(reference);
      if (!match || match[1].startsWith('/') || match[1].split('/').includes('..')) return;
      // A typed artifact reference is never a source coordinate. For string
      // coordinates retain only explicit repository prefixes, or a local path
      // in a single-repository namespace outside canonical evidence phases.
      const first = match[1].split('/')[0];
      const explicitRepository = finding.repositories.some(repo => match[1].startsWith(`${repo}/`));
      const evidencePhases = ['report', 'sast', 'repo-context', 'tool-collection', 'campaign-planning', 'intrusion', 'gap-exploration', 'synthesis', 'final-verification', 'planning', 'investigation', 'baseline', 'handoff'];
      if (!explicitRepository && (finding.repositories.length !== 1 || evidencePhases.includes(first))) return;
      for (const selector of match[2].split(',')) {
        const [start, end] = selector.split('-').map(Number);
        if (end !== undefined && end < start) continue;
        add({ file: match[1], start_line: start, end_line: end ?? start }, 'citation', componentIds);
      }
    };
    for (const reference of finding.raw.verification?.source_validation_refs ?? []) citation(reference);
    for (const step of finding.raw.exploitation?.steps ?? []) for (const reference of step.evidence_refs ?? []) citation(reference, step.component_ids);
    for (const component of finding.raw.affected_components ?? []) for (const reference of component.evidence_refs ?? []) citation(reference, [component.id]);
    for (const example of finding.raw.technical_examples ?? []) for (const reference of example.evidence_refs ?? []) citation(reference);
    for (const action of finding.raw.remediation?.actions ?? []) for (const reference of action.evidence_refs ?? []) citation(reference, action.component_ids);
  }
  return [...index.values()].sort((a, b) => a.runId.localeCompare(b.runId) || (a.repository ?? '').localeCompare(b.repository ?? '') || a.file.localeCompare(b.file) || (a.line ?? 0) - (b.line ?? 0));
}
