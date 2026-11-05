import type { FindingRecord, RepairAction, SourceLocation, TechnicalExample } from '../../domain/types';

/** Only source excerpts explicitly linked to this action and citing this coordinate.
 * Artifact references, other owners and other ranges do not imply source content.
 */
export function repairSourceExamples(finding: FindingRecord, action: RepairAction, location: SourceLocation): TechnicalExample[] {
  const start = location.line ?? location.start_line, end = location.end_line ?? start;
  if (!location.file || !Number.isSafeInteger(start) || !Number.isSafeInteger(end) || start! < 1 || end! < start!) return [];
  const ids = new Set(action.example_ids ?? []);
  return (finding.raw.technical_examples ?? []).filter(example => ids.has(example.id) && example.kind === 'source' &&
    (example.evidence_refs ?? []).some(reference => {
      if (typeof reference !== 'string') return false;
      const match = /^([^:#]+):([1-9]\d*(?:-[1-9]\d*)?(?:,[1-9]\d*(?:-[1-9]\d*)?)*)$/.exec(reference);
      if (!match || match[1] !== location.file) return false;
      return match[2].split(',').some(range => {
        const [from, last] = range.split('-').map(Number), to = last ?? from;
        return Number.isSafeInteger(from) && Number.isSafeInteger(to) && to >= from && from <= start! && to >= end!;
      });
    }));
}
