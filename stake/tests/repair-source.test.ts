import { describe, expect, it } from 'vitest';
import { normalizeWorkspace, type TechnicalExample } from '../src/domain';
import { repairSourceExamples } from '../src/features/findings/repair-source';
import { makeFinding, makePublication } from './fixtures/bundles';

const file = 'storefront/src/orders.ts';
const example = (id: string, refs: TechnicalExample['evidence_refs'], kind = 'source'): TechnicalExample => ({ id, kind,
  content: `INERT_SOURCE_${id}`, execution_status: 'not_executed', evidence_refs: refs });

describe('repair source excerpt attribution', () => {
  it('requires an explicit action link and a same-file source citation covering the complete recorded location', () => {
    const raw = makeFinding();
    raw.technical_examples = [
      example('exact', [`${file}:42-47`]),
      example('covering', [`${file}:40-50`]),
      example('multi-range', [`${file}:1-3,41-49`]),
      example('partial-left', [`${file}:40-42`]),
      example('partial-right', [`${file}:46-50`]),
      example('unlinked', [`${file}:42-47`]),
      example('wrong-range', [`${file}:48-50`]),
      example('wrong-file', ['payments/src/orders.ts:42-47']),
      example('request', [`${file}:42-47`], 'request'),
      example('foreign-owner', [{ execution_id: 'another-run', artifact_ref: `${file}:42-47` }]),
      example('artifact', ['sast/verified-findings.json:C-001']),
      example('file-only', [file]),
      example('malformed', [`${file}:47-42`, `${file}:0-47`]),
    ];
    raw.remediation!.actions[0].example_ids = raw.technical_examples.filter(item => item.id !== 'unlinked').map(item => item.id);
    const finding = normalizeWorkspace([makePublication({ findings: [raw] })]).findings[0];
    const before = structuredClone(finding.raw);
    const matches = repairSourceExamples(finding, finding.raw.remediation!.actions[0], { file, start_line: 42, end_line: 47 });
    expect(matches.map(item => item.id)).toEqual(['exact', 'covering', 'multi-range']);
    expect(matches[0]).toBe(finding.raw.technical_examples![0]);
    expect(finding.raw).toEqual(before);
  });

  it('keeps reused action and example IDs local to the owning finding and does not invent file-only coordinates', () => {
    const ordinary = makeFinding(), advantage = makeFinding({ id: 'F-060' });
    ordinary.technical_examples = [example('example-1', [`${file}:42`])];
    advantage.technical_examples = [{ ...example('example-1', [`${file}:42`]), content: 'ADVANTAGE_SOURCE_ONLY' }];
    const { findings } = normalizeWorkspace([
      makePublication({ runId: 'ordinary', findings: [ordinary] }),
      makePublication({ runId: 'advantage', kind: 'advantage', findings: [advantage] }),
    ]);
    const first = findings.find(item => item.runId === 'ordinary')!, second = findings.find(item => item.runId === 'advantage')!;
    expect(repairSourceExamples(first, first.raw.remediation!.actions[0], { file, line: 42 }).map(item => item.content)).toEqual(['INERT_SOURCE_example-1']);
    expect(repairSourceExamples(second, second.raw.remediation!.actions[0], { file, line: 42 }).map(item => item.content)).toEqual(['ADVANTAGE_SOURCE_ONLY']);
    for (const location of [{ file }, { file, line: 0 }, { file, line: 47, end_line: 42 }, { file: '', line: 42 }]) {
      expect(repairSourceExamples(first, first.raw.remediation!.actions[0], location)).toEqual([]);
    }
  });
});
