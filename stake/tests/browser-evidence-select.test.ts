import { spawn } from 'node:child_process';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { EvidenceSelectorError } from '../src/data/references';
import { RECORD_COLLECTIONS, resolveEvidencePointer, selectEvidenceValue } from '../src/data/references-select';

interface Selection { reference: string; value: unknown }
type Outcome = { content: unknown } | { code: string };
function browserOutcome({ value, reference }: Selection): Outcome {
  try { return { content: selectEvidenceValue(value, reference) }; }
  catch (error) { if (error instanceof EvidenceSelectorError) return { code: error.code }; throw error; }
}

/** One read-only Python batch compares the browser port with the shipped authority. */
async function pythonOracle(cases: Selection[]): Promise<{ collections: Record<string, string[]>; outcomes: Outcome[] }> {
  const script = `import json,sys
sys.path.insert(0,sys.argv[1])
from publication_bridge import select_value
from evidence_refs import RECORD_COLLECTIONS
outcomes=[]
for case in json.load(sys.stdin):
 try: outcomes.append({"content":select_value(case["value"],case["reference"])})
 except Exception as error: outcomes.append({"code":getattr(error,"code","invalid_input")})
print(json.dumps({"collections":RECORD_COLLECTIONS,"outcomes":outcomes}))`;
  return new Promise((accept, reject) => {
    const child = spawn(process.env.STAKE_PYTHON ?? 'python3', ['-B', '-c', script, resolve('server')], { env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1', PYTHONNOUSERSITE: '1' }, stdio: ['pipe', 'pipe', 'pipe'] });
    let output = '';
    child.stdout.on('data', chunk => { output += String(chunk); });
    child.stderr.resume();
    child.on('error', reject);
    child.on('close', code => { if (code !== 0) reject(new Error('Read-only Python selector comparison failed.')); else { try { accept(JSON.parse(output)); } catch (error) { reject(error); } } });
    child.stdin.end(JSON.stringify(cases));
  });
}

describe('browser evidence selectors match the legacy reader', () => {
  it('matches every declared collection and rejects ID-like descriptive extensions', async () => {
    const cases: Selection[] = [];
    for (const [file, collections] of Object.entries(RECORD_COLLECTIONS)) {
      const prefix = file === 'intrusion-results.json' ? 'intrusion' : 'sast';
      for (const collection of collections) {
        const key = collection === 'results' ? 'campaign_id' : collection === 'scanner_triage' ? 'evidence_id' : collection === 'limitations' ? 'code' : 'id';
        cases.push({ reference: `${prefix}/${file}:record`, value: { [collection]: [{ [key]: 'record', text: `Declared ${collection}` }], extension: { id: 'record' } } });
      }
      cases.push({ reference: `${prefix}/${file}:descriptive`, value: { extension: { id: 'descriptive' } } });
    }
    const expected = await pythonOracle(cases);
    expect(RECORD_COLLECTIONS).toEqual(expected.collections);
    expect(cases.map(browserOutcome)).toEqual(expected.outcomes);
    for (let index = 0; index < cases.length; index++) {
      if (cases[index]!.reference.endsWith(':descriptive')) expect(expected.outcomes[index]).toEqual({ code: 'missing_record' });
      else expect(expected.outcomes[index]).toHaveProperty('content');
    }
  });

  it('preserves path overrides, nested ownership, exact IDs and ambiguity', async () => {
    const cases: Selection[] = [
      { reference: 'repo-context/repo-context.json:entry', value: { projects: [{ id: 'project', entry_points: [{ id: 'entry' }] }] } },
      { reference: 'repo-context/research/inputs.json:entry', value: { observations: [{ id: 'entry' }] } },
      { reference: 'sast/deepdive/work.json:cell', value: { cell_results: [{ cell_id: 'cell', id: 'wrong' }] } },
      { reference: 'sast/deepdive/work.json:amendment', value: { model_amendments: [{ entity: { id: 'amendment' } }] } },
      { reference: 'intrusion/intrusion-results.json:primitive', value: { results: [{ campaign_id: 'campaign', candidates: [{ id: 'primitive' }] }] } },
      { reference: 'intrusion/results/campaign.json:campaign', value: { campaign_id: 'campaign', candidates: [{ id: 'campaign' }] } },
      { reference: 'investigation/passes/pass-1/results/task.json:primitive', value: { campaign_id: 'primitive', candidates: [{ id: 'primitive' }] } },
      { reference: 'investigation/passes/pass-1/results/task.json:campaign', value: { campaign_id: 'campaign' } },
      { reference: 'investigation/passes/pass-1/deeper/results/task.json:primitive', value: { candidates: [{ id: 'primitive' }] } },
      { reference: 'gap-exploration/result.json:objective', value: { objectives: [{ id: 'objective' }] } },
      { reference: 'intrusion/waves/wave.json:primitive', value: { primitives: [{ id: 'primitive' }] } },
      { reference: 'report/hardening-notes.json:note', value: [{ id: 'note' }] },
      { reference: 'report/positive-patterns.json:pattern', value: { id: 'pattern' } },
      { reference: 'sast/verified-findings.json:C-1', value: [{ finding_id: 'C-1' }] },
      { reference: 'sast/verified-findings.json:C-1', value: [{ id: '', finding_id: 'C-1' }] },
      { reference: 'sast/verified-findings.json:C-1', value: [{ id: 'other', finding_id: 'C-1' }] },
      { reference: 'sast/verified-findings.json:C-1', value: [{ id: 'c-1' }] },
      { reference: 'sast/verified-findings.json:C-1', value: [{ id: 'C-1' }, { id: 'C-1' }] },
      { reference: 'final-verification/findings.json:C-1', value: { findings: [{ id: 'C-1' }], unreviewed: [{ id: 'C-1' }] } },
      { reference: 'sast/verified-findings.json:missing', value: [{ id: 'present', details: { id: 'missing' } }] },
    ];
    expect(cases.map(browserOutcome)).toEqual((await pythonOracle(cases)).outcomes);
    expect(browserOutcome(cases[5]!)).toEqual({ content: cases[5]!.value });
    expect(browserOutcome(cases[17]!)).toEqual({ code: 'ambiguous_record' });
    expect(browserOutcome(cases[19]!)).toEqual({ code: 'missing_record' });
  });

  it('matches strict JSON pointers including escapes, empty keys and array indices', async () => {
    const value = JSON.parse('{"records":[{"id":"first"},{"id":"second"}],"a/b":{"~key":42},"":false,"__proto__":{"record":"own key"},"key:with#punctuation":7}');
    const selectors = ['#/records/1', '#/a~1b/~0key', '#/', '#/__proto__/record', '#/key:with#punctuation', '#/records/01', '#/records/-', '#/records/2', '#/records/9999999999999999999999', '#/records/0/missing', '#/a~2b', '#/constructor', '#/records/0/id/0', '#', ':', ':id:extra', ':id#extra', ''];
    const cases = selectors.map(selector => ({ reference: `sast/example.json${selector}`, value }));
    expect(cases.map(browserOutcome)).toEqual((await pythonOracle(cases)).outcomes);
    expect(resolveEvidencePointer(value, '')).toBe(value);
    expect(() => resolveEvidencePointer(value, 'records')).toThrow(EvidenceSelectorError);
    expect(() => selectEvidenceValue(value, '../sast/example.json#record')).toThrow(EvidenceSelectorError);
  });
});
