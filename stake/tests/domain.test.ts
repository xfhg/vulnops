import { describe, expect, it } from 'vitest';
import { buildCodeIndex, canonicalJson, filterFindings, findingKey, localEntityKey, normalizeWorkspace, summarizeWorkspace, type AdmittedBundle, type JsonRecord, type RawFinding } from '../src/domain';

function finding(id = 'F-001', overrides: Partial<RawFinding> = {}): RawFinding {
  return { id, title: `Object authorization ${id}`, severity: 'high', verdict: 'confirmed', status: 'verified', finding_kind: 'code', impact: 'Another account can be read.',
    attack_summary: 'An account selector reaches an owner-unbound query.', assessment_context: { assessment_id: 'scope-one', attempt_id: 'attempt-one' },
    affected_components: [{ id: 'component-1', name: 'Account API', repository: 'api', entrypoints: ['/accounts'], locations: [{ file: 'api/accounts.ts', line: 10, scope: 'readAccount', mechanism: 'Owner check is missing.' }] }],
    root_causes: [{ file: 'api/accounts.ts', line: 10, scope: 'readAccount', mechanism: 'Owner check is missing.' }],
    trace: [{ kind: 'entrypoint', file: 'api/accounts.ts', line: 10, scope: 'readAccount', description: 'Caller supplies an account.' }, { kind: 'sink', file: 'api/store.ts', line: 20, scope: 'lookup', description: 'Account selected without owner predicate.' }],
    exploitation: { setup: ['Use a synthetic account.'], steps: [{ id: 'step-1', action: 'Select another synthetic account.', component_ids: ['component-1'], controlled_input: 'Account ID', expected_result: 'The selected account is returned.', observed_result: null, evidence_status: 'source_established' }] },
    technical_examples: [{ id: 'example-1', kind: 'request', content: 'GET /accounts/<synthetic-id>', execution_status: 'not_executed', substitutions: [] }],
    remediation: { actions: [{ id: 'action-1', change: 'Bind the query to the authenticated owner.', breaks_steps: ['step-1'], component_ids: ['component-1'], locations: [{ file: 'api/accounts.ts', line: 10, scope: 'readAccount' }] }], verification_checks: [{ id: 'check-1', status: 'proposed', attack_expected: 'Other owners denied.', legitimate_expected: 'Own account remains readable.' }] },
    verification: { level: 'source_verified' }, primitive_steps: [], transitions: [], ...overrides };
}
function bundle(id = 'audit-one', rows = [finding()], kind: 'audit' | 'advantage' = 'audit'): AdmittedBundle {
  const report: JsonRecord = { schema_version: '2.0', run_id: id, findings: rows, summary: {}, unreviewed: [], non_promoted: [], rejections: [],
    publication: { execution_kind: kind, repository: 'Application', repositories: [{ name: 'api', path: 'api', commit: 'assessed-revision' }] },
    assessment: { record_scopes: Object.fromEntries(rows.map(row => [row.id!, 'scope-one'])), scopes: [{ assessment_id: 'scope-one', run_id: id, source_view: 'base', started_at: '2025-01-01T00:00:00Z', repositories: [{ name: 'api', path: 'api', commit: 'assessed-revision' }], limitations: [] }] } };
  if (kind === 'advantage') Object.assign(report, { execution_kind: kind, mode: 'deep', baseline: { execution_id: 'audit-one', artifact_ref: 'final-verification/findings.json' }, links: rows.map(row => ({ finding_id: row.id, classification: 'new_root', baseline_ids: [], source_view: 'base' })), historical_findings: [], unconfirmed: [], baseline_reconciliation: [], unresolved_applicability: [] });
  return { run_id: id, execution_kind: kind, inputPath: `/synthetic/${id}`, repository: 'Application', report, final: { run_id: id, findings: rows } };
}

describe('publication presentation adapters', () => {
  it('preserves corrected effective content and does not mutate imported values', () => {
    const corrected = finding('F-001', { severity: 'medium', title: 'Corrected reviewed scope', remediation: { actions: [{ id: 'action-1', change: 'Apply the independently corrected repair.' }] }, future_optional: { retained: true } });
    const source = bundle('audit-one', [corrected]);
    const before = JSON.stringify(source);
    const workspace = normalizeWorkspace([source]);
    expect(workspace.failures).toEqual([]);
    expect(workspace.findings[0].severity).toBe('medium');
    expect(workspace.findings[0].raw).toBe(corrected);
    expect(workspace.findings[0].raw.remediation?.actions[0].change).toContain('independently corrected');
    expect(workspace.findings[0].raw.future_optional).toEqual({ retained: true });
    expect(JSON.stringify(source)).toBe(before);
  });

  it('keeps unknown source scope separate from publication metadata', () => {
    const source = bundle();
    delete source.report.assessment;
    const workspace = normalizeWorkspace([source]);
    expect(workspace.findings[0].scope).toBeNull();
    expect(workspace.findings[0].sourceView).toBeNull();
    expect(workspace.assessments[0].scopes).toEqual([]);
    expect(workspace.assessments[0].publishedAt).toBeNull();
    expect(workspace.findings[0].scopeId).toBe('scope-one');
  });

  it('admits nullable service names without substituting a component or repository identity', () => {
    const raw = finding();
    raw.affected_components![0].service = { name: null, binding: 'unknown', limitation: 'Deployment service identity is not established.', evidence_refs: [] };
    const source = bundle('audit-one', [raw]);
    const before = JSON.stringify(source);
    const workspace = normalizeWorkspace([source]);
    expect(workspace.failures).toEqual([]);
    expect(workspace.findings[0].components[0]).toMatchObject({ name: 'Account API', repository: 'api', serviceName: null, serviceBinding: 'unknown' });
    expect(workspace.findings[0].raw).toBe(raw);
    expect(workspace.findings[0].raw.affected_components![0].service).toEqual({ name: null, binding: 'unknown', limitation: 'Deployment service identity is not established.', evidence_refs: [] });
    expect(JSON.stringify(source)).toBe(before);
  });

  it('retains nullable service names in historical and unconfirmed dossiers too', () => {
    const history = finding('F-history');
    history.affected_components![0].service = { name: null, binding: 'unknown', limitation: 'Deployment routing was not supplied.' };
    const candidate = structuredClone(history);
    candidate.id = 'F-candidate'; delete candidate.verdict;
    const advantage = bundle('advantage-one', [], 'advantage');
    advantage.report.historical_findings = [{ execution_id: 'audit-one', finding: history }];
    advantage.report.unconfirmed = [{ finding_id: candidate.id }];
    advantage.report.unconfirmed_dossiers = [candidate];
    const workspace = normalizeWorkspace([advantage]);
    expect(workspace.failures).toEqual([]);
    expect(workspace.assessments[0].diagnostics).toEqual([]);
    expect(workspace.findings).toHaveLength(2);
    expect(workspace.findings.every(row => row.components[0].serviceName === null)).toBe(true);
    expect(workspace.findings.find(row => row.id === history.id)).toMatchObject({ origin: 'historical', raw: history });
    expect(workspace.findings.find(row => row.id === candidate.id)).toMatchObject({ cohort: 'unconfirmed', verdict: null, raw: candidate });
  });

  it.each([['name', 123], ['name', { label: 'Do not coerce an object' }], ['binding', null], ['limitation', null]])('still rejects invalid service %s values', (field, value) => {
    const raw = finding();
    raw.affected_components![0].service = { name: null, binding: 'unknown', limitation: 'No deployed identity recorded.' };
    (raw.affected_components![0].service as JsonRecord)[field as string] = value;
    const workspace = normalizeWorkspace([bundle('audit-one', [raw])]);
    expect(workspace.assessments).toEqual([]);
    expect(workspace.failures[0].message).toContain(`component.service.${field}: expected text`);
  });

  it('rejects mismatched final authority and missing essential dossier structure per input', () => {
    const mismatch = bundle('mismatch');
    mismatch.final = { findings: [finding('F-other')] };
    const malformed = bundle('malformed');
    delete (malformed.report.findings as RawFinding[])[0].exploitation;
    const workspace = normalizeWorkspace([bundle('valid'), mismatch, malformed]);
    expect(workspace.assessments.map(row => row.id)).toEqual(['valid']);
    expect(workspace.failures).toHaveLength(2);
    expect(workspace.failures[0].message).toContain('disagree');
    expect(workspace.failures[1].message).toContain('exploitation.steps');
  });

  it('rejects malformed consumed optional arrays while retaining unknown extension fields', () => {
    const malformed = bundle();
    const row = (malformed.report.findings as RawFinding[])[0];
    (row.remediation!.actions[0] as JsonRecord).breaks_steps = 'step-1';
    const workspace = normalizeWorkspace([malformed]);
    expect(workspace.assessments).toEqual([]);
    expect(workspace.failures[0].message).toContain('breaks_steps');
    const extended = finding('F-extended', { producer_extension: { arbitrary: ['retained', 1] } });
    expect(normalizeWorkspace([bundle('extended', [extended])]).findings[0].raw.producer_extension).toEqual({ arbitrary: ['retained', 1] });
  });

  it('keeps identical IDs independent across runs and disambiguates tuple boundaries', () => {
    const workspace = normalizeWorkspace([bundle('one'), bundle('two')]);
    expect(workspace.findings).toHaveLength(2);
    expect(workspace.findings[0].key).not.toBe(workspace.findings[1].key);
    expect(localEntityKey(workspace.findings[0].key, 'step', 'step-1')).not.toBe(localEntityKey(workspace.findings[1].key, 'step', 'step-1'));
    expect(findingKey('a:b', 'c')).not.toBe(findingKey('a', 'b:c'));
  });

  it('deduplicates repeated roots and fails every distinct root claiming an execution', () => {
    const one = bundle();
    expect(normalizeWorkspace([one, one]).assessments).toHaveLength(1);
    const sameOwner = { ...one, inputPath: '/another/location' };
    const workspace = normalizeWorkspace([one, sameOwner, bundle('healthy')]);
    expect(workspace.assessments.map(row => row.id)).toEqual(['healthy']);
    expect(workspace.failures).toHaveLength(2);
    expect(workspace.failures.every(row => row.code === 'ambiguous_execution')).toBe(true);
  });

  it('reconciles sample-sized cohorts without inflating added outcomes or confirmed severity', () => {
    const ordinaryRows = Array.from({ length: 39 }, (_, i) => finding(`F-${i + 1}`, i >= 37 ? { verdict: 'needs_environment', status: 'needs_environment', severity: 'critical', verification: { level: 'environment_required' } } : { severity: i === 0 ? 'critical' : i < 16 ? 'high' : i < 36 ? 'medium' : 'low' }));
    const ordinary = bundle('audit-one', ordinaryRows);
    const advantage = bundle('advantage-one', Array.from({ length: 5 }, (_, i) => finding(`A-${i + 1}`)), 'advantage');
    const labels = ['new_root', 'new_root', 'impact_expansion', 'baseline_revalidation', 'baseline_revalidation'];
    advantage.report.links = (advantage.report.links as JsonRecord[]).map((link, i) => ({ ...link, classification: labels[i], baseline_ids: [`F-${i + 1}`] }));
    advantage.report.historical_findings = ordinaryRows.map(row => ({ execution_id: 'audit-one', assessment_scope: 'historical', finding: structuredClone(row) }));
    const workspace = normalizeWorkspace([ordinary, advantage]);
    expect(workspace.failures).toEqual([]);
    expect(workspace.findings).toHaveLength(44);
    expect(workspace.assessments[0].counts).toMatchObject({ total: 39, confirmed: 37, needsEnvironment: 2, severity: { critical: 1, high: 15, medium: 20, low: 1 } });
    expect(workspace.assessments[1].counts).toMatchObject({ confirmed: 5, addedOutcomes: 3, revalidations: 2, historical: 39, historicalConfirmed: 37, historicalNeedsEnvironment: 2 });
    expect(workspace.relations).toHaveLength(5);
    expect(workspace.relations.every(row => row.available)).toBe(true);
    expect(workspace.findings[0].historicalIn).toEqual(['advantage-one']);
  });

  it('retains Advantage-only history without borrowing its assessment scope or following filenames', () => {
    const advantage = bundle('advantage-one', [finding('A-1')], 'advantage');
    const history = finding('F-1', { assessment_context: { assessment_id: 'old-scope' } });
    advantage.report.historical_findings = [{ execution_id: 'audit-one', finding: history }];
    const workspace = normalizeWorkspace([advantage, bundle('unrelated', [finding('F-1', { title: history.title })])]);
    const historical = workspace.findings.find(row => row.runId === 'audit-one')!;
    expect(historical.origin).toBe('historical');
    expect(historical.scope).toBeNull();
    expect(historical.scopeId).toBe('old-scope');
    expect(workspace.assessments[0].baselineLoaded).toBe(false);
    expect(workspace.relations).toEqual([]);
  });

  it('flags conflicting historical copies rather than merging by title or date', () => {
    const ordinary = bundle();
    const advantage = bundle('advantage-one', [finding('A-1')], 'advantage');
    advantage.report.historical_findings = [{ execution_id: 'audit-one', finding: finding('F-001', { severity: 'low' }) }];
    advantage.report.links = [{ finding_id: 'A-1', classification: 'impact_expansion', baseline_ids: ['F-001'], source_view: 'base' }];
    const workspace = normalizeWorkspace([advantage, ordinary]);
    expect(workspace.conflicts).toHaveLength(1);
    expect(workspace.findings.find(row => row.runId === 'audit-one')?.conflicted).toBe(true);
    expect(workspace.relations[0].available).toBe(false);
    expect(workspace.assessments.find(row => row.id === 'audit-one')?.counts.confirmed).toBe(1);
  });

  it('preserves null accounting, bounded totals and unresolved applicability separately', () => {
    const advantage = bundle('advantage-one', [], 'advantage');
    advantage.report.counts = { unresolved_questions: null };
    advantage.report.ancillary = { question_outcomes: [], total: 400, omitted: 400, canonical_ref: 'investigation/results.json' };
    advantage.report.baseline_reconciliation = [{ baseline_id: 'F-001', status: 'reused' }];
    advantage.report.unresolved_applicability = [{ execution_id: 'audit-one', finding_id: 'F-001', reason: 'No complete later-source assessment.' }];
    delete advantage.report.unconfirmed;
    const assessment = normalizeWorkspace([advantage]).assessments[0];
    expect(assessment.counts.unresolvedQuestions).toBeNull();
    expect(assessment.counts.unconfirmed).toBeNull();
    expect(assessment.counts.confirmed).toBe(0);
    expect(assessment.accounting.ancillary).toEqual(advantage.report.ancillary);
    expect(assessment.baselineReconciliation[0].status).toBe('reused');
    expect(assessment.unresolvedApplicability).toHaveLength(1);
  });

  it('shows unresolved records as records, not invented accepted dossiers', () => {
    const source = bundle();
    source.report.non_promoted = [{ id: 'F-001', disposition: 'evidence_limited', reason: 'One route is unresolved.' }];
    source.report.unreviewed = [{ finding_id: 'F-002', reason: 'No independent review.' }];
    const workspace = normalizeWorkspace([source]);
    expect(new Set(workspace.findings.map(row => row.key)).size).toBe(3);
    const unresolved = filterFindings(workspace.findings, { cohort: 'unconfirmed' });
    expect(unresolved).toHaveLength(1);
    expect(unresolved[0].hasDossier).toBe(false);
    expect(unresolved[0].verificationLevel).toBeNull();
    expect(filterFindings(workspace.findings, { cohort: 'non_promoted' })).toHaveLength(1);
  });

  it('retains an unconfirmed full synthesis dossier without granting a final verdict', () => {
    const source = bundle('advantage-one', [], 'advantage');
    const candidate = finding('F-candidate');
    delete candidate.verdict;
    source.report.unconfirmed = [{ finding_id: 'F-candidate', outcome: 'locally_unresolved', reason: 'Review did not establish the route.' }];
    source.report.unconfirmed_dossiers = [candidate];
    const workspace = normalizeWorkspace([source]);
    expect(workspace.failures).toEqual([]);
    expect(workspace.findings[0]).toMatchObject({ hasDossier: true, cohort: 'unconfirmed', verdict: null });
    expect(workspace.assessments[0].counts.confirmed).toBe(0);
    expect(workspace.findings[0].raw).toBe(candidate);
  });

  it('combines filters without mutating totals and offers deterministic severity ordering', () => {
    const source = bundle('audit-one', [finding('F-low', { severity: 'low' }), finding('F-high'), finding('F-env', { severity: 'critical', verdict: 'needs_environment', status: 'needs_environment' })]);
    const workspace = normalizeWorkspace([source]);
    expect(filterFindings(workspace.findings).map(row => row.id)).toEqual(['F-high', 'F-low', 'F-env']);
    expect(filterFindings(workspace.findings, { assessment: 'audit-one', repository: 'api', severity: 'high', query: 'owner-unbound', kind: 'code', component: 'Account API' }).map(row => row.id)).toEqual(['F-high']);
    expect(filterFindings(workspace.findings, { query: 'absent query' })).toEqual([]);
    expect(filterFindings(workspace.findings, { severity: 'critical,high', disposition: 'confirmed' }).map(row => row.id)).toEqual(['F-high']);
    expect(filterFindings(workspace.findings, { severity: 'critical,high' }).map(row => row.id)).toEqual(['F-high', 'F-env']);
    expect(workspace.assessments[0].counts.confirmed).toBe(2);
  });

  it('keeps scope-qualified code locations and does not expose dossier bodies in summaries', () => {
    const one = bundle('audit-one');
    const two = bundle('audit-two');
    const workspace = normalizeWorkspace([one, two]);
    const index = buildCodeIndex(workspace.findings);
    expect(index.filter(row => row.file === 'api/accounts.ts')).toHaveLength(2);
    expect(index.find(row => row.file === 'api/accounts.ts')?.roles).toEqual(['trace', 'root_cause', 'component', 'repair']);
    const summary = summarizeWorkspace(workspace);
    expect(summary.findings[0]).not.toHaveProperty('raw');
    expect(summary.assessments[0]).not.toHaveProperty('report');
    expect(canonicalJson({ a: 1, b: [1, 2] })).toBe(canonicalJson({ b: [1, 2], a: 1 }));
    expect(canonicalJson([1, 2])).not.toBe(canonicalJson([2, 1]));
  });

  it('indexes literal source ranges without inventing source from artifact references', () => {
    const source = bundle('audit-one', [finding('F-1', { verification: { level: 'source_verified', source_validation_refs: ['api/policy.ts:11-14,20', 'sast/results.json:1', { execution_id: 'old-audit', artifact_ref: 'final-verification/findings.json#/findings/0' }] } })]);
    const index = buildCodeIndex(normalizeWorkspace([source]).findings);
    expect(index.filter(row => row.file === 'api/policy.ts').map(row => [row.line, row.endLine])).toEqual([[11, 14], [20, 20]]);
    expect(index.some(row => row.file.startsWith('sast/'))).toBe(false);
  });

  it('does not derive source confirmation from an unexecuted example', () => {
    const raw = finding('F-env', { verdict: 'needs_environment', status: 'needs_environment', verification: { level: 'environment_required' } });
    raw.exploitation!.steps[0].evidence_status = 'environment_required';
    const workspace = normalizeWorkspace([bundle('audit-one', [raw])]);
    expect(workspace.assessments[0].counts.sourceOnly).toBe(0);
    expect(workspace.findings[0].verificationLevel).toBe('environment_required');
    expect(workspace.findings[0].raw.exploitation?.steps[0].evidence_status).toBe('environment_required');
    expect(workspace.findings[0].raw.technical_examples?.[0].execution_status).toBe('not_executed');
  });
});
