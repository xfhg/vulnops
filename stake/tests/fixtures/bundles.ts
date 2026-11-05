import { mkdir, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import type { AdmittedBundle, JsonRecord, RawFinding } from '../../src/domain/types';

/** Synthetic evidence only. This module never imports scans or target source. */
export function makeFinding(overrides: Partial<RawFinding> = {}): RawFinding {
  const location = { file: 'storefront/src/orders.ts', line: 42, scope: 'approveOrder', mechanism: 'The reviewed operation omits an ownership decision.' };
  const references = ['storefront/src/orders.ts:42', 'sast/verified-findings.json:C-001'];
  return {
    id: 'F-001', title: 'A reusable approval session reaches another account’s order', severity: 'high', risk_score: 75,
    confidence: 'high', verdict: 'confirmed', status: 'verified', finding_kind: 'chain', origin: 'cross_evidence_discovery', category: 'authorization',
    attack_summary: 'A caller can transfer an unbound approval session and approve an order outside the permitted account.',
    impact: 'An order belonging to another synthetic account can be approved.', impact_limits: ['No deployed environment was exercised.'],
    intended_behavior: 'Only the authenticated owner or an explicitly authorized reviewer may approve the order.',
    conditions: ['A synthetic pending order exists.'],
    attacker: { perspective: 'Signed-in customer', starting_access: 'A normal customer session', boundary_crossed: 'Customer identity to another account’s order' },
    affected_components: [{ id: 'component-1', name: 'Storefront', repository: 'storefront', entrypoints: ['POST /orders/approve'], locations: [location], evidence_refs: references,
      service: { name: 'Order service', binding: 'established', limitation: 'Deployment routing is not established.', evidence_refs: references } }],
    root_causes: [location],
    trace: Array.from({ length: 8 }, (_, index) => ({ file: 'storefront/src/orders.ts', line: 20 + index * 3, scope: index === 7 ? 'commitApproval' : `approvalStage${index + 1}`, kind: index === 0 ? 'entrypoint' : index === 7 ? 'sink' : 'propagation', description: `Recorded source transition ${index + 1}.` })),
    exploitation: { setup: ['Use synthetic accounts in an isolated test environment.'], rationale: 'The identity granted at the first step is consumed without an object ownership check.', steps: [
      { id: 'step-1', action: 'Present the unbound approval session.', controlled_input: 'Synthetic session selector', why_it_works: 'The reviewed session is not bound to the initiating account.', expected_result: 'A session identity is selected.', observed_result: null, evidence_status: 'source_established', component_ids: ['component-1'], primitive_ids: ['P-1'], example_ids: ['example-1'], evidence_refs: references, observation_refs: [] },
      { id: 'step-2', action: 'Request approval of another synthetic account’s order.', controlled_input: 'Synthetic order selector', why_it_works: 'The selected session is admitted without order ownership authorization.', expected_result: 'The foreign order approval is persisted.', observed_result: null, evidence_status: 'source_established', component_ids: ['component-1'], primitive_ids: ['P-2'], example_ids: ['example-1'], evidence_refs: references, observation_refs: [] },
    ] },
    technical_examples: [{ id: 'example-1', kind: 'request', content: 'POST /orders/approve\n{"order":"SYNTHETIC_ORDER"}', execution_status: 'not_executed', substitutions: [], evidence_refs: references, observation_refs: [] }],
    remediation: { actions: [{ id: 'action-1', change: 'Bind the session to its initiating account and authorize the selected order before approval.', rationale: 'Preserve identity and object scope at both boundaries.', breaks_steps: ['step-1', 'step-2'], component_ids: ['component-1'], example_ids: ['example-1'], locations: [location], evidence_refs: references }],
      verification_checks: [{ id: 'check-1', description: 'Exercise an unauthorized and an authorized synthetic order.', attack_expected: 'The unauthorized approval is rejected without mutation.', legitimate_expected: 'The authorized approval succeeds.', status: 'proposed', evidence_refs: [] }], containment: [], detection: [], limitations: ['The proposed checks have not run.'] },
    primitive_steps: [{ primitive_id: 'P-1', input_capability: 'Session selector', output_capability: 'Approval identity', boundary_crossed: 'Browser to account identity', evidence_refs: references }, { primitive_id: 'P-2', input_capability: 'Approval identity', output_capability: 'Order approval', boundary_crossed: 'Account to order scope', evidence_refs: references }],
    transitions: [{ producer_id: 'P-1', consumer_id: 'P-2', resolution: { outcome: 'established', reason: 'The recorded identity is consumed by the approval handler.' }, obligations: { actor_control: { outcome: 'established', reason: 'The caller chooses the selectors.', evidence_refs: references } } }],
    source_refs: [{ kind: 'sast', artifact_ref: 'sast/verified-findings.json', source_id: 'C-001' }],
    independent_verification_ref: 'final-verification/results/F-001.json',
    verification: { level: 'source_verified', actor: 'synthetic-reviewer', model: 'synthetic-model', reproduction_ref: null, source_validation_refs: references },
    assessment_context: { assessment_id: 'scope-1', attempt_id: 'attempt-1' },
    ...overrides,
  };
}

export function makeMixedObservationFinding(): RawFinding {
  const finding = makeFinding({ id: 'F-004', title: 'A contained observation supports only the first approval step' });
  finding.exploitation!.steps[0] = { ...finding.exploitation!.steps[0]!, evidence_status: 'observed_contained', observed_result: 'A synthetic fixture selected the supplied session identity.', observation_refs: ['sast/experiments/fixture/result.json'] };
  finding.technical_examples![0] = { ...finding.technical_examples![0]!, execution_status: 'observed_contained', observation_refs: ['sast/experiments/fixture/result.json'] };
  return finding;
}

export interface PublicationOptions {
  runId?: string;
  kind?: 'audit' | 'advantage';
  findings?: RawFinding[];
  baselineId?: string;
  legacy?: boolean;
  reportOverrides?: JsonRecord;
}
export function makePublication(options: PublicationOptions = {}): AdmittedBundle & { markdown: string } {
  const runId = options.runId ?? 'audit-fixture';
  const kind = options.kind ?? 'audit';
  const findings = options.findings ?? [makeFinding()];
  const repositories = [{ name: 'Storefront', path: 'storefront', remote_url: 'https://example.invalid/storefront', commit: 'a'.repeat(40) }];
  const assessment = { scopes: [{ assessment_id: 'scope-1', run_id: runId, attempt_id: 'attempt-1', source_view: 'base', started_at: '2026-01-10T10:00:00Z', repositories, limitations: [] }], record_scopes: Object.fromEntries(findings.map((finding) => [finding.id, 'scope-1'])), publication_attempt_id: 'attempt-1', retained: false, limitations: [] };
  const publication: JsonRecord = { execution_kind: kind, repository: 'Synthetic shop', repositories, model_routing: {}, producer_routes: {} };
  const report: JsonRecord = { schema_version: '2.0', run_id: runId, repository: 'Synthetic shop', repositories, date: '2026-01-11T10:00:00Z', findings,
    summary: { total: findings.length, confirmed: findings.filter((finding) => finding.verdict === 'confirmed').length }, assessment, publication,
    limitations: ['Synthetic source-established example; not dynamically tested.'], coverage: {}, investigation_accounting: { counts: { unresolved_paths: null }, unresolved_paths: [], truncated: { unresolved_paths: null } }, objective_assessments: [], non_promoted: [], rejections: [], unreviewed: [],
  };
  if (kind === 'advantage') {
    const baselineId = options.baselineId ?? 'audit-fixture';
    Object.assign(publication, { mode: 'standard', source: { source_run_id: baselineId }, baseline: { execution_id: baselineId, catalog_ref: 'baseline/catalog.json' } });
    Object.assign(report, { execution_kind: 'advantage', mode: 'standard', baseline: { execution_id: baselineId, artifact_ref: 'report/security-report.json' }, action_source: null,
      counts: { accepted: findings.length }, links: findings.map((finding) => ({ finding_id: finding.id, classification: 'new_root', baseline_ids: [], source_view: 'base' })), historical_findings: [], baseline_reconciliation: [], unresolved_applicability: [], ancillary: {}, cohort_counts: {}, unconfirmed: [], unconfirmed_dossiers: [] });
  }
  Object.assign(report, options.reportOverrides ?? {});
  if (options.legacy) delete report.publication;
  return { run_id: runId, execution_kind: kind, repository: 'Synthetic shop', repositories, assessment, report,
    final: { schema_version: '2.0', run_id: runId, findings: structuredClone(report.findings) }, markdown: '# Synthetic assessment\n\nExamples are inert and not executed.\n' };
}

export async function writeJson(root: string, relative: string, value: unknown): Promise<void> {
  const path = join(root, relative);
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, JSON.stringify(value));
}
export async function writeBundle(root: string, options: PublicationOptions = {}): Promise<{ root: string; report: JsonRecord; final: JsonRecord; findings: RawFinding[] }> {
  const bundle = makePublication(options);
  await writeJson(root, 'report/security-report.json', bundle.report);
  await writeFile(join(root, 'report/security-report.md'), bundle.markdown);
  await writeJson(root, 'final-verification/findings.json', bundle.final);
  if (options.legacy) await writeJson(root, options.kind === 'advantage' ? 'advantage-manifest.json' : 'run-manifest.json', { run_id: bundle.run_id, status: 'complete', repository: bundle.repository, repositories: bundle.repositories, mode: options.kind === 'advantage' ? 'standard' : undefined });
  await writeJson(root, 'sast/verified-findings.json', [{ id: 'C-001', explanation: 'Synthetic canonical support.' }]);
  await writeJson(root, 'final-verification/results/F-001.json', { finding_id: 'F-001', status: 'verified', explanation: 'Recorded synthetic review; not replayed.' });
  return { root, report: bundle.report, final: bundle.final!, findings: bundle.report.findings as RawFinding[] };
}

export async function writePair(parent: string) {
  const environment = makeFinding({ id: 'F-002', title: 'External order callback requires deployment evidence', verdict: 'needs_environment', status: 'needs_environment', severity: 'medium', finding_kind: 'code', primitive_steps: [], transitions: [], verification: { level: 'environment_required' } });
  environment.exploitation!.steps = environment.exploitation!.steps.map((step) => ({ ...step, evidence_status: 'environment_required', observed_result: null }));
  const corrected = makeFinding({ id: 'F-003', title: 'Reviewed order export scope is limited to one account', finding_kind: 'code', primitive_steps: [], transitions: [], severity: 'high' });
  const ordinary = await writeBundle(join(parent, 'ordinary run'), { findings: [makeFinding(), environment, corrected] });
  const advantage = await writeBundle(join(parent, 'advantage run'), { runId: 'advantage-fixture', kind: 'advantage', findings: [makeFinding({ id: 'F-060', title: 'Order approval reaches the fulfillment consumer', finding_kind: 'code', primitive_steps: [], transitions: [] })],
    reportOverrides: { links: [{ finding_id: 'F-060', classification: 'impact_expansion', baseline_ids: ['F-001'], source_view: 'base' }], historical_findings: ordinary.findings.map((finding) => ({ execution_id: 'audit-fixture', finding: structuredClone(finding), disposition: 'historical' })) } });
  return { ordinary, advantage };
}
