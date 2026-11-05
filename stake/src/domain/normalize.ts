import type { AdmittedBundle, Assessment, AssessmentCounts, AssessmentScope, Classification, Cohort, Diagnostic, FindingRecord, FindingRelation, FindingSummary, IdentityConflict, ImportFailure, JsonRecord, RawFinding, RepositoryRecord, Severity, Workspace, WorkspaceSummary } from './types';
import { canonicalJson, findingKey, localEntityKey, qualifiedKey } from './identity';

const classifications = new Set<Classification>(['new_root', 'new_chain', 'impact_expansion', 'baseline_correction', 'baseline_revalidation']);
const severities: Severity[] = ['critical', 'high', 'medium', 'low', 'info', 'unknown'];
export const asRecord = (value: unknown): JsonRecord => value && typeof value === 'object' && !Array.isArray(value) ? value as JsonRecord : {};
export const asRecords = (value: unknown): JsonRecord[] => Array.isArray(value) ? value.filter(v => v && typeof v === 'object' && !Array.isArray(v)) as JsonRecord[] : [];
export const asString = (value: unknown): string | null => typeof value === 'string' && value.length > 0 ? value : null;
export const asStrings = (value: unknown): string[] => Array.isArray(value) ? value.filter((v): v is string => typeof v === 'string') : [];
const numberOrNull = (value: unknown): number | null => typeof value === 'number' && Number.isFinite(value) && value >= 0 ? value : null;
const unique = <T>(items: T[]): T[] => [...new Set(items)];
const hasOwn = (object: JsonRecord, name: string): boolean => Object.prototype.hasOwnProperty.call(object, name);
const collectionCount = (report: JsonRecord, name: string, fallback?: unknown): number | null => Array.isArray(report[name]) ? report[name].length : numberOrNull(fallback);

function validRecords(value: unknown, label: string): JsonRecord[] {
  if (!Array.isArray(value) || value.some(v => !v || typeof v !== 'object' || Array.isArray(v))) throw new Error(`${label}: expected a record array`);
  return value as JsonRecord[];
}
function uniqueIds(rows: JsonRecord[], field: string, label: string): void {
  const ids = new Set<string>();
  for (const row of rows) {
    const id = asString(row[field]);
    if (!id || ids.has(id)) throw new Error(`${label}: missing or duplicate ${field}`);
    ids.add(id);
  }
}
function optionalStrings(record: JsonRecord, names: string[], label: string): void {
  for (const name of names) if (hasOwn(record, name) && (!Array.isArray(record[name]) || (record[name] as unknown[]).some(value => typeof value !== 'string'))) throw new Error(`${label}.${name}: expected a string array`);
}
function optionalText(record: JsonRecord, names: string[], label: string, nullable = false): void {
  for (const name of names) if (hasOwn(record, name) && typeof record[name] !== 'string' && !(nullable && record[name] === null)) throw new Error(`${label}.${name}: expected text${nullable ? ' or null' : ''}`);
}
function optionalReferences(record: JsonRecord, names: string[], label: string): void {
  for (const name of names) if (hasOwn(record, name)) {
    if (!Array.isArray(record[name]) || (record[name] as unknown[]).some(value => typeof value !== 'string' && (!value || typeof value !== 'object' || Array.isArray(value)))) throw new Error(`${label}.${name}: expected reference array`);
  }
}
function locations(value: unknown, label: string): void {
  for (const location of validRecords(value, label)) {
    if (!asString(location.file)) throw new Error(`${label}: missing source path`);
    for (const key of ['line', 'start_line', 'end_line']) if (hasOwn(location, key) && (!Number.isInteger(location[key]) || Number(location[key]) < 1)) throw new Error(`${label}: invalid source line`);
    optionalText(location, ['scope', 'mechanism', 'description'], label);
  }
}
/** Validate consumed dossier structures, not a changing producer's entire schema. */
export function validateDossier(value: JsonRecord, label = 'finding', requiresVerdict = true): asserts value is RawFinding {
  for (const key of ['id', 'title', 'severity', 'status', 'finding_kind', 'impact', ...(requiresVerdict ? ['verdict'] : [])]) {
    if (!asString(value[key])) throw new Error(`${label}: missing or invalid ${key}`);
  }
  if (!['critical', 'high', 'medium', 'low', 'info', 'informational'].includes(String(value.severity))) throw new Error(`${label}: unsupported severity`);
  for (const key of ['trace', 'affected_components', 'root_causes', 'technical_examples']) validRecords(value[key], `${label}.${key}`);
  const steps = validRecords(asRecord(value.exploitation).steps, `${label}.exploitation.steps`);
  const actions = validRecords(asRecord(value.remediation).actions, `${label}.remediation.actions`);
  uniqueIds(steps, 'id', `${label}.exploitation.steps`);
  uniqueIds(actions, 'id', `${label}.remediation.actions`);
  uniqueIds(asRecords(value.affected_components), 'id', `${label}.affected_components`);
  uniqueIds(asRecords(value.technical_examples), 'id', `${label}.technical_examples`);
  optionalStrings(value, ['conditions', 'impact_limits'], label);
  optionalText(value, ['attack_summary', 'intended_behavior', 'category', 'origin'], label);
  optionalStrings(asRecord(value.exploitation), ['setup'], `${label}.exploitation`);
  optionalText(asRecord(value.exploitation), ['rationale'], `${label}.exploitation`);
  optionalReferences(value, ['source_refs', 'graph_receipt_refs'], label);
  if (hasOwn(value, 'verification') && (!value.verification || typeof value.verification !== 'object' || Array.isArray(value.verification))) throw new Error(`${label}.verification: expected an object`);
  optionalText(asRecord(value.verification), ['level', 'actor', 'model'], `${label}.verification`);
  optionalReferences(asRecord(value.verification), ['source_validation_refs'], `${label}.verification`);
  for (const step of steps) {
    if (!asString(step.action)) throw new Error(`${label}.exploitation.steps: missing action`);
    optionalStrings(step, ['component_ids', 'primitive_ids', 'example_ids'], `${label}.step`);
    optionalText(step, ['controlled_input', 'why_it_works', 'expected_result', 'evidence_status'], `${label}.step`);
    optionalText(step, ['observed_result'], `${label}.step`, true);
    optionalReferences(step, ['evidence_refs', 'observation_refs'], `${label}.step`);
  }
  for (const action of actions) {
    if (!asString(action.change)) throw new Error(`${label}.remediation.actions: missing change`);
    optionalStrings(action, ['breaks_steps', 'component_ids', 'example_ids'], `${label}.action`);
    optionalText(action, ['rationale'], `${label}.action`);
    optionalReferences(action, ['evidence_refs'], `${label}.action`);
    if (hasOwn(action, 'locations')) locations(action.locations, `${label}.action.locations`);
  }
  for (const component of asRecords(value.affected_components)) {
    if (!asString(component.name)) throw new Error(`${label}.affected_components: missing component name`);
    optionalText(component, ['repository'], `${label}.component`);
    optionalStrings(component, ['entrypoints'], `${label}.component`);
    optionalReferences(component, ['evidence_refs'], `${label}.component`);
    if (hasOwn(component, 'locations')) locations(component.locations, `${label}.component.locations`);
    if (hasOwn(component, 'service') && (!component.service || typeof component.service !== 'object' || Array.isArray(component.service))) throw new Error(`${label}.component.service: expected an object`);
    // Published dossiers use a null name when the service binding is unknown.
    // Keep that explicit unknown; a component/repository label is not a service.
    optionalText(asRecord(component.service), ['name'], `${label}.component.service`, true);
    optionalText(asRecord(component.service), ['binding', 'limitation'], `${label}.component.service`);
  }
  for (const example of asRecords(value.technical_examples)) {
    if (typeof example.content !== 'string' || !asString(example.kind)) throw new Error(`${label}.technical_examples: missing content or kind`);
    optionalText(example, ['execution_status'], `${label}.example`);
    optionalReferences(example, ['evidence_refs', 'observation_refs'], `${label}.example`);
    if (hasOwn(example, 'substitutions')) for (const substitution of validRecords(example.substitutions, `${label}.example.substitutions`)) {
      for (const key of ['original', 'replacement', 'reason']) if (typeof substitution[key] !== 'string') throw new Error(`${label}.example.substitutions: invalid ${key}`);
    }
  }
  locations(value.root_causes, `${label}.root_causes`);
  for (const trace of asRecords(value.trace)) {
    if (!asString(trace.file) || !Number.isInteger(trace.line) || Number(trace.line) < 1 || !['entrypoint', 'propagation', 'sink'].includes(String(trace.kind))) throw new Error(`${label}.trace: invalid source location or kind`);
  }
  for (const name of ['primitive_steps', 'transitions']) if (hasOwn(value, name)) validRecords(value[name], `${label}.${name}`);
  if (hasOwn(value, 'primitive_steps')) uniqueIds(asRecords(value.primitive_steps), 'primitive_id', `${label}.primitive_steps`);
  for (const transition of asRecords(value.transitions)) if (!asString(transition.producer_id) || !asString(transition.consumer_id)) throw new Error(`${label}.transitions: missing producer or consumer identity`);
  const remediation = asRecord(value.remediation);
  if (hasOwn(remediation, 'verification_checks')) {
    const checks = validRecords(remediation.verification_checks, `${label}.remediation.verification_checks`);
    uniqueIds(checks, 'id', `${label}.remediation.verification_checks`);
    for (const check of checks) optionalText(check, ['description', 'attack_expected', 'legitimate_expected', 'status'], `${label}.check`);
  }
  for (const name of ['containment', 'detection', 'unresolved_decisions']) if (hasOwn(remediation, name) && !Array.isArray(remediation[name])) throw new Error(`${label}.remediation.${name}: expected an array`);
  optionalStrings(remediation, ['limitations'], `${label}.remediation`);
}

export function validateBundle(bundle: AdmittedBundle): void {
  const report = bundle.report;
  if (!bundle.run_id || !['audit', 'advantage'].includes(bundle.execution_kind)) throw new Error('Missing or unsupported execution identity');
  if (report.schema_version !== '2.0') throw new Error('Unsupported report schema; schema 2.0 is required');
  if (report.run_id !== undefined && report.run_id !== bundle.run_id) throw new Error('Report belongs to another execution');
  if (report.execution_kind !== undefined && report.execution_kind !== bundle.execution_kind) throw new Error('Report execution kind conflicts with publication');
  if (bundle.execution_kind === 'advantage' && report.mode === 'actions') throw new Error('Actions-only Advantage reports are not supported');
  const rows = validRecords(report.findings, 'report.findings');
  uniqueIds(rows, 'id', 'report.findings');
  const final = asRecord(bundle.final);
  if (final.run_id !== undefined && final.run_id !== bundle.run_id) throw new Error('Final findings belong to another execution');
  validRecords(final.findings, 'final-verification/findings.json.findings');
  if (canonicalJson(rows) !== canonicalJson(final.findings)) throw new Error('Report findings disagree with final-verification/findings.json');
  for (const row of rows) validateDossier(row);
  const assessment = asRecord(report.assessment);
  if (hasOwn(assessment, 'scopes')) for (const scope of validRecords(assessment.scopes, 'assessment.scopes')) if (scope.run_id !== undefined && scope.run_id !== null && scope.run_id !== bundle.run_id) throw new Error('Assessment scope belongs to another execution');
  if (bundle.execution_kind === 'advantage') {
    const links = validRecords(report.links, 'report.links');
    uniqueIds(links, 'finding_id', 'report.links');
    if (links.length !== rows.length || links.some(link => !rows.some(row => row.id === link.finding_id) || !classifications.has(link.classification as Classification) || !Array.isArray(link.baseline_ids))) throw new Error('Advantage finding classifications do not match final findings');
    if (!asString(asRecord(report.baseline).execution_id)) throw new Error('Advantage baseline execution is missing');
  }
}

function normalizeScope(raw: JsonRecord, runId: string): AssessmentScope {
  return { ...raw, assessment_id: asString(raw.assessment_id), run_id: asString(raw.run_id) ?? runId,
    attempt_id: asString(raw.attempt_id), source_view: asString(raw.source_view), started_at: asString(raw.started_at),
    repositories: asRecords(raw.repositories) as RepositoryRecord[], limitations: asStrings(raw.limitations) };
}
function scopeFor(raw: RawFinding, report: JsonRecord, runId: string): AssessmentScope | null {
  const assessment = asRecord(report.assessment);
  const id = asString(asRecord(assessment.record_scopes)[raw.id ?? '']) ?? asString(raw.assessment_context?.assessment_id);
  // A single available scope is not proof that a record belongs to it.
  const match = asRecords(assessment.scopes).find(scope => scope.assessment_id === id && (!scope.run_id || scope.run_id === runId));
  return match ? normalizeScope(match, runId) : null;
}
function classificationFor(report: JsonRecord, id: string): Classification | null {
  const value = asRecords(report.links).find(link => link.finding_id === id)?.classification;
  return classifications.has(value as Classification) ? value as Classification : null;
}
function cohortFor(raw: RawFinding): Cohort {
  if (raw.verdict === 'confirmed' && raw.status === 'verified') return 'confirmed';
  if (raw.verdict === 'needs_environment' || raw.status === 'needs_environment') return 'needs_environment';
  if (raw.verdict === 'rejected' || raw.status === 'rejected') return 'rejected';
  return 'unconfirmed';
}
function normalizeFinding(raw: RawFinding, runId: string, report: JsonRecord, options: { origin?: 'assessed' | 'historical'; cohort?: Cohort; hasDossier?: boolean; id?: string; representedIn?: string } = {}): FindingRecord {
  const id = options.id ?? raw.id ?? raw.finding_id ?? 'unknown';
  const cohort = options.cohort ?? cohortFor(raw);
  const hasDossier = options.hasDossier ?? true;
  const key = cohort === 'non_promoted' ? qualifiedKey('record', runId, cohort, id) : findingKey(runId, id);
  const scope = scopeFor(raw, report, runId);
  const link = asRecords(report.links).find(row => row.finding_id === id);
  const sourceView = scope?.source_view ?? asString(link?.source_view);
  const components = (raw.affected_components ?? []).map(component => ({ id: component.id, key: localEntityKey(key, 'component', component.id), name: component.name,
    repository: asString(component.repository), entrypoints: asStrings(component.entrypoints), serviceBinding: asString(component.service?.binding), serviceName: asString(component.service?.name) }));
  const severity = raw.severity === 'informational' ? 'info' : severities.includes(raw.severity as Severity) ? raw.severity as Severity : 'unknown';
  const roleLabel = cohort === 'non_promoted' ? 'Non-promoted record' : cohort === 'rejected' ? 'Rejected finding' : 'Unconfirmed finding';
  return { key, runId, id, title: raw.title ?? `${roleLabel} ${id}`, severity, verdict: asString(raw.verdict), status: asString(raw.status), kind: asString(raw.finding_kind),
    classification: options.origin === 'historical' ? null : classificationFor(report, id), origin: options.origin ?? 'assessed', cohort, hasDossier,
    scope, scopeId: scope?.assessment_id ?? asString(raw.assessment_context?.assessment_id), sourceView,
    repositories: unique(components.map(component => component.repository).filter((name): name is string => !!name)), components,
    verificationLevel: asString(raw.verification?.level), attackSummary: asString(raw.attack_summary), impact: asString(raw.impact),
    repairCount: raw.remediation?.actions?.length ?? 0, stepCount: raw.exploitation?.steps?.length ?? 0, traceCount: raw.trace?.length ?? 0,
    historicalIn: options.representedIn ? [options.representedIn] : [], conflicted: false, diagnostics: [], raw };
}
function countAssessment(rows: FindingRecord[], report: JsonRecord, kind: 'audit' | 'advantage'): AssessmentCounts {
  const confirmed = rows.filter(row => row.cohort === 'confirmed');
  const history = asRecords(report.historical_findings).map(row => asRecord(row.finding));
  const counts = asRecord(report.counts), summary = asRecord(report.summary);
  const categoryCount = (classification: Classification) => confirmed.filter(row => row.classification === classification).length;
  return { total: rows.length, confirmed: confirmed.length, needsEnvironment: rows.filter(row => row.cohort === 'needs_environment').length,
    severity: Object.fromEntries(severities.map(severity => [severity, confirmed.filter(row => row.severity === severity).length])) as Record<Severity, number>,
    confirmedChains: confirmed.filter(row => row.kind === 'chain').length, historical: history.length,
    historicalConfirmed: history.filter(row => row.verdict === 'confirmed' && row.status === 'verified').length,
    historicalNeedsEnvironment: history.filter(row => row.verdict === 'needs_environment').length,
    unconfirmed: kind === 'advantage' ? collectionCount(report, 'unconfirmed') : collectionCount(report, 'unreviewed', summary.unreviewed),
    nonPromoted: collectionCount(report, 'non_promoted'), rejected: collectionCount(report, 'rejections', summary.rejected),
    addedOutcomes: categoryCount('new_root') + categoryCount('new_chain') + categoryCount('impact_expansion'), newRoots: categoryCount('new_root'), newChains: categoryCount('new_chain'), impactExpansions: categoryCount('impact_expansion'), revalidations: categoryCount('baseline_revalidation'), corrections: categoryCount('baseline_correction'),
    sourceOnly: confirmed.filter(row => row.verificationLevel === 'source_verified').length, dynamicallyVerified: confirmed.filter(row => row.verificationLevel === 'dynamic_verified').length,
    unresolvedQuestions: numberOrNull(counts.unresolved_questions), unresolvedApplicability: collectionCount(report, 'unresolved_applicability', counts.unresolved_applicability) };
}
function adapt(bundle: AdmittedBundle): { assessment: Assessment; findings: FindingRecord[] } {
  validateBundle(bundle);
  const report = bundle.report, own = (report.findings as RawFinding[]).map(raw => normalizeFinding(raw, bundle.run_id, report));
  const findings = [...own];
  const ownIds = new Set(own.map(row => row.id));
  const extras: Array<[string, Cohort]> = [['unconfirmed', 'unconfirmed'], ['unreviewed', 'unconfirmed'], ['rejections', 'rejected'], ['non_promoted', 'non_promoted']];
  for (const [field, cohort] of extras) {
    for (const [index, record] of asRecords(report[field]).entries()) {
      const id = asString(record.id) ?? asString(record.finding_id) ?? `${field}-${index + 1}`;
      if (cohort !== 'non_promoted' && ownIds.has(id)) continue;
      const dossier = asRecords(report.unconfirmed_dossiers).find(row => row.id === id);
      const raw = (dossier ?? record) as RawFinding;
      const hasDossier = !!dossier || !!(raw.title && raw.exploitation && raw.remediation && raw.trace);
      // Retained unconfirmed dossiers come from synthesis and intentionally
      // have no final verdict. Their explicit cohort never becomes confirmed.
      if (hasDossier) validateDossier(raw, field, false);
      findings.push(normalizeFinding(raw, bundle.run_id, report, { id, cohort, hasDossier }));
    }
  }
  const assessment = asRecord(report.assessment);
  const publication = asRecord(report.publication);
  const scopes = asRecords(assessment.scopes).map(scope => normalizeScope(scope, bundle.run_id));
  const limitations = unique([...asStrings(report.limitations), ...asStrings(assessment.limitations), ...asStrings(asRecord(report.coverage).limitations), ...scopes.flatMap(scope => scope.limitations)]);
  const accounting: JsonRecord = {};
  for (const field of ['ancillary', 'investigation_accounting', 'evidence_quality', 'objective_assessments', 'coverage', 'outcome_assessment', 'gap_exploration', 'non_promoted', 'unconfirmed', 'unreviewed', 'rejections']) if (hasOwn(report, field)) accounting[field] = report[field];
  return { findings, assessment: { id: bundle.run_id, kind: bundle.execution_kind, mode: asString(report.mode) ?? asString(bundle.mode), repository: asString(bundle.repository) ?? asString(report.repository),
    repositories: asRecords(publication.repositories ?? report.repositories ?? bundle.repositories) as RepositoryRecord[], scopes,
    publishedAt: asString(publication.published_at) ?? asString(report.date), counts: countAssessment(own, report, bundle.execution_kind),
    findingKeys: findings.map(row => row.key), historicalFindingKeys: [], baselineId: asString(asRecord(report.baseline).execution_id), baselineLoaded: false,
    baselineReconciliation: asRecords(report.baseline_reconciliation), unresolvedApplicability: asRecords(report.unresolved_applicability),
    limitations, availability: hasOwn(report, 'baseline_availability') ? asRecord(report.baseline_availability) : null, accounting, diagnostics: [], report } };
}
export function adaptOrdinary(bundle: AdmittedBundle): ReturnType<typeof adapt> {
  if (bundle.execution_kind !== 'audit') throw new Error('Ordinary adapter requires an audit publication');
  return adapt(bundle);
}
export function adaptAdvantage(bundle: AdmittedBundle): ReturnType<typeof adapt> {
  if (bundle.execution_kind !== 'advantage') throw new Error('Advantage adapter requires an Advantage publication');
  return adapt(bundle);
}

/** Inputs must already be filesystem-admitted. This layer never reads source or files. */
export function normalizeWorkspace(bundles: AdmittedBundle[], initialFailures: ImportFailure[] = []): Workspace {
  const failures = [...initialFailures], assessments: Assessment[] = [], findings: FindingRecord[] = [], conflicts: IdentityConflict[] = [], relations: FindingRelation[] = [];
  const seenPaths = new Set<string>();
  const distinct = bundles.filter(bundle => { if (!bundle.inputPath) return true; if (seenPaths.has(bundle.inputPath)) return false; seenPaths.add(bundle.inputPath); return true; });
  const counts = new Map<string, number>();
  for (const bundle of distinct) counts.set(bundle.run_id, (counts.get(bundle.run_id) ?? 0) + 1);
  for (const bundle of distinct) {
    if ((counts.get(bundle.run_id) ?? 0) > 1) { failures.push({ inputPath: bundle.inputPath, runId: bundle.run_id, code: 'ambiguous_execution', message: 'Distinct input roots claim this execution; restart with one selected root.' }); continue; }
    try { const result = bundle.execution_kind === 'advantage' ? adaptAdvantage(bundle) : adaptOrdinary(bundle); assessments.push(result.assessment); findings.push(...result.findings); }
    catch (error) { failures.push({ inputPath: bundle.inputPath, runId: bundle.run_id, code: 'invalid_presentation_structure', message: error instanceof Error ? error.message : 'Invalid publication structure' }); }
  }
  const byKey = new Map(findings.map(finding => [finding.key, finding]));
  const owners = new Map(assessments.map(assessment => [assessment.id, assessment]));
  for (const assessment of assessments) {
    assessment.baselineLoaded = !!assessment.baselineId && owners.has(assessment.baselineId);
    for (const wrapper of asRecords(assessment.report.historical_findings)) {
      const ownerId = asString(wrapper.execution_id), raw = asRecord(wrapper.finding) as RawFinding;
      if (!ownerId || !raw.id) { assessment.diagnostics.push({ code: 'unreadable_history', message: 'A historical record lacks owning execution or finding identity.', runId: assessment.id }); continue; }
      const key = findingKey(ownerId, raw.id);
      try { validateDossier(raw, 'historical finding'); }
      catch { assessment.diagnostics.push({ code: 'unreadable_history', message: 'A historical dossier is unavailable because required fields are invalid.', runId: ownerId, findingKey: key }); continue; }
      const existing = byKey.get(key);
      if (existing) {
        existing.historicalIn = unique([...existing.historicalIn, assessment.id]);
        if (canonicalJson(existing.raw) !== canonicalJson(raw)) {
          existing.conflicted = true;
          let conflict = conflicts.find(item => item.key === key);
          if (!conflict) { conflict = { key, runId: ownerId, findingId: raw.id, representedIn: [], message: 'Representations of this execution-qualified finding disagree; excluded from deduplicated inventory.' }; conflicts.push(conflict); }
          conflict.representedIn = unique([...conflict.representedIn, existing.runId, assessment.id]);
        }
      } else {
        // No linked scope is borrowed from the importing Advantage assessment.
        const historical = normalizeFinding(raw, ownerId, owners.get(ownerId)?.report ?? {}, { origin: 'historical', representedIn: assessment.id });
        findings.push(historical); byKey.set(key, historical);
      }
      assessment.historicalFindingKeys.push(key);
    }
    for (const link of asRecords(assessment.report.links)) {
      if (!assessment.baselineId || !classifications.has(link.classification as Classification) || !asString(link.finding_id)) continue;
      for (const id of asStrings(link.baseline_ids)) {
        const from = findingKey(assessment.id, String(link.finding_id)), to = findingKey(assessment.baselineId, id);
        relations.push({ key: qualifiedKey('relation', from, to, String(link.classification)), kind: 'baseline', from, to, classification: link.classification as Classification, sourceView: asString(link.source_view), available: byKey.has(to) && !byKey.get(to)?.conflicted });
      }
    }
  }
  // A later representation can expose a conflict after a relation was first seen.
  for (const relation of relations) relation.available = byKey.has(relation.to) && !byKey.get(relation.to)?.conflicted;
  return { assessments, findings, failures, conflicts, relations };
}
export function summarizeFinding(finding: FindingRecord): FindingSummary {
  const { raw: _raw, ...summary } = finding;
  return summary;
}
export function summarizeWorkspace(workspace: Workspace): WorkspaceSummary {
  return { ...workspace, assessments: workspace.assessments.map(({ report: _report, ...summary }) => summary), findings: workspace.findings.map(summarizeFinding) };
}
export const summaryWorkspace = summarizeWorkspace;
