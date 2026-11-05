import { describe, expect, it } from 'vitest';
import { buildOverviewModel } from '../src/domain/overview';
import { filterFindings, normalizeWorkspace, summarizeWorkspace } from '../src/domain';
import type { AssessmentSummary, FindingSummary, JsonRecord } from '../src/domain/types';
import { makeFinding, makePublication } from './fixtures/bundles';

function fixture() {
  return summarizeWorkspace(normalizeWorkspace([makePublication({ runId: 'audit', findings: [makeFinding({ id: 'F-2' })] })]));
}
function summary(id: string, overrides: Partial<FindingSummary> = {}): FindingSummary {
  const base = fixture().findings[0];
  const runId = overrides.runId ?? 'audit';
  return { ...base, id, key: JSON.stringify(['finding', runId, id]), title: `Synthetic ${id}`, ...overrides };
}
function assessment(id = 'audit', kind: AssessmentSummary['kind'] = 'audit'): AssessmentSummary {
  return { ...fixture().assessments[0], id, kind };
}

describe('Overview summary projection', () => {
  it('counts ordinary and additional outcomes once while retaining revalidations and corrections separately', () => {
    const ordinary = makePublication({ runId: 'audit', findings: [makeFinding({ id: 'F-1' })] });
    const advantage = makePublication({ runId: 'advantage', kind: 'advantage', baselineId: 'audit', findings: ['F-2', 'F-3', 'F-4', 'F-5', 'F-6'].map(id => makeFinding({ id })),
      reportOverrides: { links: ['new_root', 'new_chain', 'impact_expansion', 'baseline_revalidation', 'baseline_correction'].map((classification, index) => ({ finding_id: `F-${index + 2}`, classification, baseline_ids: ['F-1'] })), historical_findings: [{ execution_id: 'audit', finding: structuredClone((ordinary.report.findings as JsonRecord[])[0]) }] } });
    const workspace = summarizeWorkspace(normalizeWorkspace([ordinary, advantage]));
    const model = buildOverviewModel(workspace.assessments, [...workspace.findings, workspace.findings[0]]);
    expect(model.confirmed).toHaveLength(6);
    expect(model.confirmation.ordinary.map(finding => finding.id)).toEqual(['F-1']);
    expect(model.confirmation.additional.map(finding => finding.id)).toEqual(['F-2', 'F-3', 'F-4']);
    expect(model.confirmation.revalidations.map(finding => finding.id)).toEqual(['F-5']);
    expect(model.confirmation.corrections.map(finding => finding.id)).toEqual(['F-6']);
    expect(model.confirmation.other).toEqual([]);
    expect(model.confirmed[0].historicalIn).toEqual(['advantage']);
    expect(model.context.loadedAssessmentCount).toBe(2);
  });

  it('keeps Advantage-only historical dossiers out of assessed KPIs without discarding a revalidation', () => {
    const advantage = makePublication({ runId: 'advantage', kind: 'advantage', findings: [makeFinding({ id: 'F-2' })], reportOverrides: {
      links: [{ finding_id: 'F-2', classification: 'baseline_revalidation', baseline_ids: ['F-1'] }],
      historical_findings: [{ execution_id: 'missing-audit', finding: makeFinding({ id: 'F-1', severity: 'critical' }) }],
    } });
    const workspace = summarizeWorkspace(normalizeWorkspace([advantage]));
    expect(workspace.findings).toHaveLength(2);
    const model = buildOverviewModel(workspace.assessments, workspace.findings);
    expect(model.findings.map(finding => finding.id)).toEqual(['F-2']);
    expect(model.confirmation.revalidations).toHaveLength(1); expect(model.confirmation.ordinary).toHaveLength(0);
    expect(model.confirmation.additional).toHaveLength(0); expect(model.highImpact).toHaveLength(1);
  });

  it('uses the repository-filtered records for all finding metrics instead of assessment-wide totals', () => {
    const owner = assessment(); owner.counts.confirmed = 999;
    owner.repositories = [{ path: 'api' }, { path: 'worker' }];
    const records = [summary('F-1', { repositories: ['api'], severity: 'high', repairCount: 3, kind: 'chain' }),
      summary('F-2', { repositories: ['worker'], severity: 'critical', repairCount: 8 }),
      summary('F-3', { repositories: ['api'], cohort: 'needs_environment', verdict: 'needs_environment', repairCount: 5 })];
    const scoped = filterFindings(records, { repository: 'api' });
    const model = buildOverviewModel([owner], scoped);
    expect(model.confirmed).toHaveLength(1); expect(model.highImpact).toHaveLength(1); expect(model.chains).toHaveLength(1);
    expect(model.needsEnvironment).toHaveLength(1); expect(model.repairGuidance.actionRecords).toBe(3);
    expect(model.severity.find(bucket => bucket.severity === 'critical')!.count).toBe(0);
    expect(model.repositories.map(row => row.repository)).toEqual(['api']);
    expect(model.context.inventoryRepositories).toEqual(['api', 'worker']);
  });

  it('deduplicates only identical keys, excludes conflicts and history, and never merges equal IDs across owners', () => {
    const first = summary('F-1'), second = summary('F-1', { runId: 'another-audit' });
    const conflicted = summary('F-2', { conflicted: true });
    const history = summary('F-3', { origin: 'historical' });
    const model = buildOverviewModel([assessment(), assessment('another-audit')], [first, structuredClone(first), second, conflicted, { ...conflicted, conflicted: false }, history]);
    expect(model.confirmed).toHaveLength(2); expect(new Set(model.confirmed.map(finding => finding.key)).size).toBe(2);
    expect(model.repairGuidance.actionRecords).toBe(2);
  });

  it('orders priority by severity then natural ID and keeps confirmed ahead of other cohorts', () => {
    const records = [summary('F-10'), summary('F-2'), summary('F-1', { severity: 'medium' }), summary('F-20', { severity: 'critical' }),
      summary('F-0', { severity: 'critical', cohort: 'unconfirmed', verdict: null, status: null })];
    const model = buildOverviewModel([assessment()], records);
    expect(model.priority.map(finding => finding.id)).toEqual(['F-20', 'F-2', 'F-10', 'F-1']);
    expect(model.findings.at(-1)!.id).toBe('F-0');
    const shuffled = buildOverviewModel([assessment()], [records[4], records[2], records[0], records[3], records[1]]);
    expect(shuffled.priority.map(finding => finding.key)).toEqual(model.priority.map(finding => finding.key));
  });

  it('uses deterministic owner and scope tiebreaks without changing source records', () => {
    const records = [summary('F-2', { runId: 'run-10' }), summary('F-2', { runId: 'run-2' }), summary('F-02', { runId: 'run-2' })];
    const before = JSON.stringify(records);
    const model = buildOverviewModel([assessment('run-10'), assessment('run-2')], records);
    const reverse = buildOverviewModel([assessment('run-2'), assessment('run-10')], [...records].reverse());
    expect(model.priority.map(finding => finding.key)).toEqual(reverse.priority.map(finding => finding.key));
    expect(model.priority.filter(finding => finding.id === 'F-2').map(finding => finding.runId)).toEqual(['run-2', 'run-10']);
    expect(JSON.stringify(records)).toBe(before);
  });

  it('counts repository associations once per finding and labels the nonadditive repair records', () => {
    const cross = summary('F-1', { repositories: ['api', 'worker', 'api'], repairCount: 2, kind: 'chain' });
    const local = summary('F-2', { repositories: ['api'], repairCount: 1, kind: 'code', severity: 'medium' });
    const model = buildOverviewModel([assessment()], [cross, local]);
    expect(model.repositories.map(row => [row.repository, row.confirmed, row.highImpact, row.chains, row.repairActionRecords])).toEqual([
      ['api', 2, 1, 1, 3], ['worker', 1, 1, 1, 2],
    ]);
    expect(model.repositories[0].findingKeys).toEqual([cross.key, local.key]);
    expect(model.confirmed).toHaveLength(2); expect(model.repairGuidance.actionRecords).toBe(3);
  });

  it('retains unknown severity, ownership, repository and evidence rather than assigning defaults', () => {
    const owner = assessment(); owner.repositories = [{}];
    const missingOwner = summary('F-1', { runId: 'not-loaded', classification: 'new_root', severity: 'unknown', verificationLevel: null, repositories: [] });
    const missingClassification = summary('F-2', { runId: 'advantage', classification: null, verificationLevel: 'future_evidence_level', repositories: [] });
    const advantage = assessment('advantage', 'advantage'); advantage.repositories = [];
    const model = buildOverviewModel([owner, advantage], [missingOwner, missingClassification]);
    expect(model.confirmation.other).toHaveLength(2); expect(model.confirmation.additional).toHaveLength(0);
    expect(model.severity.find(bucket => bucket.severity === 'unknown')!.count).toBe(1);
    expect(model.repositories[0]).toMatchObject({ repository: null, confirmed: 2 });
    expect(model.evidence.other).toHaveLength(2); expect(model.evidence.sourceVerified).toHaveLength(0);
    expect(model.context).toMatchObject({ inventoryRepositoryCount: 0, unknownInventoryRepositories: 1, assessmentsWithoutRepositoryInventory: 1 });
  });

  it('counts guidance and evidence only for confirmed records, without implying an implemented fix', () => {
    const records = [summary('F-1', { repairCount: 2, verificationLevel: 'source_verified' }),
      summary('F-2', { repairCount: 0, verificationLevel: 'dynamic_verified' }),
      summary('F-3', { repairCount: 0, hasDossier: false, verificationLevel: null }),
      summary('F-4', { repairCount: 7, cohort: 'needs_environment', verificationLevel: 'environment_required' })];
    const model = buildOverviewModel([assessment()], records);
    expect(model.repairGuidance).toMatchObject({ withGuidance: 1, withoutGuidance: 1, unknownGuidance: 1, actionRecords: 2 });
    expect(model.repairGuidance.findings.map(finding => finding.id)).toEqual(['F-1']);
    expect(model.evidence.sourceVerified.map(finding => finding.id)).toEqual(['F-1']);
    expect(model.evidence.dynamicallyVerified.map(finding => finding.id)).toEqual(['F-2']);
    expect(model.evidence.other.map(finding => finding.id)).toEqual(['F-3']);
  });

  it('requires an explicit chain kind and does not promote a long procedure into composition', () => {
    const model = buildOverviewModel([assessment()], [summary('F-1', { kind: 'code', stepCount: 12 }), summary('F-2', { kind: 'chain', stepCount: 0 })]);
    expect(model.chains.map(finding => finding.id)).toEqual(['F-2']);
  });

  it('provides explicit empty buckets without inventing assessment scope or coverage', () => {
    const model = buildOverviewModel([], []);
    expect(model.confirmed).toEqual([]); expect(model.priority).toEqual([]); expect(model.repositories).toEqual([]);
    expect(model.severity.map(bucket => [bucket.severity, bucket.count])).toEqual([['critical', 0], ['high', 0], ['medium', 0], ['low', 0], ['info', 0], ['unknown', 0]]);
    expect(model.context).toEqual({ loadedAssessmentCount: 0, inventoryRepositories: [], inventoryRepositoryCount: 0, unknownInventoryRepositories: 0, assessmentsWithoutRepositoryInventory: 0 });
    expect(model.repairGuidance).toEqual({ findings: [], withGuidance: 0, withoutGuidance: 0, unknownGuidance: 0, actionRecords: 0 });
  });
});
