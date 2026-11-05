// @vitest-environment jsdom
import { useState, type ReactNode } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import '@testing-library/jest-dom/vitest';
import Overview from '../src/features/overview/Overview';
import FindingsTable from '../src/features/findings/FindingsTable';
import FindingDetail from '../src/features/findings/FindingDetail';
import Remediation from '../src/features/remediation/Remediation';
import AssessmentView from '../src/features/assessment/Assessment';
import { filterFindings, normalizeWorkspace, summarizeWorkspace, type FindingRecord, type RawFinding, type TechnicalExample } from '../src/domain';
import { makeFinding, makeMixedObservationFinding, makePublication } from './fixtures/bundles';

// Canvas/layout and syntax-worker rendering have separate graph/browser tests.
// Keep these tests focused on the information and actions a reader receives.
vi.mock('recharts', () => ({
  ResponsiveContainer: ({ children }: { children: ReactNode }) => <div>{children}</div>,
  BarChart: ({ children }: { children: ReactNode }) => <div>{children}</div>,
  Bar: () => null, Cell: () => null, XAxis: () => null, Tooltip: () => null,
}));
vi.mock('../src/features/attack-explorer/AttackExplorer', () => ({ default: () => <div data-testid="attack-explorer">Recorded attack explorer</div> }));
vi.mock('../src/features/remediation/RepairCanvas', () => ({ default: () => <div>Repair relationship map</div> }));
vi.mock('../src/components/CodeBlock', () => ({ default: ({ example }: { example: TechnicalExample }) => <div><span>{example.execution_status}</span><pre>{example.content}</pre></div> }));
afterEach(cleanup);
Element.prototype.scrollIntoView = vi.fn();

function normalized(findings: RawFinding[]) {
  const workspace = normalizeWorkspace([makePublication({ findings })]);
  expect(workspace.failures).toEqual([]);
  return workspace;
}
function section(title: string) {
  return within(screen.getByRole('heading', { name: title, level: 2 }).closest('section')!);
}
function metric(label: string) {
  return within(screen.getByLabelText('Assessed outcome metrics')).getByText(label).closest('.metric-card')!;
}
function DetailHarness({ finding, initialPanel = 'reproduce', onRepair = vi.fn(), onRepairMap = vi.fn() }: { finding: FindingRecord; initialPanel?: string; onRepair?: (id: string) => void; onRepairMap?: (id: string) => void }) {
  const [panel, setPanel] = useState(initialPanel);
  const [selected, setSelected] = useState(''), [repairId, setRepairId] = useState(''), [detailRecord, setDetailRecord] = useState('');
  const [mode, setMode] = useState<'procedure' | 'trace' | 'composition'>('procedure');
  return <FindingDetail finding={finding} panel={panel} graphMode={mode} selected={selected} repairId={repairId} detailRecord={detailRecord} onPanel={setPanel} onBack={vi.fn()} onMode={setMode} onSelect={setSelected} onRepair={onRepair} onRepairMap={onRepairMap} onEvidence={vi.fn()} onNavigate={changes => {
    if (changes.panel) setPanel(changes.panel);
    if (changes.mode) setMode(changes.mode as typeof mode);
    if ('selected' in changes) setSelected(changes.selected ?? '');
    if ('detailRecord' in changes) setDetailRecord(changes.detailRecord ?? '');
    if ('repair' in changes) { setRepairId(changes.repair ?? ''); onRepair(changes.repair ?? ''); }
  }} />;
}

describe('owner overview', () => {
  it('shows four numeric outcome metrics, bounded priorities and exact cohort drilldowns', async () => {
    const user = userEvent.setup(), onExplore = vi.fn();
    const rows = Array.from({ length: 39 }, (_, i) => makeFinding({ id: `F-${i + 1}`, severity: i >= 37 ? 'critical' : i === 0 ? 'critical' : i < 16 ? 'high' : i < 36 ? 'medium' : 'low',
      ...(i >= 37 ? { verdict: 'needs_environment', status: 'needs_environment', verification: { level: 'environment_required' } } : {}) }));
    const workspace = summarizeWorkspace(normalized(rows));
    render(<Overview assessments={workspace.assessments} findings={workspace.findings} onFinding={vi.fn()} onView={vi.fn()} onExplore={onExplore} />);
    expect(metric('Confirmed outcomes').querySelector('strong')).toHaveTextContent(/^37$/);
    expect(metric('High & critical').querySelector('strong')).toHaveTextContent(/^16$/);
    expect(metric('Recorded chains').querySelector('strong')).toHaveTextContent(/^37$/);
    expect(metric('Needs environment').querySelector('strong')).toHaveTextContent(/^2$/);
    const repository = within(screen.getByRole('region', { name: 'Confirmed outcomes by repository' }));
    expect(repository.getByRole('button', { name: 'Explore critical outcomes in storefront' })).toHaveTextContent('Critical1');
    expect(repository.getByRole('button', { name: 'Explore high outcomes in storefront' })).toHaveTextContent('High15');
    expect(repository.getByRole('button', { name: 'Explore medium outcomes in storefront' })).toHaveTextContent('Medium20');
    expect(repository.getByRole('button', { name: 'Explore low outcomes in storefront' })).toHaveTextContent('Low1');
    expect(within(screen.getByRole('table', { name: 'Priority findings' })).getAllByRole('row')).toHaveLength(6);
    expect(screen.getByText('Showing 5 of 16 confirmed records')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Explore high and critical outcomes' }));
    expect(onExplore).toHaveBeenLastCalledWith({ disposition: 'confirmed', origin: 'assessed', severity: 'critical,high' });
    await user.click(screen.getByRole('button', { name: 'Explore recorded chains' }));
    expect(onExplore).toHaveBeenLastCalledWith({ disposition: 'confirmed', origin: 'assessed', kind: 'chain' });
    await user.click(screen.getByRole('tab', { name: 'Needs environment' }));
    expect(screen.getByText('Showing 2 of 2 environment-dependent records')).toBeInTheDocument();
    expect(within(screen.getByRole('table', { name: 'Priority findings' })).getAllByRole('row')).toHaveLength(3);
    await user.click(screen.getByRole('button', { name: 'View matching findings' }));
    expect(onExplore).toHaveBeenLastCalledWith({ disposition: 'needs_environment', origin: 'assessed' });
  });

  it('labels added Advantage outcomes separately from revalidations and imported history', () => {
    const rows = Array.from({ length: 5 }, (_, i) => makeFinding({ id: `A-${i + 1}` }));
    const labels = ['new_root', 'new_root', 'impact_expansion', 'baseline_revalidation', 'baseline_revalidation'];
    const workspace = summarizeWorkspace(normalizeWorkspace([makePublication({ kind: 'advantage', runId: 'advantage', findings: rows, reportOverrides: {
      links: rows.map((row, i) => ({ finding_id: row.id, classification: labels[i], baseline_ids: [], source_view: 'base' })),
      historical_findings: Array.from({ length: 12 }, (_, i) => ({ execution_id: 'older-audit', finding: makeFinding({ id: `B-${i + 1}` }) })),
    } })]));
    render(<Overview assessments={workspace.assessments} findings={workspace.findings} onFinding={vi.fn()} onView={vi.fn()} />);
    expect(metric('Confirmed outcomes').querySelector('strong')).toHaveTextContent(/^5$/);
    expect(metric('Confirmed outcomes')).toHaveTextContent('0 ordinary · 3 added · 2 revalidated');
    const contribution = within(screen.getByRole('region', { name: 'Advantage contribution' }));
    expect(contribution.getByText('3 added outcomes')).toBeInTheDocument();
    expect(contribution.getByRole('button', { name: 'Explore Advantage new roots' }).querySelector('strong')).toHaveTextContent(/^2$/);
    expect(contribution.getByRole('button', { name: 'Explore Advantage impact expansions' }).querySelector('strong')).toHaveTextContent(/^1$/);
    expect(contribution.getByRole('button', { name: 'Explore Advantage revalidations' }).querySelector('strong')).toHaveTextContent(/^2$/);
    expect(contribution.getByText(/Imported history is excluded/)).toBeInTheDocument();
    expect(within(screen.getByRole('table', { name: 'Priority findings' })).queryByText(/B-/)).not.toBeInTheDocument();
  });

  it('presents zero confirmations with uncertainty and leaves missing accounting unknown', async () => {
    const user = userEvent.setup();
    const workspace = normalizeWorkspace([makePublication({ findings: [], reportOverrides: {
      limitations: ['The deployed queue binding remains unresolved.'],
      investigation_accounting: { unresolved_questions: null, known_empty_cohort: 0 },
    } })]);
    const summary = summarizeWorkspace(workspace);
    const { unmount } = render(<Overview assessments={summary.assessments} findings={summary.findings} onFinding={vi.fn()} onView={vi.fn()} />);
    expect(metric('Confirmed outcomes').querySelector('strong')).toHaveTextContent(/^0$/);
    expect(screen.getByRole('heading', { name: 'No confirmed outcomes' })).toBeInTheDocument();
    expect(screen.getByText(/Review Assessment for open questions and recorded limitations/)).toBeInTheDocument();
    expect(screen.queryByRole('meter')).not.toBeInTheDocument();
    unmount();
    render(<AssessmentView assessments={summary.assessments} onEvidence={vi.fn()} />);
    await user.click(screen.getByRole('tab', { name: 'Open questions' }));
    await user.click(screen.getByRole('button', { name: /Recorded investigation totals/ }));
    const unknown = screen.getByText('Unresolved Questions').closest('div')!;
    const empty = screen.getByText('Known Empty Cohort').closest('div')!;
    expect(unknown).toHaveTextContent('Unknown');
    expect(empty).toHaveTextContent('0');
    expect(empty).not.toHaveTextContent('Unknown');
  });

  it('keeps critical findings ahead of informational ones while exposing the complete priority cohort', async () => {
    const user = userEvent.setup(), onFinding = vi.fn();
    const workspace = summarizeWorkspace(normalized([
      makeFinding({ id: 'F-info', title: 'Informational finding', severity: 'informational' }),
      makeFinding({ id: 'F-critical', title: 'Critical finding', severity: 'critical' }),
    ]));
    render(<Overview assessments={workspace.assessments} findings={workspace.findings} onFinding={onFinding} onView={vi.fn()} />);
    const priority = within(screen.getByRole('region', { name: 'Priority findings' }));
    expect(priority.getAllByRole('heading', { level: 3 }).map(node => node.textContent)).toEqual(['Critical finding']);
    await user.click(screen.getByRole('tab', { name: 'All confirmed' }));
    expect(priority.getAllByRole('heading', { level: 3 }).map(node => node.textContent)).toEqual(['Critical finding', 'Informational finding']);
    await user.click(priority.getByRole('button', { name: 'Open F-info: Informational finding' }));
    expect(onFinding).toHaveBeenCalledWith(expect.objectContaining({ id: 'F-info' }));
  });

  it('labels combined numbers as assessed records and retains every owning report count', () => {
    const workspace = summarizeWorkspace(normalizeWorkspace([
      makePublication({ runId: 'first-assessment', findings: [makeFinding()] }),
      makePublication({ runId: 'second-assessment', findings: [makeFinding(), makeFinding({ id: 'F-002' })] }),
    ]));
    workspace.assessments[0].repositories = [{ commit: null }];
    workspace.assessments[1].repositories = [];
    render(<Overview assessments={workspace.assessments} findings={workspace.findings} onFinding={vi.fn()} onView={vi.fn()} />);
    expect(metric('Confirmed outcomes').querySelector('strong')).toHaveTextContent(/^3$/);
    expect(metric('Confirmed outcomes')).toHaveTextContent('Assessed outcome records');
    expect(screen.getByText(/The same issue can appear in more than one report/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: '2 reports' })).toBeInTheDocument();
    expect(screen.getByText('Repository inventory not recorded')).toBeInTheDocument();
    expect(screen.getByText('1 inventory entry is unattributed · 1 report inventory is not recorded')).toBeInTheDocument();
    const context = within(screen.getByRole('region', { name: 'Report context' }));
    expect(context.getByText('first-assessment').closest('.scope-card')).toHaveTextContent('1 confirmed');
    expect(context.getByText('second-assessment').closest('.scope-card')).toHaveTextContent('2 confirmed');
  });

  it('uses scoped records for repository and repair guidance counts, with honest unattributed navigation', async () => {
    const user = userEvent.setup(), onExplore = vi.fn(), onView = vi.fn();
    const raw = [makeFinding({ id: 'F-001' }), makeFinding({ id: 'F-002' }), makeFinding({ id: 'F-003' })];
    raw[0].remediation!.actions.push({ ...raw[0].remediation!.actions[0], id: 'action-2' });
    raw[1].remediation!.actions = [];
    const workspace = summarizeWorkspace(normalized(raw));
    workspace.findings[2].repositories = ['another-repository'];
    const scoped = filterFindings(workspace.findings, { repository: 'storefront' });
    render(<Overview assessments={workspace.assessments} findings={scoped} scopedRepository="storefront" unattributedReviewCount={2} onFinding={vi.fn()} onView={onView} onExplore={onExplore} />);
    expect(metric('Confirmed outcomes').querySelector('strong')).toHaveTextContent(/^2$/);
    expect(screen.getByText('Selected: storefront')).toBeInTheDocument();
    const handoff = within(screen.getByRole('region', { name: 'Developer handoff' }));
    expect(handoff.getByRole('meter')).toHaveAttribute('aria-valuenow', '1');
    expect(handoff.getByRole('meter')).toHaveAttribute('aria-valuemax', '2');
    expect(handoff.getByText('No recorded actions').closest('div')).toHaveTextContent('1');
    expect(handoff.getByText('Guidance unknown').closest('div')).toHaveTextContent('0');
    expect(handoff.getByText('recorded action entries').closest('.overview-action-records')).toHaveTextContent('2');
    expect(handoff.getByText('Recommendations, not completed fixes.')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Explore confirmed outcomes in storefront' }));
    expect(onExplore).toHaveBeenLastCalledWith({ disposition: 'confirmed', origin: 'assessed', repository: 'storefront' });
    await user.click(screen.getByRole('button', { name: 'Review repository attribution' }));
    expect(onView).toHaveBeenLastCalledWith('assessment');
    await user.click(screen.getByRole('button', { name: 'Review repair guidance' }));
    expect(onView).toHaveBeenLastCalledWith('remediation');
  });
});

describe('finding inventory and complete evidence', () => {
  it('opens repair instructions before the graph and focuses exact prose records without changing evidence', async () => {
    const user = userEvent.setup(), onRepairMap = vi.fn();
    const raw = makeFinding();
    raw.remediation!.actions[0].change = 'Bind the initiating account before approval. ' + 'Retain the recorded ownership requirement through the callback and selected order transition. '.repeat(6).trim();
    const finding = normalized([raw]).findings[0], before = structuredClone(finding.raw);
    const { container } = render(<DetailHarness finding={finding} initialPanel="summary" onRepairMap={onRepairMap}/>);
    expect(screen.queryByTestId('attack-explorer')).not.toBeInTheDocument();
    const header = within(container.querySelector('.finding-header')!);
    await user.click(header.getByRole('button', { name: 'Read repair instructions' }));
    expect(screen.getByRole('tab', { name: /^Repair/ })).toHaveAttribute('data-state', 'active');
    const action = screen.getByRole('article', { name: 'Repair action 1: action-1' });
    expect(within(action).getByText(raw.remediation!.actions[0].change, { selector: 'p' })).toBeVisible();
    await user.click(within(action).getByRole('button', { name: /^Read reproduction step step-2:/ }));
    const step = screen.getByRole('region', { name: raw.exploitation!.steps[1].action });
    await waitFor(() => expect(step).toHaveFocus());
    expect(within(step).getByText('No observation recorded; no execution claimed.')).toBeVisible();
    expect(screen.queryByTestId('attack-explorer')).not.toBeInTheDocument();
    await user.click(within(step).getByRole('button', { name: 'Read repair action-1' }));
    const returnedAction = screen.getByRole('article', { name: 'Repair action 1: action-1' });
    await waitFor(() => expect(returnedAction).toHaveFocus());
    await user.click(within(returnedAction).getByRole('button', { name: 'Open technical example example-1' }));
    await waitFor(() => expect(screen.getByRole('region', { name: 'Recorded technical example example-1' })).toHaveFocus());
    await user.click(screen.getByRole('tab', { name: /^Repair/ }));
    await user.click(screen.getByRole('button', { name: 'Open repair map' }));
    expect(onRepairMap).toHaveBeenCalledWith('action-1');
    await user.click(screen.getByRole('button', { name: 'Show interruption' }));
    expect(screen.getByRole('tab', { name: 'Attack map' })).toHaveAttribute('data-state', 'active');
    expect(await screen.findByTestId('attack-explorer')).toBeVisible();
    expect(finding.raw).toEqual(before);
  });

  it('keeps all filtered findings reachable through pagination and resets empty filters', async () => {
    const user = userEvent.setup();
    const rows = Array.from({ length: 27 }, (_, i) => makeFinding({ id: `F-${String(i + 1).padStart(3, '0')}`, title: `Synthetic approval ${i + 1}` }));
    const workspace = summarizeWorkspace(normalized(rows));
    const onFinding = vi.fn(), onReset = vi.fn();
    const filtered = filterFindings(workspace.findings, { repository: 'storefront', severity: 'high', query: 'Synthetic approval' });
    const { rerender } = render(<FindingsTable findings={filtered} onFinding={onFinding} onReset={onReset} />);
    expect(screen.getByText('27 matching findings')).toBeInTheDocument();
    expect(screen.queryByText('Synthetic approval 27')).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Next page' }));
    await user.click(screen.getByRole('button', { name: 'Next page' }));
    expect(screen.getByText('Page 3 of 3')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Open F-027' }));
    expect(onFinding).toHaveBeenCalledWith(expect.objectContaining({ id: 'F-027' }));
    expect(screen.getByRole('button', { name: 'Next page' })).toBeDisabled();
    rerender(<FindingsTable findings={filterFindings(workspace.findings, { query: 'no match' })} onFinding={onFinding} onReset={onReset} />);
    expect(screen.getByRole('heading', { name: 'No matching findings' })).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Reset filters' }));
    expect(onReset).toHaveBeenCalledOnce();
    expect(workspace.assessments[0].counts.confirmed).toBe(27);
  });

  it('exposes every step and full final example of a long dossier', async () => {
    const raw = makeFinding();
    raw.exploitation!.steps = Array.from({ length: 35 }, (_, i) => ({ ...raw.exploitation!.steps[0], id: `step-${i + 1}`, action: `Recorded synthetic action ${i + 1}` }));
    const longExample = Array.from({ length: 120 }, (_, i) => `SYNTHETIC_LINE_${i + 1}`).join('\n');
    raw.technical_examples = Array.from({ length: 18 }, (_, i) => ({ id: `example-${i + 1}`, kind: 'request', content: i === 17 ? longExample : `INERT_EXAMPLE_${i + 1}`, execution_status: 'not_executed' }));
    render(<DetailHarness finding={normalized([raw]).findings[0]} />);
    expect(screen.getAllByRole('heading', { name: /Recorded synthetic action/ })).toHaveLength(35);
    const finalExample = await screen.findByText((_, element) => element?.tagName === 'PRE' && element.textContent === longExample);
    expect(finalExample.textContent).toBe(longExample);
    expect(screen.getByRole('heading', { name: 'Recorded synthetic action 35' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Run|Execute/ })).not.toBeInTheDocument();
  });

  it('keeps an observation local to its step and does not promote an unexecuted environment-dependent step', async () => {
    const raw = makeMixedObservationFinding();
    raw.exploitation!.steps.push({ ...raw.exploitation!.steps[1], id: 'step-3', action: 'Check the deployment-only boundary.', evidence_status: 'environment_required', expected_result: 'A deployed binding would be required.', observed_result: null });
    raw.technical_examples!.push({ id: 'example-2', kind: 'request', content: 'INERT_DEPLOYMENT_EXAMPLE', execution_status: 'not_executed' });
    render(<DetailHarness finding={normalized([raw]).findings[0]} />);
    const observed = within(screen.getByRole('heading', { name: 'Present the unbound approval session.' }).closest('section')!);
    const sourceOnly = within(screen.getByRole('heading', { name: 'Request approval of another synthetic account’s order.' }).closest('section')!);
    const external = within(screen.getByRole('heading', { name: 'Check the deployment-only boundary.' }).closest('section')!);
    expect(observed.getByText('observed contained')).toBeInTheDocument();
    expect(observed.getByText('A synthetic fixture selected the supplied session identity.')).toBeInTheDocument();
    expect(sourceOnly.getByText('source established')).toBeInTheDocument();
    expect(sourceOnly.getByText('No observation recorded; no execution claimed.')).toBeInTheDocument();
    expect(external.getByText('environment required')).toBeInTheDocument();
    expect(external.queryByText('source established')).not.toBeInTheDocument();
    expect(external.getByText('No observation recorded; no execution claimed.')).toBeInTheDocument();
    expect(await screen.findByText('INERT_DEPLOYMENT_EXAMPLE')).toBeInTheDocument();
    expect(screen.getByText('not_executed')).toBeInTheDocument();
  });
});

describe('repair decisions', () => {
  it('keeps same-named actions from separate findings distinct within a component group', async () => {
    const user = userEvent.setup(), onFinding = vi.fn();
    const first = makeFinding({ id: 'F-one', title: 'First route' });
    const second = makeFinding({ id: 'F-two', title: 'Second route' });
    first.remediation!.actions[0].change = 'Authorize the initiating account.';
    second.remediation!.actions[0].change = 'Authorize the consumed order.';
    const workspace = normalized([first, second]);
    render(<Remediation findings={workspace.findings} onFinding={onFinding} onRecord={vi.fn()} onCode={vi.fn()} onEvidence={vi.fn()} />);
    expect(screen.getByRole('tab', { name: 'Repair brief' })).toHaveAttribute('aria-selected', 'true');
    expect(screen.getByRole('region', { name: 'Repair brief' })).toBeVisible();
    expect(screen.queryByText('Repair relationship map')).not.toBeInTheDocument();
    expect(screen.queryByRole('region', { name: 'Repair record details' })).not.toBeInTheDocument();
    const queue = within(screen.getByRole('complementary', { name: 'Repair actions' }));
    expect(queue.getByText('2 of 2')).toBeInTheDocument();
    expect(queue.getByText('F-one / action-1')).toBeInTheDocument();
    expect(queue.getByText('F-two / action-1')).toBeInTheDocument();
    const secondRow = within(queue.getByRole('button', { name: /Select repair F-two/ }).closest('article')!);
    await user.click(secondRow.getByRole('button', { name: /Select repair F-two/ }));
    expect(screen.getByRole('heading', { name: 'Authorize the consumed order.', level: 2 })).toBeInTheDocument();
    await user.click(secondRow.getByRole('button', { name: 'Review repair' }));
    expect(onFinding).toHaveBeenCalledWith(expect.objectContaining({ id: 'F-two' }), 'action-1');
    expect(screen.queryByText(/Fixed|Tests passed|Verified patch/)).not.toBeInTheDocument();
  });

  it('discloses complete rationale and additional recorded action fields without showing an inspector on the brief', async () => {
    const user = userEvent.setup();
    const raw = makeFinding();
    const rationale = 'The recorded ownership decision must retain the original account context through approval. '.repeat(8).trim();
    raw.remediation!.actions[0].rationale = rationale;
    raw.remediation!.actions[0].viewer_note = 'Additional synthetic implementation context remains intact.';
    render(<Remediation findings={normalized([raw]).findings} onFinding={vi.fn()} onRecord={vi.fn()} onCode={vi.fn()} onEvidence={vi.fn()} />);
    const brief = within(screen.getByRole('region', { name: 'Repair brief' }));
    expect(brief.getByRole('button', { name: 'Show full rationale' })).toHaveAttribute('aria-expanded', 'false');
    await user.click(brief.getByRole('button', { name: 'Show full rationale' }));
    expect(brief.getByText(rationale)).toBeVisible();
    expect(screen.queryByRole('region', { name: 'Repair record details' })).not.toBeInTheDocument();
    await user.click(screen.getByRole('tab', { name: /All repair records/ }));
    const records = within(screen.getByLabelText('All repair records'));
    await user.click(records.getByRole('button', { name: /action-1/ }));
    expect(screen.getByRole('tab', { name: /All repair records/ })).toHaveAttribute('aria-selected', 'true');
    const detail = within(screen.getByRole('region', { name: 'Repair record details' }));
    await user.click(detail.getByText('Complete selected record', { exact: true }));
    expect(detail.getByText('Additional synthetic implementation context remains intact.')).toBeVisible();
    await user.click(screen.getByRole('tab', { name: 'Repair brief' }));
    expect(screen.queryByRole('region', { name: 'Repair record details' })).not.toBeInTheDocument();
  });

  it('retains interrupted steps and proposed attack/legitimate-operation checks', async () => {
    const user = userEvent.setup(), onRepair = vi.fn();
    const finding = normalized([makeFinding()]).findings[0];
    render(<DetailHarness finding={finding} initialPanel="repair" onRepair={onRepair} />);
    const repair = within(screen.getByRole('heading', { name: finding.raw.remediation!.actions[0].change }).closest('article')!);
    expect(repair.getByRole('button', { name: /^Read reproduction step step-1:/ })).toBeInTheDocument();
    expect(repair.getByRole('button', { name: /^Read reproduction step step-2:/ })).toBeInTheDocument();
    await user.click(repair.getByRole('button', { name: 'Show interruption' }));
    expect(onRepair).toHaveBeenCalledWith('action-1');
    await user.click(screen.getByRole('tab', { name: 'Verify' }));
    const checks = section('Fix verification');
    expect(checks.getByText('proposed')).toBeInTheDocument();
    expect(checks.getByText('The unauthorized approval is rejected without mutation.')).toBeInTheDocument();
    expect(checks.getByText('The authorized approval succeeds.')).toBeInTheDocument();
    expect(checks.queryByText(/passed|fixed/i)).not.toBeInTheDocument();
  });

  it('does not combine same-named components belonging to different repositories', async () => {
    const first = makeFinding({ id: 'F-storefront' });
    const second = makeFinding({ id: 'F-payments' });
    second.affected_components![0].repository = 'payments';
    second.affected_components![0].locations![0].file = 'payments/src/orders.ts';
    const workspace = normalized([first, second]);
    render(<Remediation findings={workspace.findings} onFinding={vi.fn()} onRecord={vi.fn()} onCode={vi.fn()} onEvidence={vi.fn()} />);
    const queue = within(screen.getByRole('complementary', { name: 'Repair actions' }));
    expect(queue.getAllByRole('button', { name: /^Select repair / })).toHaveLength(2);
    expect(queue.getByText('confirmed · payments')).toBeInTheDocument();
    expect(queue.getByText('confirmed · storefront')).toBeInTheDocument();
    await userEvent.click(queue.getByRole('button', { name: /Select repair F-payments/ }));
    await userEvent.click(screen.getByRole('tab', { name: /All repair records/ }));
    const records = within(screen.getByLabelText('All repair records'));
    expect(records.getByRole('button', { name: /component-1/ })).toHaveTextContent('payments');
  });
});
