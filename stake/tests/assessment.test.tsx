// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import '@testing-library/jest-dom/vitest';
import AssessmentView from '../src/features/assessment/Assessment';
import { normalizeWorkspace, summarizeWorkspace, type AssessmentSummary } from '../src/domain';
import { makeFinding, makePublication } from './fixtures/bundles';

afterEach(cleanup);

function assessment(): AssessmentSummary {
  return summarizeWorkspace(normalizeWorkspace([makePublication({ reportOverrides: {
    limitations: Array.from({ length: 8 }, (_, i) => `Synthetic scope limitation ${i + 1}: additional deployment evidence is required.`),
    investigation_accounting: {
      counts: { unresolved_paths: null, evidence_limited: 0, unscheduled_work: 9 },
      truncated: { unresolved_paths: null, evidence_limited: 0, unscheduled_work: 8 },
      unresolved_paths: [{ id: 'PATH-001', reason: 'The synthetic callback routing is unknown.', resolution: { outcome: 'externally_blocked', missing_fact: 'The deployed queue binding.', next_action: 'Request the deployment binding inventory.' }, evidence_ref: 'sast/verified-findings.json:C-001' }],
      evidence_limited: [],
      unscheduled_work: [{ question_id: 'Q-009', reason: 'The synthetic retry branch remains outside the recorded allocation.', next_action: 'Review the retry consumer.' }],
    },
  } })])).assessments[0];
}

describe('assessment context workspace', () => {
  it('accepts the route selection while keeping every loaded assessment available', async () => {
    const user = userEvent.setup(), first = assessment(), onAssessmentChange = vi.fn();
    const second = { ...first, id: 'second-assessment' };
    const { rerender } = render(<AssessmentView assessments={[first, second]} selectedAssessmentId="second-assessment" onAssessmentChange={onAssessmentChange} onEvidence={vi.fn()}/>);
    expect(screen.getByLabelText('Assessment', { exact: true })).toHaveValue('second-assessment');
    await user.selectOptions(screen.getByLabelText('Assessment', { exact: true }), first.id);
    expect(onAssessmentChange).toHaveBeenCalledWith(first.id);
    rerender(<AssessmentView assessments={[first, second]} selectedAssessmentId={first.id} onAssessmentChange={onAssessmentChange} onEvidence={vi.fn()}/>);
    expect(screen.getByLabelText('Assessment', { exact: true })).toHaveValue(first.id);
  });

  it('starts with one clear assessment and collapsed detail, and changes the local selection without merging totals', async () => {
    const user = userEvent.setup(), first = assessment();
    const second = summarizeWorkspace(normalizeWorkspace([makePublication({ runId: 'advantage-fixture', kind: 'advantage', findings: [makeFinding(), makeFinding({ id: 'F-002' })] })])).assessments[0];
    second.baselineReconciliation = [{ baseline_id: 'F-OLD', status: 'historical', reason: 'The original source scope remains authoritative.' }];
    render(<AssessmentView assessments={[first, second]} onEvidence={vi.fn()}/>);
    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent('Know the scope.');
    expect(screen.getByRole('tab', { name: 'Overview' })).toHaveAttribute('data-state', 'active');
    expect(screen.queryByText('Synthetic scope limitation 1: additional deployment evidence is required.')).not.toBeInTheDocument();
    expect(screen.queryByText('Advanced provenance & accounting')).not.toBeInTheDocument();
    expect(screen.getByText('Confirmed findings').closest('.asmt-number-card')).toHaveTextContent('1');
    await user.click(screen.getByRole('tab', { name: 'Source scope' }));
    await user.selectOptions(screen.getByLabelText('Assessment', { exact: true }), 'advantage-fixture');
    expect(screen.getByRole('tab', { name: 'Overview' })).toHaveAttribute('data-state', 'active');
    expect(screen.getByText('Confirmed findings').closest('.asmt-number-card')).toHaveTextContent('2');
    expect(screen.getByText('Added outcomes').closest('.asmt-number-card')).toHaveTextContent('2');
    expect(screen.getByText('Not supplied in this workspace')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: /Baseline decisions/ }));
    await user.click(screen.getByRole('button', { name: /F-OLD/ }));
    expect(screen.getByText('The original source scope remains authoritative.', { selector: 'p' })).toBeInTheDocument();
  });

  it('presents complete assessed revisions and leaves absent source metadata unknown', async () => {
    const user = userEvent.setup(), a = assessment();
    const { rerender } = render(<AssessmentView assessments={[a]} onEvidence={vi.fn()}/>);
    await user.click(screen.getByRole('tab', { name: 'Source scope' }));
    const table = screen.getAllByRole('table')[0];
    expect(within(table).getByRole('columnheader', { name: 'Assessed revision' })).toBeInTheDocument();
    expect(within(table).getByText('a'.repeat(40))).toBeInTheDocument();
    expect(within(table).getByText('storefront')).toBeInTheDocument();
    expect(screen.queryByText('Scope and publication are separate events.')).not.toBeInTheDocument();
    rerender(<AssessmentView assessments={[{ ...a, repositories: [{ name: 'Storefront', path: 'storefront', commit: null }], scopes: [] }]} onEvidence={vi.fn()}/>);
    expect(within(screen.getByRole('table')).getByText('Unknown')).toBeInTheDocument();
    expect(screen.getByText('Assessment scope metadata is unavailable')).toBeInTheDocument();
    expect(screen.queryByText('a'.repeat(40))).not.toBeInTheDocument();
  });

  it('separates unknown, zero, included and omitted accounting and exposes actionable question detail', async () => {
    const user = userEvent.setup(), onEvidence = vi.fn();
    render(<AssessmentView assessments={[assessment()]} onEvidence={onEvidence}/>);
    await user.click(screen.getByRole('tab', { name: 'Open questions' }));
    expect(screen.getByText('Unresolved paths').closest('.asmt-number-card')).toHaveTextContent('Unknown');
    await user.click(screen.getByRole('button', { name: /Unresolved attack paths/ }));
    expect(screen.getByText('Total:', { exact: false }).closest('.asmt-cohort-meta')).toHaveTextContent('1 included hereTotal: UnknownOmitted: Unknown');
    await user.click(screen.getByRole('button', { name: /PATH-001/ }));
    expect(screen.getByText('The deployed queue binding.', { selector: 'dd' })).toBeVisible();
    expect(screen.getByText('Request the deployment binding inventory.', { selector: 'dd' })).toBeVisible();
    await user.click(screen.getByRole('button', { name: 'sast/verified-findings.json:C-001' }));
    expect(onEvidence).toHaveBeenCalledWith('sast/verified-findings.json:C-001', 'audit-fixture');
    await user.click(screen.getByRole('button', { name: /Unscheduled investigation/ }));
    expect(screen.getAllByText('Total:', { exact: false }).map(node => node.closest('.asmt-cohort-meta')?.textContent)).toContain('1 included hereTotal: 9Omitted: 8');
    await user.click(screen.getByRole('button', { name: /Recorded investigation totals/ }));
    const unknown = screen.getByText('Unresolved Paths').closest('div')!;
    const zero = screen.getByText('Evidence Limited').closest('div')!;
    expect(unknown).toHaveTextContent('Unknown');
    expect(zero).toHaveTextContent('0');
    expect(zero).not.toHaveTextContent('Unknown');
  });

  it('opens each original artifact in its owning execution and makes raw details optional', async () => {
    const user = userEvent.setup(), onEvidence = vi.fn();
    render(<AssessmentView assessments={[assessment()]} onEvidence={onEvidence}/>);
    await user.click(screen.getByRole('tab', { name: 'Evidence' }));
    for (const [label, path] of [['Report JSON', 'report/security-report.json'], ['Report Markdown', 'report/security-report.md'], ['Final findings', 'final-verification/findings.json']]) {
      await user.click(screen.getByRole('button', { name: label }));
      expect(onEvidence).toHaveBeenLastCalledWith(path, 'audit-fixture');
    }
    expect(screen.queryByText('publication attempt id')).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: /Advanced provenance & accounting/ }));
    expect(screen.getAllByText('The deployed queue binding.').length).toBeGreaterThan(0);
  });
});
