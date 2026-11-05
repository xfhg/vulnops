// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import '@testing-library/jest-dom/vitest';
import { normalizeWorkspace, type RawFinding } from '../src/domain';
import { EvidenceList, SourceLocations } from '../src/features/findings/DossierPrimitives';
import RepairPanel from '../src/features/findings/RepairPanel';
import { makeFinding, makePublication } from './fixtures/bundles';

afterEach(cleanup);

function normalized(raw: RawFinding = makeFinding()) {
  const workspace = normalizeWorkspace([makePublication({ runId: 'repair-owner', findings: [raw] })]);
  expect(workspace.failures).toEqual([]);
  return workspace.findings[0];
}

describe('dossier evidence and source navigation', () => {
  it('preserves original typed references and the owning run behind compact evidence labels', async () => {
    const user = userEvent.setup(), onEvidence = vi.fn();
    const typed = { execution_id: 'original-baseline', artifact_ref: 'final-verification/results/F-2.json', source_id: 'review-2' };
    const source = 'storefront/src/orders.ts:42-47';
    render(<EvidenceList refs={[typed, source]} runId="repair-owner" onEvidence={onEvidence}/>);
    await user.click(screen.getByRole('button', { name: 'final-verification/results/F-2.json · review-2' }));
    expect(onEvidence).toHaveBeenLastCalledWith(typed, 'repair-owner');
    expect(onEvidence.mock.calls[0][0]).toBe(typed);
    await user.click(screen.getByRole('button', { name: source }));
    expect(onEvidence).toHaveBeenLastCalledWith(source, 'repair-owner');
    expect(typed.execution_id).toBe('original-baseline');
  });

  it('opens exact source ranges, retains full context, and leaves missing file coordinates inert', async () => {
    const user = userEvent.setup(), onEvidence = vi.fn();
    const mechanism = 'The recorded ownership decision is absent before the state change.';
    render(<SourceLocations locations={[
      { file: 'storefront/src/orders.ts', start_line: 42, end_line: 47, scope: 'approveOrder', mechanism, description: 'The assessed source contains two distinct authorization boundaries.' },
      { file: '' },
    ]} runId="repair-owner" onEvidence={onEvidence} label="Proposed repair locations"/>);
    const table = within(screen.getByRole('table', { name: 'Proposed repair locations' }));
    expect(table.getByText('42–47')).toBeVisible();
    await user.click(table.getByRole('button', { name: 'storefront/src/orders.ts:42-47' }));
    expect(onEvidence).toHaveBeenCalledWith('storefront/src/orders.ts:42-47', 'repair-owner');
    expect(table.getByText(mechanism, { selector: 'p' })).not.toBeVisible();
    await user.click(table.getByText('View context'));
    expect(table.getByText(mechanism, { selector: 'p' })).toBeVisible();
    expect(table.getByText('The assessed source contains two distinct authorization boundaries.')).toBeVisible();
    const missing = table.getByRole('button', { name: 'File not recorded' });
    expect(missing).toBeDisabled();
    expect(within(missing.closest('tr')!).getByText('Not recorded')).toBeVisible();
    await user.click(missing);
    expect(onEvidence).toHaveBeenCalledTimes(1);
  });

  it('shows requested repair source context openly and copies the exact citation with an honest failure fallback', async () => {
    const user = userEvent.setup(), onEvidence = vi.fn();
    const copy = vi.spyOn(navigator.clipboard, 'writeText').mockResolvedValue();
    const reference = 'storefront/src/orders.ts:42-47';
    render(<SourceLocations showContext locations={[{ file: 'storefront/src/orders.ts', start_line: 42, end_line: 47,
      mechanism: 'The full recorded mechanism remains visible.', description: 'The complete assessed source context remains visible.' }]}
      runId="repair-owner" onEvidence={onEvidence} label="Proposed repair locations"/>);
    expect(screen.getByText('The full recorded mechanism remains visible.')).toBeVisible();
    expect(screen.getByText('The complete assessed source context remains visible.')).toBeVisible();
    expect(screen.queryByText('View context')).not.toBeInTheDocument();
    const button = screen.getByRole('button', { name: `Copy citation ${reference}` });
    await user.click(button);
    expect(copy).toHaveBeenLastCalledWith(reference);
    expect(screen.getByRole('status')).toHaveTextContent('Source citation copied');
    expect(onEvidence).not.toHaveBeenCalled();
    copy.mockRejectedValueOnce(new Error('Synthetic clipboard denial'));
    await user.click(button);
    expect(screen.getByRole('status')).toHaveTextContent('Could not copy');
    expect(screen.getByText(reference, { selector: 'code' })).toBeVisible();
    await user.click(screen.getByRole('button', { name: reference }));
    expect(onEvidence).toHaveBeenCalledWith(reference, 'repair-owner');
    copy.mockRestore();
  });
});

describe('implementation repair cards', () => {
  it('names the change, opens exact linked steps, and keeps overlay and verification actions separate', async () => {
    const user = userEvent.setup(), raw = makeFinding();
    raw.remediation!.actions[0].status = 'proposed';
    const finding = normalized(raw);
    const onRepair = vi.fn(), onStep = vi.fn(), onVerify = vi.fn(), onEvidence = vi.fn();
    const props = { finding, onRepair, onStep, onVerify, onEvidence };
    const { rerender } = render(<RepairPanel {...props} repairId=""/>);
    const action = finding.raw.remediation!.actions[0];
    const card = within(screen.getByRole('article'));
    expect(card.getByRole('heading', { name: action.change })).toBeVisible();
    expect(card.queryByRole('heading', { name: action.id })).not.toBeInTheDocument();
    expect(card.getByText('Recorded status: proposed')).toBeVisible();
    const step = finding.raw.exploitation!.steps[1];
    const stepLink = card.getByRole('button', { name: name => name.startsWith(`Read reproduction step ${step.id}:`) && name.includes(step.action) });
    expect(stepLink).toHaveTextContent(step.action);
    await user.click(stepLink);
    expect(onStep).toHaveBeenCalledWith(step.id, action.id);
    await user.click(card.getByRole('button', { name: 'Show interruption' }));
    expect(onRepair).toHaveBeenLastCalledWith(action.id);
    expect(onVerify).not.toHaveBeenCalled();
    rerender(<RepairPanel {...props} repairId={action.id}/>);
    await user.click(card.getByRole('button', { name: 'Show interruption' }));
    expect(onRepair).toHaveBeenLastCalledWith(action.id);
    await user.click(screen.getByRole('button', { name: 'Review verification checks' }));
    expect(onVerify).toHaveBeenCalledOnce();
  });

  it('keeps action evidence and repair locations attributed to the owning execution', async () => {
    const user = userEvent.setup(), raw = makeFinding(), onEvidence = vi.fn();
    const copy = vi.spyOn(navigator.clipboard, 'writeText').mockResolvedValue();
    raw.remediation!.actions[0].evidence_refs = [{ execution_id: 'baseline-owner', artifact_ref: 'sast/verified-findings.json', record_id: 'C-2' }];
    raw.remediation!.actions[0].locations = [{ file: 'storefront/src/orders.ts', start_line: 42, end_line: 47 }];
    const finding = normalized(raw), reference = finding.raw.remediation!.actions[0].evidence_refs![0];
    render(<RepairPanel finding={finding} repairId="" onRepair={vi.fn()} onStep={vi.fn()} onVerify={vi.fn()} onEvidence={onEvidence}/>);
    await user.click(screen.getByRole('button', { name: 'sast/verified-findings.json · C-2' }));
    expect(onEvidence).toHaveBeenLastCalledWith(reference, 'repair-owner');
    expect(onEvidence.mock.calls[0][0]).toBe(reference);
    const guide = within(screen.getByRole('region', { name: 'Repair location orders.ts:42–47' }));
    expect(guide.getByText('storefront/src/orders.ts', { selector: 'code' })).toBeVisible();
    await user.click(guide.getByRole('button', { name: 'Copy citation storefront/src/orders.ts:42-47' }));
    expect(copy).toHaveBeenCalledWith('storefront/src/orders.ts:42-47');
    expect(onEvidence).toHaveBeenCalledTimes(1);
    expect(guide.queryByRole('button', { name: 'storefront/src/orders.ts:42-47' })).not.toBeInTheDocument();
    copy.mockRestore();
  });

  it('retains containment, detection, limitations and unresolved decisions as independent guidance', async () => {
    const user = userEvent.setup(), raw = makeFinding();
    Object.assign(raw.remediation!, {
      containment: ['Restrict the synthetic approval callback while preparing the repair.'],
      detection: ['Review unexpected cross-account approval events.'],
      limitations: ['The deployed consumer binding was not supplied.'],
      unresolved_decisions: [{ decision: 'Choose the owner of the callback authorization policy.', next_action: 'Request the deployment ownership inventory.' }],
    });
    const finding = normalized(raw), before = structuredClone(finding.raw);
    render(<RepairPanel finding={finding} repairId="" onRepair={vi.fn()} onStep={vi.fn()} onVerify={vi.fn()} onEvidence={vi.fn()}/>);
    const support = within(screen.getByRole('region', { name: 'Supporting guidance' }));
    for (const title of ['Temporary containment', 'Detection guidance', 'Implementation limitations', 'Unresolved decisions']) {
      const trigger = support.getByRole('button', { name: new RegExp('^' + title) });
      expect(trigger).toHaveAttribute('aria-expanded', 'false');
      await user.click(trigger);
      expect(trigger).toHaveAttribute('aria-expanded', 'true');
    }
    for (const text of [
      'Restrict the synthetic approval callback while preparing the repair.',
      'Review unexpected cross-account approval events.',
      'The deployed consumer binding was not supplied.',
      'Choose the owner of the callback authorization policy.',
      'Request the deployment ownership inventory.',
    ]) expect(support.getByText(text)).toBeVisible();
    expect(finding.raw).toEqual(before);
  });

  it('shows unavailable references honestly without substituting known steps or components', async () => {
    const user = userEvent.setup(), raw = makeFinding(), onRepair = vi.fn(), onStep = vi.fn();
    raw.remediation!.actions = [{ id: 'action-missing', change: 'Authorize the callback before accepting the order.', breaks_steps: ['step-unavailable'], component_ids: ['component-unavailable'], example_ids: ['example-unavailable'], locations: [] }];
    const props = { finding: normalized(raw), onRepair, onStep, onVerify: vi.fn(), onEvidence: vi.fn() };
    const { rerender } = render(<RepairPanel {...props} repairId=""/>);
    const card = within(screen.getByRole('article'));
    expect(card.getByText('Referenced step is unavailable in this dossier.')).toBeVisible();
    expect(card.getByText('Referenced component unavailable')).toBeVisible();
    expect(card.getByText('Referenced example unavailable')).toBeVisible();
    expect(card.queryByRole('button', { name: /step-unavailable/ })).not.toBeInTheDocument();
    expect(card.queryByText('Storefront')).not.toBeInTheDocument();
    expect(card.getByRole('button', { name: 'Show interruption' })).toBeDisabled();
    await user.click(card.getByText('step-unavailable', { selector: 'code' }));
    await user.click(card.getByRole('button', { name: 'Show interruption' }));
    expect(onRepair).not.toHaveBeenCalled();
    expect(onStep).not.toHaveBeenCalled();
    rerender(<RepairPanel {...props} repairId="action-missing"/>);
    expect(card.getByRole('button', { name: 'Show interruption' })).toBeDisabled();
    expect(onRepair).not.toHaveBeenCalled();
  });

  it('shows the complete implementation change immediately and preserves rationale and additional fields', async () => {
    const user = userEvent.setup(), raw = makeFinding();
    const change = 'Bind the synthetic session to its initiating account. '.repeat(12) + 'COMPLETE_CHANGE_END';
    const rationale = 'Preserve the recorded ownership decision across the callback boundary. '.repeat(12) + 'COMPLETE_RATIONALE_END';
    Object.assign(raw.remediation!.actions[0], { change, rationale, additional_guidance: 'Keep the legitimate callback path available.' });
    render(<RepairPanel finding={normalized(raw)} repairId="" onRepair={vi.fn()} onStep={vi.fn()} onVerify={vi.fn()} onEvidence={vi.fn()}/>);
    const card = within(screen.getByRole('article'));
    expect(card.getByText(change, { selector: 'p' })).toBeVisible();
    expect(card.queryByText('Read complete implementation change')).not.toBeInTheDocument();
    await user.click(card.getByText('Read full rationale'));
    expect(card.getByText(rationale, { selector: 'p' })).toBeVisible();
    await user.click(card.getByText('Complete action record'));
    expect(card.getByText('Keep the legitimate callback path available.')).toBeVisible();
  });
});
