// @vitest-environment jsdom
import { afterEach, expect, it, vi } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import '@testing-library/jest-dom/vitest';
import AttackExplorer from '../src/features/attack-explorer/AttackExplorer';
import { normalizeWorkspace } from '../src/domain';
import { makeFinding, makePublication } from './fixtures/bundles';

afterEach(cleanup);

it('opens exact proposed repair location instructions by original action and index without opening source evidence', async () => {
  const finding = normalizeWorkspace([makePublication({ runId: 'location-owner', findings: [makeFinding()] })]).findings[0];
  // This regression exercises the repair links independently of canvas layout.
  finding.raw.exploitation!.steps = [];
  finding.raw.remediation!.actions[0].locations = [
    { file: 'storefront/range.ts', start_line: 4, end_line: 8 },
    { file: 'storefront/single.ts', line: 12, end_line: 12 },
    { file: 'storefront/file-only.ts' },
  ];
  Object.assign(finding.raw.remediation!.actions[0].locations[2], { line: null, start_line: null, end_line: null });
  const onEvidence = vi.fn(), onReadRepair = vi.fn(); const user = userEvent.setup();
  render(<AttackExplorer finding={finding} repairId="action-1" onEvidence={onEvidence} onReadRepair={onReadRepair} />);
  const references = ['storefront/range.ts:4-8', 'storefront/single.ts:12', 'storefront/file-only.ts'];
  for (const [index, reference] of references.entries()) {
    await user.click(screen.getByRole('button', { name: `Read implementation instructions for ${reference} of action-1` }));
    expect(onReadRepair).toHaveBeenLastCalledWith('action-1', index);
  }
  expect(onReadRepair).toHaveBeenCalledTimes(3);
  await user.click(screen.getByRole('button', { name: 'Read implementation instructions' }));
  expect(onReadRepair).toHaveBeenLastCalledWith('action-1');
  expect(onEvidence).not.toHaveBeenCalled();
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
});

it('keeps a proposed location readable when instruction navigation is unavailable instead of substituting an evidence action', () => {
  const finding = normalizeWorkspace([makePublication({ findings: [makeFinding()] })]).findings[0];
  finding.raw.exploitation!.steps = [];
  const onEvidence = vi.fn();
  render(<AttackExplorer finding={finding} repairId="action-1" onEvidence={onEvidence}/>);
  expect(screen.getByRole('region', { name: 'Proposed repair action-1' })).toHaveTextContent('storefront/src/orders.ts');
  expect(screen.queryByRole('button', { name: /^Read implementation instructions/ })).not.toBeInTheDocument();
  expect(onEvidence).not.toHaveBeenCalled();
});
