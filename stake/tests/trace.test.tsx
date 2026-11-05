// @vitest-environment jsdom
import { useState } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import '@testing-library/jest-dom/vitest';
import { FileCode2 } from 'lucide-react';
import { Trace, TraceCollapsible, TraceCollapsibleContent, TraceCollapsibleTrigger, TraceDescription, TraceIcon, TraceLine, TraceTitle } from '../src/components/ui/trace';
import SummaryPanel from '../src/features/findings/SummaryPanel';
import { normalizeWorkspace, type RawFinding } from '../src/domain';
import { makeFinding, makePublication } from './fixtures/bundles';

afterEach(cleanup);

function finding(raw: RawFinding = makeFinding()) {
  return normalizeWorkspace([makePublication({ runId: 'trace-owner', findings: [raw] })]).findings[0];
}

describe('Radix Trace composition', () => {
  it('keeps a plain line inert, forwards its attributes, and hides decorative icons', () => {
    const { container } = render(<Trace aria-label="Recorded context"><TraceLine title="Recorded source citation">
      <TraceIcon><FileCode2 /></TraceIcon><TraceTitle>A recorded authorization boundary</TraceTitle><TraceDescription>Three citations</TraceDescription>
    </TraceLine></Trace>);
    const line = container.querySelector('[data-slot=trace-line]')!;
    expect(line.tagName).toBe('SPAN');
    expect(line).toHaveAttribute('title', 'Recorded source citation');
    expect(line).not.toHaveAttribute('tabindex');
    expect(line).not.toHaveAttribute('data-status');
    expect(screen.queryByRole('button')).not.toBeInTheDocument();
    expect(container.querySelector('[data-slot=trace-icon]')).toHaveAttribute('aria-hidden', 'true');
    expect(screen.getByText('Three citations')).toBeVisible();
  });

  it('supports controlled expansion and keyboard activation without nesting controls', async () => {
    const user = userEvent.setup(), changed = vi.fn();
    function Controlled() {
      const [open, setOpen] = useState(false);
      return <Trace><TraceCollapsible open={open} onOpenChange={value => { changed(value); setOpen(value); }}>
        <TraceCollapsibleTrigger><TraceLine><TraceTitle>Inspect the recorded boundary</TraceTitle></TraceLine></TraceCollapsibleTrigger>
        <TraceCollapsibleContent className="recorded-detail"><p>The full original explanation.</p><button>Open source citation</button></TraceCollapsibleContent>
      </TraceCollapsible></Trace>;
    }
    render(<Controlled />);
    const trigger = screen.getByRole('button', { name: 'Inspect the recorded boundary' });
    expect(trigger).toHaveAttribute('aria-expanded', 'false');
    expect(trigger.querySelector('button')).toBeNull();
    await user.tab();
    expect(trigger).toHaveFocus();
    await user.keyboard('{Enter}');
    expect(changed).toHaveBeenLastCalledWith(true);
    expect(trigger).toHaveAttribute('aria-expanded', 'true');
    expect(screen.getByText('The full original explanation.').parentElement).toHaveClass('recorded-detail');
    await user.tab();
    expect(screen.getByRole('button', { name: 'Open source citation' })).toHaveFocus();
    await user.tab({ shift: true });
    await user.keyboard(' ');
    expect(changed).toHaveBeenLastCalledWith(false);
    expect(trigger).toHaveAttribute('aria-expanded', 'false');
    expect(screen.queryByRole('button', { name: 'Open source citation' })).not.toBeInTheDocument();
  });

  it('supports defaultOpen and explicit status values without making icons the accessible name', () => {
    const { container } = render(<Trace><TraceCollapsible defaultOpen>
      <TraceCollapsibleTrigger><TraceLine status="error"><TraceIcon><FileCode2 /></TraceIcon><TraceTitle>Failed to read the selected report</TraceTitle></TraceLine></TraceCollapsibleTrigger>
      <TraceCollapsibleContent>Publication unavailable.</TraceCollapsibleContent>
    </TraceCollapsible></Trace>);
    expect(screen.getByRole('button', { name: 'Failed to read the selected report' })).toHaveAttribute('aria-expanded', 'true');
    expect(container.querySelector('[data-slot=trace-line]')).toHaveAttribute('data-status', 'error');
    expect(screen.getByText('Publication unavailable.')).toBeVisible();
  });
});

describe('recorded finding explanations', () => {
  it('leads with the failing boundary and keeps complete source citations available on demand', async () => {
    const user = userEvent.setup();
    const { container } = render(<SummaryPanel finding={finding()} onEvidence={vi.fn()} />);
    expect(screen.getByRole('heading', { name: 'How this finding works' })).toBeVisible();
    const explanation = screen.getByRole('list', { name: 'Recorded finding explanation' });
    expect(within(explanation).getAllByRole('listitem')).toHaveLength(4);
    for (const label of ['Starting access and prerequisites', 'Why the boundary fails', 'Impact and limits']) {
      const trigger = within(explanation).getByRole('button', { name: label });
      expect(trigger).toHaveAttribute('aria-expanded', label === 'Why the boundary fails' ? 'true' : 'false');
      expect(trigger.querySelector('button')).toBeNull();
      expect(trigger).toHaveAccessibleDescription();
    }
    expect(screen.getByRole('button', { name: 'Supporting source citations' })).toHaveAttribute('aria-expanded', 'false');
    expect(screen.queryByRole('table', { name: 'Root-cause locations' })).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Supporting source citations' }));
    expect(screen.getByRole('table', { name: 'Root-cause locations' })).toBeVisible();
    expect(container.querySelectorAll('[data-slot=trace-line]')).toHaveLength(4);
    expect(container.querySelector('[data-status]')).toBeNull();
  });

  it('keeps the complete recorded access, control failure, impact and limits behind compact summaries', async () => {
    const user = userEvent.setup(), raw = makeFinding();
    const access = 'An authenticated caller can reach the approval callback with a supplied reference. '.repeat(7) + 'FULL_ACCESS_END';
    const mechanism = 'The callback reuses a supplied approval identifier without its recorded ownership binding. '.repeat(7) + 'FULL_MECHANISM_END';
    const impact = 'A permitted callback can affect an order in another account under the recorded conditions. '.repeat(7) + 'FULL_IMPACT_END';
    const intended = 'A callback must bind the approval to the initiating account before changing the order.';
    raw.attacker = { perspective: 'Authenticated synthetic user', starting_access: access, boundary_crossed: 'Account ownership decision' };
    raw.intended_behavior = intended;
    raw.exploitation!.rationale = mechanism;
    raw.impact = impact;
    raw.impact_limits = ['Other account routes were not established.'];
    raw.conditions = ['A valid callback reference is available.'];
    const original = JSON.stringify(raw);
    render(<SummaryPanel finding={finding(raw)} onEvidence={vi.fn()} />);
    expect(screen.queryByText(access, { selector: 'dd' })).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Starting access and prerequisites' })).toHaveAccessibleDescription(/An authenticated caller/);
    expect(screen.getByRole('button', { name: 'Starting access and prerequisites' })).not.toHaveTextContent('FULL_ACCESS_END');
    await user.click(screen.getByRole('button', { name: 'Starting access and prerequisites' }));
    expect(screen.getByText(access, { selector: 'dd' })).toBeVisible();
    expect(screen.getByText('Account ownership decision')).toBeVisible();
    expect(screen.getByText('A valid callback reference is available.')).toBeVisible();
    expect(screen.getByRole('button', { name: 'Why the boundary fails' })).toHaveAttribute('aria-expanded', 'true');
    expect(screen.getByText(intended, { selector: 'p' })).toBeVisible();
    expect(screen.getByText(mechanism, { selector: 'p' })).toBeVisible();
    await user.click(screen.getByRole('button', { name: 'Impact and limits' }));
    expect(screen.getByText(impact, { selector: 'p' })).toBeVisible();
    expect(screen.getByText('Other account routes were not established.')).toBeVisible();
    expect(JSON.stringify(raw)).toBe(original);
  });

  it('preserves source ownership and component evidence actions outside narrative triggers', async () => {
    const user = userEvent.setup(), onEvidence = vi.fn(), raw = makeFinding();
    raw.root_causes = [{ file: 'storefront/src/a-long-component/orders.ts', start_line: 42, end_line: 49, mechanism: 'The recorded boundary is missing.' }];
    const typed = { execution_id: 'original-owner', artifact_ref: 'sast/verified-findings.json', record_id: 'C-7' };
    raw.affected_components![0].evidence_refs = [typed];
    render(<SummaryPanel finding={finding(raw)} onEvidence={onEvidence} />);
    await user.click(screen.getByRole('button', { name: 'Supporting source citations' }));
    const roots = within(screen.getByRole('table', { name: 'Root-cause locations' }));
    await user.click(roots.getByRole('button', { name: 'storefront/src/a-long-component/orders.ts:42-49' }));
    expect(onEvidence).toHaveBeenLastCalledWith('storefront/src/a-long-component/orders.ts:42-49', 'trace-owner');
    await user.click(screen.getByRole('button', { name: /^Storefront/ }));
    await user.click(screen.getByRole('button', { name: 'sast/verified-findings.json · C-7' }));
    expect(onEvidence).toHaveBeenLastCalledWith(typed, 'trace-owner');
    expect(screen.getByRole('heading', { name: 'Affected components' })).toBeVisible();
    expect(screen.getByText('POST /orders/approve')).toBeVisible();
  });

  it('keeps missing facts explicit and never invents an outcome or execution status', async () => {
    const user = userEvent.setup(), raw = makeFinding();
    delete raw.attacker; delete raw.impact; delete raw.intended_behavior; delete raw.exploitation;
    raw.root_causes = []; raw.conditions = [];
    const record = finding(); record.raw = raw;
    const { container } = render(<SummaryPanel finding={record} onEvidence={vi.fn()} />);
    expect(screen.getByRole('button', { name: 'Starting access and prerequisites' })).toHaveAccessibleDescription('Starting access was not recorded.');
    expect(screen.getByRole('button', { name: 'Why the boundary fails' })).toHaveAccessibleDescription('The exploitation mechanism was not recorded.');
    expect(screen.getByRole('button', { name: 'Supporting source citations' })).toHaveAccessibleDescription('No root-cause locations were recorded.');
    expect(screen.getByRole('button', { name: 'Why the boundary fails' })).toHaveAttribute('aria-expanded', 'true');
    expect(screen.getByText('No intended behavior recorded.')).toBeVisible();
    expect(screen.getByText('No exploitation rationale recorded.')).toBeVisible();
    expect(container.querySelector('[data-status]')).toBeNull();
  });
});
