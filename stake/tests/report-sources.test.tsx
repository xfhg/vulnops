// @vitest-environment jsdom
import { useState } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import '@testing-library/jest-dom/vitest';
import { ReportSourcesSetup, ReportSourcesSheet, type ReportSourcesProps } from '../src/features/settings/ReportSources';
import type { SourceSubmissionResult, WorkspaceSourceState } from '../src/domain/sources';

afterEach(cleanup);

function sourceState(overrides: Partial<WorkspaceSourceState> = {}): WorkspaceSourceState {
  return {
    generation: 'workspace-one', sources: [
      { inputPath: '/reports/ordinary run', runId: 'audit-one', kind: 'audit' },
      { inputPath: '/reports/advantage run', runId: 'advantage-one', kind: 'advantage' },
    ], savedPair: { ordinaryPath: '/saved/ordinary', advantagePath: '/saved/advantage' },
    origin: 'cli', loading: false, lastLoad: null, persistence: { status: 'not_applicable' }, diagnostics: [], ...overrides,
  };
}

function SheetHarness(props: ReportSourcesProps) {
  const [open, setOpen] = useState(false);
  return <><button key={props.state.generation} aria-label="Settings" onClick={() => setOpen(true)}>Settings</button><ReportSourcesSheet {...props} open={open} onOpenChange={setOpen} /></>;
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(done => { resolve = done; });
  return { promise, resolve };
}

describe('report source settings', () => {
  it('opens an accessible sheet, shows every current source, and discards an unsubmitted draft on dismissal', async () => {
    const user = userEvent.setup(), onLoad = vi.fn();
    render(<SheetHarness state={sourceState()} busy={false} onLoad={onLoad} />);
    await user.click(screen.getByRole('button', { name: 'Settings' }));
    const dialog = screen.getByRole('dialog', { name: 'Report sources' });
    expect(dialog).toHaveAccessibleDescription('Choose the ordinary and Advantage runs for this workspace.');
    expect(screen.getByLabelText('Ordinary run folder')).toHaveFocus();
    const current = within(screen.getByRole('region', { name: 'Currently loaded' }));
    expect(current.getByText('audit-one')).toBeVisible();
    expect(current.getByText('advantage-one')).toBeVisible();
    expect(current.getByText('/reports/ordinary run')).toBeVisible();
    await user.clear(screen.getByLabelText('Ordinary run folder'));
    await user.type(screen.getByLabelText('Ordinary run folder'), '/a draft');
    await user.keyboard('{Escape}');
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(screen.getByRole('button', { name: 'Settings' })).toHaveFocus();
    await user.click(screen.getByRole('button', { name: 'Settings' }));
    expect(screen.getByLabelText('Ordinary run folder')).toHaveValue('/reports/ordinary run');
    expect(onLoad).not.toHaveBeenCalled();
  });

  it('leaves ambiguous roles blank and never fills an explicit CLI gap from saved sources', () => {
    const state = sourceState({ sources: [
      { kind: 'audit', runId: 'a', inputPath: '/reports/a' },
      { kind: 'audit', runId: 'b', inputPath: '/reports/b' },
      { kind: 'advantage', runId: 'c', inputPath: '/reports/c' },
    ] });
    const { unmount } = render(<ReportSourcesSheet open onOpenChange={vi.fn()} state={state} busy={false} onLoad={vi.fn()} />);
    expect(within(screen.getByRole('region', { name: 'Currently loaded' })).getAllByRole('listitem')).toHaveLength(3);
    expect(screen.getByLabelText('Ordinary run folder')).toHaveValue('');
    expect(screen.getByLabelText('Advantage run folder')).toHaveValue('/reports/c');
    expect(screen.getByText('Multiple ordinary runs are loaded. Choose the folder to use.')).toBeVisible();
    unmount();
    render(<ReportSourcesSheet open onOpenChange={vi.fn()} state={sourceState({ sources: [{ kind: 'audit', runId: 'a', inputPath: '/only/ordinary' }] })} busy={false} onLoad={vi.fn()} />);
    expect(screen.getByLabelText('Ordinary run folder')).toHaveValue('/only/ordinary');
    expect(screen.getByLabelText('Advantage run folder')).toHaveValue('');
  });

  it('uses saved recovery paths only for empty setup and associates its field diagnostics', () => {
    render(<ReportSourcesSetup state={sourceState({ sources: [], origin: 'empty', diagnostics: ['The saved Advantage folder is unavailable.'], fieldErrors: { advantagePath: 'This report folder has moved.' } })} busy={false} onLoad={vi.fn()} />);
    expect(screen.getByRole('heading', { level: 1, name: 'Load your reports' })).toBeVisible();
    expect(screen.queryByRole('region', { name: 'Currently loaded' })).not.toBeInTheDocument();
    expect(screen.getByLabelText('Ordinary run folder')).toHaveValue('/saved/ordinary');
    expect(screen.getByLabelText('Advantage run folder')).toHaveValue('/saved/advantage');
    expect(screen.getByLabelText('Advantage run folder')).toHaveAttribute('aria-invalid', 'true');
    expect(screen.getByLabelText('Advantage run folder')).toHaveAccessibleDescription(/This report folder has moved/);
    expect(screen.getByText('The saved Advantage folder is unavailable.')).toBeVisible();
    expect(screen.queryByText('0 findings')).not.toBeInTheDocument();
  });

  it('validates keyboard submission, retains input, and focuses the affected field', async () => {
    const user = userEvent.setup(), onLoad = vi.fn();
    render(<ReportSourcesSetup state={sourceState({ sources: [], savedPair: null, origin: 'empty' })} busy={false} onLoad={onLoad} />);
    await user.type(screen.getByLabelText('Ordinary run folder'), 'relative/ordinary');
    await user.type(screen.getByLabelText('Advantage run folder'), '/reports/advantage');
    await user.keyboard('{Enter}');
    expect(onLoad).not.toHaveBeenCalled();
    expect(screen.getByLabelText('Ordinary run folder')).toHaveFocus();
    expect(screen.getByLabelText('Ordinary run folder')).toHaveValue('relative/ordinary');
    expect(screen.getByLabelText('Ordinary run folder')).toHaveAccessibleDescription(/full absolute path/);
    expect(screen.getByRole('alert')).toHaveTextContent('Check the marked folder paths');
  });

  it('submits literal absolute paths with spaces and retains server errors for correction', async () => {
    const user = userEvent.setup();
    const onLoad = vi.fn().mockResolvedValue({ status: 'failed', message: 'The pair could not be admitted.', fieldErrors: { advantagePath: 'This folder contains an ordinary report.' } });
    render(<ReportSourcesSetup state={sourceState({ sources: [], savedPair: null, origin: 'empty' })} busy={false} onLoad={onLoad} />);
    const ordinary = screen.getByLabelText('Ordinary run folder'), advantage = screen.getByLabelText('Advantage run folder');
    await user.type(ordinary, '/reports/ordinary with spaces ');
    await user.type(advantage, 'C:\\reports\\advantage with spaces');
    await user.click(screen.getByRole('button', { name: 'Load reports' }));
    expect(onLoad).toHaveBeenCalledExactlyOnceWith({ ordinaryPath: '/reports/ordinary with spaces ', advantagePath: 'C:\\reports\\advantage with spaces' }, 'workspace-one');
    expect(advantage).toHaveValue('C:\\reports\\advantage with spaces');
    expect(advantage).toHaveFocus();
    expect(advantage).toHaveAccessibleDescription(/contains an ordinary report/);
    expect(screen.getByRole('alert')).toHaveTextContent('The pair could not be admitted.');
  });

  it('prevents duplicate submissions while allowing a running load to continue after closing', async () => {
    const user = userEvent.setup(), result = deferred<SourceSubmissionResult>();
    const onLoad = vi.fn(() => result.promise);
    const { rerender } = render(<SheetHarness state={sourceState()} busy={false} onLoad={onLoad} />);
    await user.click(screen.getByRole('button', { name: 'Settings' }));
    await user.dblClick(screen.getByRole('button', { name: 'Load reports' }));
    fireEvent.submit(screen.getByRole('form', { name: 'Report source folders' }));
    expect(onLoad).toHaveBeenCalledTimes(1);
    expect(screen.getByRole('button', { name: 'Load reports' })).toBeDisabled();
    expect(screen.getByText(/loading will continue/)).toBeVisible();
    expect(screen.getByRole('button', { name: 'Close settings' })).toBeEnabled();
    rerender(<SheetHarness state={sourceState({ loading: true })} busy onLoad={onLoad} />);
    await user.click(screen.getByRole('button', { name: 'Close settings' }));
    await user.click(screen.getByRole('button', { name: 'Settings' }));
    expect(screen.getByRole('button', { name: 'Load reports' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Close settings' })).toHaveFocus();
    await act(async () => result.resolve({ status: 'loaded' }));
    expect(onLoad).toHaveBeenCalledTimes(1);
  });

  it('preserves a stale draft until explicit reconciliation and submits only the refreshed generation', async () => {
    const user = userEvent.setup(), onLoad = vi.fn().mockResolvedValue({ status: 'loaded' });
    const { rerender } = render(<ReportSourcesSheet open onOpenChange={vi.fn()} state={sourceState()} busy={false} onLoad={onLoad} />);
    await user.clear(screen.getByLabelText('Ordinary run folder'));
    await user.type(screen.getByLabelText('Ordinary run folder'), '/my draft');
    const next = sourceState({ generation: 'workspace-two', sources: [
      { inputPath: '/new/ordinary', runId: 'audit-new', kind: 'audit' },
      { inputPath: '/new/advantage', runId: 'advantage-new', kind: 'advantage' },
    ] });
    rerender(<ReportSourcesSheet open onOpenChange={vi.fn()} state={next} busy={false} onLoad={onLoad} />);
    expect(screen.getByLabelText('Ordinary run folder')).toHaveValue('/my draft');
    expect(screen.getByLabelText('Ordinary run folder')).toBeEnabled();
    expect(screen.getByRole('button', { name: 'Load reports' })).toBeDisabled();
    fireEvent.submit(screen.getByRole('form', { name: 'Report source folders' }));
    expect(onLoad).not.toHaveBeenCalled();
    await user.click(screen.getByRole('button', { name: 'Use current sources' }));
    expect(screen.getByLabelText('Ordinary run folder')).toHaveValue('/new/ordinary');
    expect(screen.getByLabelText('Advantage run folder')).toHaveValue('/new/advantage');
    expect(screen.queryByText('The workspace changed')).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Load reports' }));
    expect(onLoad).toHaveBeenCalledExactlyOnceWith({ ordinaryPath: '/new/ordinary', advantagePath: '/new/advantage' }, 'workspace-two');
  });

  it('restores focus to the replacement Settings action after another tab changes the workspace', async () => {
    const user = userEvent.setup(), onLoad = vi.fn();
    const { rerender } = render(<SheetHarness state={sourceState()} busy={false} onLoad={onLoad} />);
    const originalOpener = screen.getByRole('button', { name: 'Settings' });
    await user.click(originalOpener);
    rerender(<SheetHarness state={sourceState({ generation: 'workspace-two' })} busy={false} onLoad={onLoad} />);
    expect(originalOpener).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Close settings' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(screen.getByRole('button', { name: 'Settings' })).toHaveFocus();
    expect(onLoad).not.toHaveBeenCalled();
  });

  it('keeps an uncertain response disabled until authoritative reconciliation without retrying', async () => {
    const user = userEvent.setup(), onLoad = vi.fn().mockResolvedValue({ status: 'pending', message: 'Waiting for the active load.' });
    const { rerender } = render(<ReportSourcesSetup state={sourceState()} busy={false} onLoad={onLoad} />);
    await user.click(screen.getByRole('button', { name: 'Load reports' }));
    expect(screen.getByRole('button', { name: 'Load reports' })).toBeDisabled();
    rerender(<ReportSourcesSetup state={sourceState()} busy={false} onLoad={onLoad} />);
    expect(screen.getByRole('button', { name: 'Load reports' })).toBeDisabled();
    rerender(<ReportSourcesSetup state={sourceState({ lastLoad: { id: 'finished-load', status: 'failed', generation: 'workspace-one', message: 'The ordinary publication is unavailable.', fieldErrors: { ordinaryPath: 'The folder is no longer available.' }, persistence: { status: 'not_applicable' } } })} busy={false} onLoad={onLoad} />);
    await waitFor(() => expect(screen.getByRole('button', { name: 'Load reports' })).toBeEnabled());
    expect(screen.getByLabelText('Ordinary run folder')).toHaveFocus();
    expect(screen.getByLabelText('Ordinary run folder')).toHaveAccessibleDescription(/no longer available/);
    expect(onLoad).toHaveBeenCalledTimes(1);
  });

  it('separates session-only persistence feedback from validation failures', () => {
    render(<ReportSourcesSheet open onOpenChange={vi.fn()} state={sourceState({ persistence: { status: 'session_only', message: 'The reports loaded, but the settings directory is not writable.' } })} busy={false} onLoad={vi.fn()} />);
    expect(screen.getByText('Loaded for this session').closest('[role=status]')).toHaveTextContent('settings directory is not writable');
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    expect(screen.getByLabelText('Ordinary run folder')).toHaveAttribute('aria-invalid', 'false');
    expect(screen.getByRole('button', { name: 'Load reports' })).toBeEnabled();
  });
});
