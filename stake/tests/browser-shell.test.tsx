// @vitest-environment jsdom
import { useSyncExternalStore } from 'react';
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import '@testing-library/jest-dom/vitest';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import App from '../src/app/App';
import { BrowserCoordinator, type BrowserSnapshot } from '../src/data/browser-coordinator';
import { normalizeWorkspace, summarizeWorkspace } from '../src/domain';
import { makePublication } from './fixtures/bundles';

const { mockWorkspace } = vi.hoisted(() => ({ mockWorkspace: vi.fn() }));
vi.mock('../src/app/useWorkspace', () => ({ useWorkspace: mockWorkspace }));
vi.mock('../src/data/runtime-mode', () => ({ browserMode: true }));

const coordinators: BrowserCoordinator[] = [];
const empty = (): BrowserSnapshot => ({ generation: 'empty', workspace: null, phase: 'empty', error: '', ownCompletion: 0 });
const file = () => new File(['Synthetic ZIP placeholder; admission is separately tested.'], 'assessment.zip', { type: 'application/zip' });
function loaded(generation = 'saved'): BrowserSnapshot {
  const publications = [makePublication({ runId: 'ordinary-zero', findings: [] }), makePublication({ runId: 'advantage-zero', kind: 'advantage', baselineId: 'ordinary-zero', findings: [] })];
  return { ...empty(), generation, phase: 'ready', workspace: { ...summarizeWorkspace(normalizeWorkspace(publications)), generation },
    archive: { name: 'zero-findings.zip', size: 4096, importedAt: '2026-11-05T00:00:00Z', roots: [
      { root: 'ordinary', runId: 'ordinary-zero', kind: 'audit' }, { root: 'advantage', runId: 'advantage-zero', kind: 'advantage' },
    ] } };
}
function runtime(snapshot: BrowserSnapshot) {
  return { browser: snapshot, workspace: snapshot.workspace, sources: null, busy: Boolean(snapshot.progress) || snapshot.phase === 'restoring', loadError: '', notice: '', ownCompletion: snapshot.ownCompletion,
    importArchive: vi.fn(async (_file: File, _generation: string) => {}), removeArchive: vi.fn(async (_generation: string) => {}), cancelImport: vi.fn(), refresh: vi.fn(async () => {}), loadSources: vi.fn(),
    dataSource: { finding: vi.fn(), page: vi.fn(), reference: vi.fn(), evidence: vi.fn() } };
}
function deferred() { let resolve!: () => void; const promise = new Promise<void>(done => { resolve = done; }); return { promise, resolve }; }
beforeEach(() => { mockWorkspace.mockReset(); window.history.replaceState({}, '', '/#?view=overview'); });
afterEach(() => {
  cleanup(); for (const coordinator of coordinators.splice(0)) coordinator.dispose();
  vi.restoreAllMocks(); vi.unstubAllGlobals(); document.documentElement.classList.remove('dark');
  window.history.replaceState({}, '', '/'); localStorage.clear();
});

describe('browser workspace shell', () => {
  it('distinguishes first restore and saved-state recovery from a fresh empty overview', async () => {
    let current = runtime({ ...empty(), phase: 'restoring' }); mockWorkspace.mockImplementation(() => current);
    const user = userEvent.setup(); const { rerender } = render(<App />);
    expect(screen.getByRole('status')).toHaveTextContent('Restoring assessment');
    expect(screen.getByRole('button', { name: 'Load assessment' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Settings' })).toBeEnabled();
    expect(screen.queryByRole('navigation', { name: 'Main navigation' })).not.toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Assessment overview' })).not.toBeInTheDocument();

    current = runtime({ ...empty(), phase: 'recovery', generation: 'unreadable-saved', error: 'The saved ZIP is not readable. Choose a supported archive or remove this selection.' }); rerender(<App />);
    expect(screen.getByRole('status')).toHaveTextContent('Saved assessment needs attention');
    await user.click(screen.getByRole('button', { name: 'Open Settings' }));
    const dialog = screen.getByRole('dialog', { name: 'Assessment archive' });
    expect(within(dialog).getByRole('alert')).toHaveTextContent('The saved ZIP is not readable');
    expect(within(dialog).getByRole('button', { name: 'Remove local assessment' })).toBeEnabled();
    expect(within(dialog).getByLabelText('Assessment ZIP')).toBeEnabled();
    await user.keyboard('{Escape}');

    current = runtime(empty()); rerender(<App />);
    expect(screen.queryByRole('status')).not.toBeInTheDocument();
    expect(screen.queryByRole('heading')).not.toBeInTheDocument();
    expect(screen.queryByLabelText('Search findings')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Load assessment' })).toBeEnabled();
  });

  it('shows valid zero-finding reports, archive metadata and removal without treating them as an empty import', async () => {
    let current = runtime(loaded()); mockWorkspace.mockImplementation(() => current);
    const user = userEvent.setup(); const { rerender } = render(<App />);
    expect(screen.getByRole('heading', { name: 'Assessment overview' })).toBeInTheDocument();
    expect(screen.getByRole('navigation', { name: 'Main navigation' })).toBeInTheDocument();
    const metrics = screen.getByLabelText('Assessed outcome metrics');
    expect(metrics.querySelectorAll('.overview-metric-value')).toHaveLength(4);
    for (const value of metrics.querySelectorAll('.overview-metric-value')) expect(value).toHaveTextContent(/^0$/);
    await user.click(screen.getByRole('button', { name: 'Settings' }));
    const dialog = screen.getByRole('dialog', { name: 'Assessment archive' });
    const archive = within(dialog).getByRole('region', { name: 'Current archive' });
    expect(archive).toHaveTextContent('zero-findings.zip');
    expect(archive).toHaveTextContent('ordinary-zero'); expect(archive).toHaveTextContent('advantage-zero');
    expect(within(dialog).getByRole('button', { name: 'Replace assessment' })).toBeDisabled();
    await user.click(within(dialog).getByRole('button', { name: 'Remove local assessment' }));
    expect(current.removeArchive).toHaveBeenCalledExactlyOnceWith('saved');
    current = runtime({ ...empty(), generation: 'removed-tombstone', ownCompletion: 1, lastOperation: 'remove' }); rerender(<App />);
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(screen.queryByRole('navigation', { name: 'Main navigation' })).not.toBeInTheDocument();
    expect(screen.queryByRole('status')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Load assessment' })).toBeEnabled();
  });

  it('keeps theme toggles, navigation and Settings operable when theme storage reads and writes are denied', async () => {
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => { throw new DOMException('Denied', 'SecurityError'); });
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => { throw new DOMException('Denied', 'SecurityError'); });
    mockWorkspace.mockReturnValue(runtime(loaded())); const user = userEvent.setup(); render(<App />);
    const dark = screen.getByRole('button', { name: 'Use dark theme' }); dark.focus();
    await user.keyboard('{Enter}'); expect(document.documentElement).toHaveClass('dark');
    await user.click(screen.getByRole('button', { name: 'Use light theme' })); expect(document.documentElement).not.toHaveClass('dark');
    const findings = within(screen.getByRole('navigation', { name: 'Main navigation' })).getByRole('button', { name: /^Findings/ });
    findings.focus(); await user.keyboard('{Enter}');
    expect(screen.getByRole('heading', { name: 'Findings, in context.' })).toBeInTheDocument();
    expect(window.location.hash).toContain('view=findings');
    screen.getByRole('button', { name: 'Settings' }).focus(); await user.keyboard('{Enter}');
    expect(screen.getByRole('dialog', { name: 'Assessment archive' })).toBeInTheDocument();
    await user.keyboard('{Escape}'); await waitFor(() => expect(screen.getByRole('button', { name: 'Settings' })).toHaveFocus());
  });

  it('retains import progress when Settings closes and reopens, then focuses the loaded overview without a success banner', async () => {
    const pending = deferred(); const submit = vi.fn(() => pending.promise);
    let current = { ...runtime(empty()), importArchive: submit }; mockWorkspace.mockImplementation(() => current);
    const user = userEvent.setup(); const { rerender } = render(<App />);
    screen.getByRole('button', { name: 'Settings' }).focus(); await user.keyboard('{Enter}');
    const zip = file(); await user.upload(screen.getByLabelText('Assessment ZIP'), zip);
    screen.getByRole('button', { name: 'Load assessment' }).focus(); await user.keyboard('{Enter}');
    expect(submit).toHaveBeenCalledExactlyOnceWith(zip, 'empty');
    current = { ...runtime({ ...empty(), progress: { phase: 'reading', completed: 1, total: 8 } }), importArchive: submit }; rerender(<App />);
    await user.keyboard('{Escape}'); await waitFor(() => expect(screen.getByRole('button', { name: 'Settings' })).toHaveFocus());
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument(); expect(screen.getByRole('status')).toHaveTextContent('Reading archive');
    current = { ...runtime({ ...empty(), progress: { phase: 'validating', completed: 1, total: 2 } }), importArchive: submit }; rerender(<App />);
    await user.keyboard('{Enter}');
    let dialog = screen.getByRole('dialog', { name: 'Assessment archive' });
    expect(within(dialog).getByRole('status')).toHaveTextContent('Validating reports');
    expect(within(dialog).getByRole('button', { name: 'Cancel import' })).toBeEnabled();
    expect(within(dialog).getByLabelText('Assessment ZIP')).toBeDisabled();
    expect(within(dialog).getByRole('button', { name: 'Load assessment' })).toBeDisabled();
    current = { ...runtime({ ...empty(), progress: { phase: 'saving', completed: 0 } }), importArchive: submit }; rerender(<App />);
    dialog = screen.getByRole('dialog', { name: 'Assessment archive' });
    expect(within(dialog).queryByRole('button', { name: 'Cancel import' })).not.toBeInTheDocument();
    expect(within(dialog).getByRole('status')).toHaveTextContent('Saving cannot be cancelled');
    await act(async () => { pending.resolve(); });
    current = { ...runtime({ ...loaded(), ownCompletion: 1, lastOperation: 'import' }), importArchive: submit }; rerender(<App />);
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Assessment overview' })).toHaveFocus());
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(document.querySelector('.workspace-notice')).not.toBeInTheDocument();
    expect(submit).toHaveBeenCalledOnce();
  });

  it('opens Settings with the ZIP dropped on the empty shell and submits the exact file by keyboard', async () => {
    const current = runtime(empty()); mockWorkspace.mockReturnValue(current); const user = userEvent.setup(); render(<App />);
    const zip = file();
    fireEvent.drop(document.querySelector('.browser-empty-shell')!, { dataTransfer: { files: [zip], types: ['Files'] } });
    const dialog = screen.getByRole('dialog', { name: 'Assessment archive' });
    expect(within(dialog).getByText('assessment.zip')).toBeInTheDocument();
    within(dialog).getByRole('button', { name: 'Load assessment' }).focus(); await user.keyboard('{Enter}');
    expect(current.importArchive).toHaveBeenCalledExactlyOnceWith(zip, 'empty');
  });

  it('announces a bounded import failure instead of displaying arbitrary parser output', async () => {
    const unsafeMessage = 'PRIVATE_ARCHIVE_DIAGNOSTIC '.repeat(400);
    const store = { read: vi.fn(async () => ({ revision: 'empty' })), revision: vi.fn(async () => 'empty'), commit: vi.fn(), remove: vi.fn(), close: vi.fn() };
    const coordinator = new BrowserCoordinator({ store, channel: false, openArchive: async () => { throw new Error(unsafeMessage); } }); coordinators.push(coordinator);
    await coordinator.initialize();
    mockWorkspace.mockImplementation(() => {
      const snapshot = useSyncExternalStore(coordinator.subscribe, coordinator.getSnapshot);
      return { ...runtime(snapshot), importArchive: (archive: File, generation: string) => coordinator.importArchive(archive, archive.name, generation) };
    });
    const user = userEvent.setup(); render(<App />);
    await user.click(screen.getByRole('button', { name: 'Load assessment' }));
    await user.upload(screen.getByLabelText('Assessment ZIP'), file());
    await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Load assessment' }));
    const alert = await screen.findByRole('alert');
    expect(alert.textContent?.length).toBeLessThanOrEqual(500);
    expect(alert).not.toHaveTextContent('PRIVATE_ARCHIVE_DIAGNOSTIC');
    expect(alert).toHaveTextContent('Choose a supported report ZIP');
    expect(alert).toHaveFocus(); expect(store.commit).not.toHaveBeenCalled();
    await user.keyboard('{Escape}'); expect(screen.getByRole('button', { name: 'Settings' })).toHaveFocus();
  });
});
