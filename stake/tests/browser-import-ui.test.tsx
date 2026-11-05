// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ArchiveSourceForm, EmptyBrowserWorkspace, type ArchiveState } from '../src/features/settings/ArchiveSources';
const empty: ArchiveState = { generation: 'empty', phase: 'empty', error: '' };
afterEach(() => { cleanup(); window.history.replaceState({}, '', '/'); });
const file = () => new File(['synthetic'], 'assessment.zip', { type: 'application/zip' });

describe('browser archive interface', () => {
  it('keeps an empty overview free of report content and preserves fragment selections on skip', () => {
    window.history.replaceState({}, '', '/#?view=findings&finding=owned');
    const open = vi.fn();
    render(<EmptyBrowserWorkspace state={empty} onSettings={open} onDrop={vi.fn()}/>);
    expect(screen.queryByRole('navigation')).toBeNull();
    expect(screen.queryByRole('heading')).toBeNull();
    expect(screen.queryByLabelText('Search findings')).toBeNull();
    fireEvent.click(screen.getByRole('link', { name: 'Skip to content' }));
    expect(window.location.hash).toContain('finding=owned');
    expect(document.activeElement?.id).toBe('main');
    fireEvent.click(screen.getByRole('button', { name: 'Load assessment' }));
    expect(open).toHaveBeenCalledOnce();
  });
  it('imports one keyboard-selected ZIP with the draft generation and retains a bounded failure', async () => {
    const submit = vi.fn().mockRejectedValue(new Error('Required report Markdown is missing.'));
    render(<ArchiveSourceForm state={empty} onImport={submit} onRemove={vi.fn()} onCancel={vi.fn()}/>);
    const zip = file(); await userEvent.upload(screen.getByLabelText('Assessment ZIP'), zip);
    await userEvent.click(screen.getByRole('button', { name: 'Load assessment' }));
    await waitFor(() => expect(screen.getByRole('alert').textContent).toContain('Markdown is missing'));
    expect(submit).toHaveBeenCalledWith(zip, 'empty');
    expect(document.activeElement).toBe(screen.getByRole('alert'));
  });
  it('rejects multiple files and keeps stale drafts until explicit reconciliation', async () => {
    const submit = vi.fn(); const props = { onImport: submit, onRemove: vi.fn(), onCancel: vi.fn() };
    const { rerender } = render(<ArchiveSourceForm state={empty} {...props}/>);
    fireEvent.drop(screen.getByText('Drop your assessment ZIP').parentElement!, { dataTransfer: { files: [file(), file()] } });
    expect(screen.getByRole('alert').textContent).toContain('one ZIP');
    await userEvent.upload(screen.getByLabelText('Assessment ZIP'), file());
    rerender(<ArchiveSourceForm state={{ ...empty, generation: 'other' }} {...props}/>);
    expect((screen.getByRole('button', { name: 'Load assessment' }) as HTMLButtonElement).disabled).toBe(true);
    await userEvent.click(screen.getByRole('button', { name: 'Use current assessment' }));
    await userEvent.click(screen.getByRole('button', { name: 'Load assessment' }));
    expect(submit).toHaveBeenCalledWith(expect.any(File), 'other');
  });
  it('offers cancellation while reading but announces non-cancellable saving', () => {
    const cancel = vi.fn(); const props = { onImport: vi.fn(), onRemove: vi.fn(), onCancel: cancel };
    const { rerender } = render(<ArchiveSourceForm state={{ ...empty, progress: { phase: 'reading', completed: 0 } }} {...props}/>);
    fireEvent.click(screen.getByRole('button', { name: 'Cancel import' })); expect(cancel).toHaveBeenCalledOnce();
    rerender(<ArchiveSourceForm state={{ ...empty, progress: { phase: 'saving', completed: 0 } }} {...props}/>);
    expect(screen.queryByRole('button', { name: 'Cancel import' })).toBeNull();
    expect(screen.getByRole('status').textContent).toContain('cannot be cancelled');
  });
  it('prevents duplicate submissions while a selected archive is being prepared', async () => {
    let finish!: () => void; const submit = vi.fn(() => new Promise<void>(resolve => { finish = resolve; }));
    render(<ArchiveSourceForm state={empty} onImport={submit} onRemove={vi.fn()} onCancel={vi.fn()}/>);
    await userEvent.upload(screen.getByLabelText('Assessment ZIP'), file());
    fireEvent.submit(screen.getByRole('form', { name: 'Assessment archive' }));
    fireEvent.submit(screen.getByRole('form', { name: 'Assessment archive' }));
    expect(submit).toHaveBeenCalledOnce();
    await act(async () => finish());
  });
});
