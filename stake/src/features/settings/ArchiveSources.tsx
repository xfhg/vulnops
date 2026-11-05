import { useEffect, useRef, useState } from 'react';
import * as Dialog from '@radix-ui/react-dialog';
import { Archive, LoaderCircle, RefreshCw, Settings, Trash2, Upload, X } from 'lucide-react';
import { Badge, Button } from '../../components/ui';
import type { BrowserArchiveMetadata } from '../../data/browser-store';
import './settings.css';
import './archive-sources.css';

export interface ArchiveState {
  generation: string; archive?: BrowserArchiveMetadata; error: string;
  phase: 'restoring' | 'empty' | 'ready' | 'recovery';
  progress?: { phase: string; completed: number; total?: number };
  persisted?: boolean; storageEstimate?: { usage?: number; quota?: number };
}
export interface ArchiveSourcesProps {
  state: ArchiveState; onImport(file: File, generation: string): Promise<void>;
  onRemove(generation: string): Promise<void>; onCancel(): void;
}
export const archiveSize = (bytes: number) => bytes < 1024 * 1024 ? `${Math.ceil(bytes / 1024)} KiB` : `${(bytes / 1024 / 1024).toFixed(1)} MiB`;
export function importLabel(state: ArchiveState) {
  return state.progress?.phase === 'saving' ? 'Saving assessment…' : state.progress?.phase === 'validating' ? 'Validating reports…' : state.progress ? 'Reading archive…' : state.phase === 'restoring' ? 'Restoring assessment…' : '';
}

export function ArchiveSourceForm({ state, onImport, onRemove, onCancel, initialFiles }: ArchiveSourcesProps & { initialFiles?: File[] }) {
  const [file, setFile] = useState<File | null>(null);
  const [generation, setGeneration] = useState(state.generation);
  const [error, setError] = useState('');
  const [working, setWorking] = useState(false);
  const [dragging, setDragging] = useState(false);
  const input = useRef<HTMLInputElement>(null);
  const errorRef = useRef<HTMLParagraphElement>(null);
  const lock = useRef(false);
  const busy = working || Boolean(state.progress) || state.phase === 'restoring';
  const stale = generation !== state.generation;
  function choose(files: File[]) {
    if (busy) return;
    setError('');
    if (files.length !== 1 || !/\.zip$/i.test(files[0].name)) { setFile(null); setError('Choose one ZIP containing the ordinary and Advantage run folders.'); return; }
    setFile(files[0]);
  }
  useEffect(() => { if (initialFiles?.length) choose(initialFiles); }, [initialFiles]);
  useEffect(() => { if (error) errorRef.current?.focus(); }, [error]);
  async function operation(action: () => Promise<void>) {
    if (lock.current || busy || stale) return;
    lock.current = true; setWorking(true); setError('');
    try { await action(); }
    catch (failure) { setError(failure instanceof Error ? failure.message : 'The assessment could not be loaded.'); }
    finally { lock.current = false; setWorking(false); }
  }
  return <div className="archive-settings">
    {state.archive && <section aria-label="Current archive" className="sources-current">
      <div className="sources-section-heading"><h3>Current assessment</h3><Badge>Browser storage</Badge></div>
      <div className="archive-file"><Archive size={22} /><div><strong>{state.archive.name}</strong><span>{archiveSize(state.archive.size)} · Imported {new Date(state.archive.importedAt).toLocaleString()}</span></div></div>
      <ul>{state.archive.roots.map(root => <li key={root.runId}><Badge>{root.kind === 'audit' ? 'Ordinary' : 'Advantage'}</Badge><code>{root.runId}</code></li>)}</ul>
      <p className="small muted">{state.persisted ? 'Persistent storage granted.' : 'Saved in this browser; clearing site data removes this assessment.'}{state.storageEstimate?.usage !== undefined && ` Site storage: ${archiveSize(state.storageEstimate.usage)}.`}</p>
    </section>}
    {stale && <div role="alert" className="sources-notice"><RefreshCw size={18} /><div><strong>The assessment changed in another tab</strong><p>Your selected ZIP has been kept. Review the current assessment before retrying.</p><Button variant="outline" size="sm" disabled={busy} onClick={() => { setGeneration(state.generation); setError(''); }}>Use current assessment</Button></div></div>}
    {(error || state.error) && <p role="alert" ref={errorRef} tabIndex={-1} className="sources-notice">{error || state.error}</p>}
    <form aria-label="Assessment archive" aria-busy={busy} onSubmit={event => { event.preventDefault(); if (file) void operation(() => onImport(file, generation)); }}>
      <div className={'archive-drop ' + (dragging ? 'dragging' : '')} onDragOver={event => { event.preventDefault(); setDragging(true); }} onDragLeave={() => setDragging(false)} onDrop={event => { event.preventDefault(); setDragging(false); choose(Array.from(event.dataTransfer.files)); }}>
        <Upload size={26} aria-hidden="true" /><strong>{file ? file.name : 'Drop your assessment ZIP'}</strong>
        <span>{file ? archiveSize(file.size) : 'One archive with the ordinary and Advantage run folders.'}</span>
        <label className="archive-picker">Choose ZIP<input ref={input} type="file" accept=".zip,application/zip" aria-label="Assessment ZIP" disabled={busy} onChange={event => choose(Array.from(event.target.files ?? []))} /></label>
      </div>
      <p className="small muted archive-hint">Both run folders must include their report and final-verification files. Files are processed and saved in this browser.</p>
      {state.progress && <div role="status" aria-live="polite" className="archive-progress"><LoaderCircle className="spinner" size={17}/><span>{importLabel(state)}{state.progress.phase === 'saving' ? ' Saving cannot be cancelled.' : ' You can close Settings while this finishes.'}</span></div>}
      <div className="archive-actions">
        {state.progress && state.progress.phase !== 'saving' && <Button variant="outline" onClick={onCancel}>Cancel import</Button>}
        <Button type="submit" disabled={!file || busy || stale}><Upload size={16}/>{state.archive ? 'Replace assessment' : 'Load assessment'}</Button>
      </div>
    </form>
    {(state.archive || state.phase === 'recovery') && <div className="archive-remove"><div><strong>Remove local assessment</strong><p>Clear this site’s saved reports from this browser.</p></div><Button variant="outline" disabled={busy || stale} onClick={() => void operation(() => onRemove(generation))}><Trash2 size={16}/>Remove local assessment</Button></div>}
  </div>;
}

export function ArchiveSourcesSheet({ open, onOpenChange, initialFiles, ...props }: ArchiveSourcesProps & { open: boolean; onOpenChange(open: boolean): void; initialFiles?: File[] }) {
  return <Dialog.Root open={open} onOpenChange={onOpenChange}><Dialog.Portal><Dialog.Overlay className="sources-sheet-overlay"/><Dialog.Content className="sources-sheet" onCloseAutoFocus={event => { event.preventDefault(); document.querySelector<HTMLButtonElement>('button[aria-label="Settings"]')?.focus(); }}>
    <header className="sources-sheet-heading"><div><p className="eyebrow">Settings</p><Dialog.Title>Assessment archive</Dialog.Title><Dialog.Description>Load an ordinary and Advantage report pair from one ZIP.</Dialog.Description></div><Dialog.Close asChild><Button variant="ghost" size="icon" aria-label="Close settings"><X size={19}/></Button></Dialog.Close></header>
    <div className="sources-sheet-body">{open && <ArchiveSourceForm {...props} initialFiles={initialFiles}/>}</div>
  </Dialog.Content></Dialog.Portal></Dialog.Root>;
}

export function EmptyBrowserWorkspace({ state, onSettings, onDrop }: { state: ArchiveState; onSettings(): void; onDrop(files: File[]): void }) {
  const [dragging, setDragging] = useState(false);
  return <div className={'browser-empty-shell ' + (dragging ? 'is-dragging' : '')} onDragOver={event => { if (event.dataTransfer.types.includes('Files')) { event.preventDefault(); setDragging(true); } }} onDragLeave={event => { if (!event.currentTarget.contains(event.relatedTarget as Node | null)) setDragging(false); }} onDrop={event => { event.preventDefault(); setDragging(false); onDrop(Array.from(event.dataTransfer.files)); }}>
    <a className="skip-link" href="#main" onClick={event => { event.preventDefault(); document.getElementById('main')?.focus(); }}>Skip to content</a>
    <header className="browser-empty-header"><a className="brand" href="#?view=overview"><img className="brand-logo" src="/brand/vulnops-icon.svg" alt="VulnOps Doberman"/><span className="brand-name"><strong>VulnOps</strong><span className="brand-label">@stake</span></span></a><div><Button onClick={onSettings} disabled={state.phase === 'restoring'}><Upload size={16}/>Load assessment</Button><Button variant="ghost" size="icon" onClick={onSettings} aria-label="Settings"><Settings size={19}/></Button></div></header>
    <main id="main" tabIndex={-1} aria-label="Empty assessment overview">
      {dragging && <div className="empty-drop-hint"><Upload size={24}/>Drop assessment ZIP</div>}
      {(state.phase === 'restoring' || state.progress) && <button className="empty-operation" onClick={onSettings} role="status"><LoaderCircle size={16} className="spinner"/>{importLabel(state)}</button>}
      {state.phase === 'recovery' && <div className="empty-recovery" role="status"><span>Saved assessment needs attention.</span><Button variant="outline" size="sm" onClick={onSettings}>Open Settings</Button></div>}
    </main>
  </div>;
}
