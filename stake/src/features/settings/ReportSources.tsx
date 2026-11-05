import { useEffect, useId, useLayoutEffect, useRef, useState, type FormEvent } from 'react';
import * as Dialog from '@radix-ui/react-dialog';
import { AlertCircle, ArrowRight, FolderOpen, LoaderCircle, RefreshCw, X } from 'lucide-react';
import { Badge, Button } from '../../components/ui';
import type { SourceFieldErrors, SourcePair, SourceSubmissionResult, WorkspaceSourceState } from '../../domain/sources';
import './settings.css';

export interface ReportSourcesProps {
  state: WorkspaceSourceState;
  busy: boolean;
  onLoad: (pair: SourcePair, expectedGeneration: string) => Promise<SourceSubmissionResult>;
}

function sourceDraft(state: WorkspaceSourceState): SourcePair {
  if (!state.sources.length) return state.savedPair ? { ...state.savedPair } : { ordinaryPath: '', advantagePath: '' };
  const ordinary = state.sources.filter(source => source.kind === 'audit');
  const advantage = state.sources.filter(source => source.kind === 'advantage');
  return { ordinaryPath: ordinary.length === 1 ? ordinary[0].inputPath : '', advantagePath: advantage.length === 1 ? advantage[0].inputPath : '' };
}

function validatePaths(pair: SourcePair): SourceFieldErrors {
  const errors: SourceFieldErrors = {};
  for (const field of ['ordinaryPath', 'advantagePath'] as const) {
    const path = pair[field];
    if (!path.trim()) errors[field] = 'Enter the absolute path to this run folder.';
    else if (/[\u0000-\u001f\u007f]/.test(path)) errors[field] = 'The folder path cannot contain control characters.';
    else if (path.length > 16384) errors[field] = 'The folder path must be at most 16,384 characters.';
    else if (!/^(?:\/|[A-Za-z]:[\\/]|\\\\[^\\/]+[\\/][^\\/]+)/.test(path)) errors[field] = 'Use a full absolute path on the server machine, without quotes or ~.';
  }
  return errors;
}

function SourceStatus({ state }: { state: WorkspaceSourceState }) {
  return <>
    {state.diagnostics.length > 0 && <div className="sources-notice" role="status">
      <AlertCircle size={17} aria-hidden="true" />
      <div><strong>Source status</strong><ul>{state.diagnostics.map((message, index) => <li key={index}>{message}</li>)}</ul></div>
    </div>}
    {state.persistence.status === 'session_only' && <div className="sources-notice sources-persistence" role="status">
      <AlertCircle size={17} aria-hidden="true" />
      <div><strong>Loaded for this session</strong><p>{state.persistence.message || 'The reports are available, but their paths could not be remembered for the next launch.'}</p></div>
    </div>}
    {state.persistence.status === 'remembered' && <p className="sources-remembered" role="status">Paths remembered for the next launch.</p>}
  </>;
}

function CurrentSources({ state }: { state: WorkspaceSourceState }) {
  if (!state.sources.length) return null;
  return <section className="sources-current" aria-label="Currently loaded">
    <div className="sources-section-heading"><h3>Currently loaded</h3><span>{state.sources.length} {state.sources.length === 1 ? 'run' : 'runs'}</span></div>
    <ul>{state.sources.map((source, index) => <li key={`${source.runId}-${index}`}>
      <div className="sources-current-meta"><Badge>{source.kind === 'audit' ? 'Ordinary' : 'Advantage'}</Badge><span>{source.runId}</span></div>
      <code>{source.inputPath}</code>
    </li>)}</ul>
  </section>;
}

/** Shared by the first-launch page and settings sheet; draft ownership stays local. */
function ReportSourceForm({ state, busy, onLoad }: ReportSourcesProps) {
  const id = useId();
  const [draft, setDraft] = useState<SourcePair>(() => sourceDraft(state));
  const [draftGeneration, setDraftGeneration] = useState(state.generation);
  const [errors, setErrors] = useState<SourceFieldErrors>(() => state.fieldErrors ?? {});
  const [message, setMessage] = useState<string | null>(null);
  const [messageKind, setMessageKind] = useState<'error' | 'status'>('error');
  const [submitting, setSubmitting] = useState(false);
  const [focusError, setFocusError] = useState(0);
  const [pending, setPending] = useState<{ generation: string; loadId: string | null; observedBusy: boolean } | null>(null);
  const submissionLock = useRef(false);
  const ordinaryInput = useRef<HTMLInputElement>(null);
  const advantageInput = useRef<HTMLInputElement>(null);
  const errorSummary = useRef<HTMLDivElement>(null);
  const stale = state.generation !== draftGeneration;
  const loading = busy || state.loading || submitting || pending !== null;

  useEffect(() => {
    if (!pending) return;
    if (busy || state.loading) {
      if (!pending.observedBusy) setPending({ ...pending, observedBusy: true });
      return;
    }
    const reconciled = pending.observedBusy || state.generation !== pending.generation || (state.lastLoad?.id ?? null) !== pending.loadId;
    if (reconciled) {
      setPending(null);
      if (state.lastLoad?.status === 'failed') {
        setErrors(state.lastLoad.fieldErrors ?? {});
        setMessage(state.lastLoad.message);
        setMessageKind('error');
        setFocusError(value => value + 1);
      } else {
        setMessage(null);
      }
    }
  }, [busy, pending, state.generation, state.lastLoad, state.loading]);

  useLayoutEffect(() => {
    if (!focusError) return;
    if (errors.ordinaryPath) ordinaryInput.current?.focus();
    else if (errors.advantagePath) advantageInput.current?.focus();
    else errorSummary.current?.focus();
  }, [focusError]);

  function update(field: keyof SourcePair, value: string) {
    setDraft(current => ({ ...current, [field]: value }));
    setErrors(current => ({ ...current, [field]: undefined }));
  }

  function reconcile() {
    setDraft(sourceDraft(state));
    setDraftGeneration(state.generation);
    setErrors(state.fieldErrors ?? {});
    setMessage(null);
    ordinaryInput.current?.focus();
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (loading || stale || submissionLock.current) return;
    const fieldErrors = validatePaths(draft);
    if (Object.keys(fieldErrors).length) {
      setErrors(fieldErrors);
      setMessage('Check the marked folder paths before loading reports.');
      setMessageKind('error');
      setFocusError(value => value + 1);
      return;
    }
    submissionLock.current = true;
    setSubmitting(true);
    setErrors({});
    setMessage(null);
    try {
      const result = await onLoad({ ...draft }, draftGeneration);
      if (result.status === 'failed') {
        setErrors(result.fieldErrors ?? {});
        setMessage(result.message || 'The reports could not be loaded. Review the folder paths and try again.');
        setMessageKind('error');
        setFocusError(value => value + 1);
      } else if (result.status === 'pending') {
        setPending({ generation: draftGeneration, loadId: state.lastLoad?.id ?? null, observedBusy: false });
        setMessage(result.message || 'Checking whether the report load completed…');
        setMessageKind('status');
      } else {
        setMessage(result.message || 'Reports loaded.');
        setMessageKind('status');
      }
    } catch {
      // An interrupted response does not prove that the server rejected the load.
      setPending({ generation: draftGeneration, loadId: state.lastLoad?.id ?? null, observedBusy: false });
      setMessage('The load response could not be confirmed. Checking workspace status…');
      setMessageKind('status');
    } finally {
      submissionLock.current = false;
      setSubmitting(false);
    }
  }

  const ambiguousOrdinary = state.sources.filter(source => source.kind === 'audit').length > 1;
  const ambiguousAdvantage = state.sources.filter(source => source.kind === 'advantage').length > 1;
  return <div className="report-source-content">
    <CurrentSources state={state} />
    <SourceStatus state={state} />
    <form className="report-source-form" onSubmit={submit} noValidate aria-label="Report source folders" aria-busy={loading}>
      {stale && <div className="sources-notice sources-stale" role="alert">
        <RefreshCw size={17} aria-hidden="true" /><div><strong>The workspace changed</strong><p>Another selection is now loaded. Your draft has been kept. Use the current sources or close and reopen settings before loading.</p><Button variant="outline" size="sm" onClick={reconcile} disabled={loading}>Use current sources</Button></div>
      </div>}
      {message && <div ref={errorSummary} tabIndex={-1} role={messageKind === 'error' ? 'alert' : 'status'} className={`sources-notice sources-result sources-result-${messageKind}`}>
        {messageKind === 'error' && <AlertCircle size={17} aria-hidden="true" />}<p>{message}</p>
      </div>}
      <div className="sources-fields">
        <div className="sources-field">
          <label htmlFor={`${id}-ordinary`}>Ordinary run folder</label>
          <input ref={ordinaryInput} id={`${id}-ordinary`} name="ordinaryPath" type="text" value={draft.ordinaryPath} onChange={event => update('ordinaryPath', event.target.value)} disabled={loading} required autoComplete="off" autoCapitalize="none" spellCheck={false} placeholder="/absolute/path/to/ordinary-run" aria-invalid={!!errors.ordinaryPath} aria-describedby={`${id}-ordinary-hint${errors.ordinaryPath ? ` ${id}-ordinary-error` : ''}`} />
          <p id={`${id}-ordinary-hint`} className="sources-field-hint">{ambiguousOrdinary ? 'Multiple ordinary runs are loaded. Choose the folder to use.' : 'The completed ordinary audit run, including its report folder.'}</p>
          {errors.ordinaryPath && <p id={`${id}-ordinary-error`} className="sources-field-error">{errors.ordinaryPath}</p>}
        </div>
        <div className="sources-field">
          <label htmlFor={`${id}-advantage`}>Advantage run folder</label>
          <input ref={advantageInput} id={`${id}-advantage`} name="advantagePath" type="text" value={draft.advantagePath} onChange={event => update('advantagePath', event.target.value)} disabled={loading} required autoComplete="off" autoCapitalize="none" spellCheck={false} placeholder="/absolute/path/to/advantage-run" aria-invalid={!!errors.advantagePath} aria-describedby={`${id}-advantage-hint${errors.advantagePath ? ` ${id}-advantage-error` : ''}`} />
          <p id={`${id}-advantage-hint`} className="sources-field-hint">{ambiguousAdvantage ? 'Multiple Advantage runs are loaded. Choose the folder to use.' : 'The completed Advantage run, including its report folder.'}</p>
          {errors.advantagePath && <p id={`${id}-advantage-error`} className="sources-field-error">{errors.advantagePath}</p>}
        </div>
      </div>
      <div className="sources-path-help"><FolderOpen size={16} aria-hidden="true" /><p>Enter full absolute paths on the machine running VulnOps @stake, such as <code>/Users/you/reports/ordinary-run</code> or <code>C:\reports\ordinary-run</code>. Paste them without surrounding quotes or <code>~</code>.</p></div>
      <footer className="sources-form-footer">
        <p>Loading replaces the reports for every tab connected to this local workspace. Successful paths are remembered for the next launch.</p>
        <Button type="submit" disabled={loading || stale}>{loading ? <LoaderCircle className="spinner" size={16} aria-hidden="true" /> : <ArrowRight size={16} aria-hidden="true" />}Load reports</Button>
      </footer>
      <div className="sources-loading" role="status" aria-live="polite">{loading && <><LoaderCircle className="spinner" size={15} aria-hidden="true" /><span>{pending ? 'Confirming the report load…' : 'Loading report publications…'} You can close settings; loading will continue.</span></>}</div>
    </form>
  </div>;
}

export function ReportSourcesSheet({ open, onOpenChange, ...props }: ReportSourcesProps & { open: boolean; onOpenChange: (value: boolean) => void }) {
  const opener = useRef<HTMLElement | null>(null);
  const content = useRef<HTMLDivElement>(null);
  return <Dialog.Root open={open} onOpenChange={onOpenChange}>
    <Dialog.Portal><Dialog.Overlay className="sources-sheet-overlay" /><Dialog.Content ref={content} className="sources-sheet" onOpenAutoFocus={event => {
      opener.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
      event.preventDefault();
      const target = content.current?.querySelector<HTMLInputElement>('input:not(:disabled)')
        ?? content.current?.querySelector<HTMLButtonElement>('button[aria-label="Close settings"]');
      (target ?? content.current)?.focus();
    }} onCloseAutoFocus={event => {
      event.preventDefault();
      // A cross-tab workspace switch replaces the shell while keeping this draft open.
      const target = opener.current?.isConnected ? opener.current : document.querySelector<HTMLButtonElement>('button[aria-label="Settings"]:not(:disabled)');
      target?.focus();
    }}>
      <header className="sources-sheet-heading"><div><p className="eyebrow">Settings</p><Dialog.Title>Report sources</Dialog.Title><Dialog.Description>Choose the ordinary and Advantage runs for this workspace.</Dialog.Description></div><Dialog.Close asChild><Button variant="ghost" size="icon" aria-label="Close settings"><X size={19} aria-hidden="true" /></Button></Dialog.Close></header>
      <div className="sources-sheet-body">{open && <ReportSourceForm {...props} />}</div>
    </Dialog.Content></Dialog.Portal>
  </Dialog.Root>;
}

export function ReportSourcesSetup(props: ReportSourcesProps) {
  return <div className="sources-setup">
    <header className="sources-setup-heading"><div className="sources-setup-icon"><FolderOpen size={25} strokeWidth={1.5} aria-hidden="true" /></div><p className="eyebrow">REPORT SOURCES</p><h1 tabIndex={-1}>Load your reports</h1><p>Open a completed ordinary audit and an Advantage run to explore their findings, attack paths and repair guidance.</p></header>
    <section className="sources-setup-card" aria-label="Choose report folders"><ReportSourceForm {...props} /></section>
  </div>;
}
