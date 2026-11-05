import { useState, type ReactNode } from 'react';
import { ArrowUpRight, Check, Copy, FileCode2 } from 'lucide-react';
import type { SourceLocation } from '../../domain/types';
import { human } from '../../app/state';
import { Card, CardContent, CardHeader } from '../../components/ui/data-display';
import { RecordView, type EvidenceHandler } from '../../components/RecordView';
import './dossier.css';

export function DetailSection({ title, description, aside, children, className = '' }: {
  title: string; description?: string; aside?: ReactNode; children: ReactNode; className?: string;
}) {
  return <section className={'dossier-section ' + className} aria-label={title}><Card><CardHeader className="dossier-section-heading"><div><h2>{title}</h2>{description && <p>{description}</p>}</div>{aside}</CardHeader><CardContent>{children}</CardContent></Card></section>;
}

const present = (value: unknown) => value !== undefined && value !== null && value !== '' && !(Array.isArray(value) && !value.length);
export function RawDisclosure({ value, label = 'Complete recorded detail' }: { value: unknown; label?: string }) {
  const [open, setOpen] = useState(false);
  if (!present(value) || (typeof value === 'object' && !Array.isArray(value) && !Object.keys(value as object).length)) return null;
  return <details className="dossier-raw" onToggle={event => setOpen(event.currentTarget.open)}><summary>{label}</summary>{open && <div><RecordView value={value}/></div>}</details>;
}

export function NarrativeList({ value, empty = 'None recorded.', depth = 0 }: { value: unknown; empty?: string; depth?: number }): ReactNode {
  if (!present(value)) return <p className="dossier-empty">{empty}</p>;
  if (Array.isArray(value)) return <ul className="dossier-list">{value.map((item, index) => <li key={index}><NarrativeList value={item} empty={empty} depth={depth + 1}/></li>)}</ul>;
  if (typeof value !== 'object') return <p className="dossier-copy">{typeof value === 'boolean' ? value ? 'Yes' : 'No' : String(value)}</p>;
  if (depth > 2) return <RawDisclosure value={value} label="Additional recorded detail"/>;
  return <dl className="dossier-facts">{Object.entries(value as Record<string, unknown>).map(([key, item]) => <div key={key}><dt>{human(key)}</dt><dd><NarrativeList value={item} empty="Not recorded." depth={depth + 1}/></dd></div>)}</dl>;
}

function referenceLabel(reference: unknown) {
  if (typeof reference === 'string') return reference;
  if (reference && typeof reference === 'object') {
    const ref = reference as Record<string, unknown>;
    return String(ref.artifact_ref ?? ref.file ?? 'Evidence reference') + (ref.source_id || ref.record_id || ref.selector ? ` · ${ref.source_id ?? ref.record_id ?? ref.selector}` : '');
  }
  return 'Evidence reference';
}
export function EvidenceList({ refs, runId, onEvidence, label = 'Supporting evidence' }: { refs?: unknown[]; runId: string; onEvidence: EvidenceHandler; label?: string }) {
  const unique = [...new Map((refs ?? []).map(reference => [JSON.stringify(reference), reference])).values()];
  if (!unique.length) return null;
  return <div className="dossier-evidence" aria-label={label}><span className="dossier-label">{label} <span>{unique.length}</span></span><ul>{unique.map((reference, index) => {
    const full = referenceLabel(reference);
    const short = full.split('/').at(-1) || full;
    const typed = reference && typeof reference === 'object' ? reference as Record<string, unknown> : {};
    return <li key={index}><button type="button" title={full} aria-label={full} onClick={() => onEvidence(reference, runId)}><FileCode2 size={14} aria-hidden="true"/><span><strong>{short}</strong><small>{full.slice(0, Math.max(0, full.length - short.length)) || (typeof typed.execution_id === 'string' ? typed.execution_id : 'Recorded reference')}</small></span><ArrowUpRight size={13} aria-hidden="true"/></button></li>;
  })}</ul></div>;
}

export function sourceReference(location: SourceLocation): string | null {
  if (typeof location.file !== 'string' || !location.file) return null;
  const line = location.line ?? location.start_line;
  return location.file + (typeof line === 'number' ? `:${line}${typeof location.end_line === 'number' && location.end_line !== line ? `-${location.end_line}` : ''}` : '');
}

export function CopySourceCitation({ reference }: { reference: string }) {
  const [state, setState] = useState<'idle' | 'copying' | 'copied' | 'error'>('idle');
  async function copy() {
    setState('copying');
    try {
      if (!navigator.clipboard?.writeText) throw new Error('Clipboard unavailable');
      await navigator.clipboard.writeText(reference);
      setState('copied');
    } catch { setState('error'); }
  }
  return <div className="dossier-source-copy">
    <button type="button" aria-label={`Copy citation ${reference}`} title={reference} disabled={state === 'copying'} onClick={() => void copy()}>
      {state === 'copied' ? <Check size={12} aria-hidden="true"/> : <Copy size={12} aria-hidden="true"/>}
      {state === 'copied' ? 'Copied' : state === 'copying' ? 'Copying…' : 'Copy citation'}
    </button>
    <span className="dossier-copy-status" role="status" aria-live="polite" aria-atomic="true">{state === 'copied' ? 'Source citation copied.' : state === 'error' ? 'Could not copy. Select the citation below to copy manually.' : ''}</span>
    {state === 'error' && <code className="dossier-copy-fallback" tabIndex={0}>{reference}</code>}
  </div>;
}

export function SourceLocations({ locations, runId, onEvidence, label = 'Source locations', showContext = false }: { locations: SourceLocation[]; runId: string; onEvidence: EvidenceHandler; label?: string; showContext?: boolean }) {
  if (!locations.length) return <p className="dossier-empty">No source locations recorded.</p>;
  return <div className="dossier-source-table"><table aria-label={label}><thead><tr><th>File</th><th>Line</th><th>Recorded context</th></tr></thead><tbody>{locations.map((location, index) => {
    const reference = sourceReference(location);
    const file = typeof location.file === 'string' ? location.file : '';
    const name = file.split('/').at(-1) || 'File not recorded';
    const line = location.line ?? location.start_line;
    const notes = [location.mechanism, location.description].filter((value, i, all): value is string => typeof value === 'string' && Boolean(value) && all.indexOf(value) === i);
    const other = Object.fromEntries(Object.entries(location).filter(([key]) => !['file', 'line', 'start_line', 'end_line', 'scope', 'mechanism', 'description'].includes(key)));
    const hasContext = notes.length > 0 || Object.keys(other).length > 0;
    return <tr key={index}><td data-label="File">{typeof location.kind === 'string' && <span className="dossier-trace-kind">{String(index + 1).padStart(2, '0')} · {human(location.kind)}</span>}<button type="button" className="dossier-source-link" title={reference || name} aria-label={reference || name} disabled={!reference} onClick={() => reference && onEvidence(reference, runId)}><FileCode2 size={15} aria-hidden="true"/><span><strong>{name}</strong><small>{file.slice(0, Math.max(0, file.length - name.length))}</small></span><ArrowUpRight size={13} aria-hidden="true"/></button>{reference && <CopySourceCitation key={`${runId}:${reference}`} reference={reference}/>}</td>
      <td data-label="Line"><span className="dossier-line">{typeof line === 'number' ? `${line}${typeof location.end_line === 'number' && location.end_line !== line ? `–${location.end_line}` : ''}` : 'Not recorded'}</span></td>
      <td data-label="Recorded context">{hasContext ? showContext ? <div className="dossier-source-context-open">{location.scope && <strong className="dossier-source-scope">{location.scope}</strong>}{notes.map(note => <p className="dossier-copy" key={note}>{note}</p>)}<RawDisclosure value={other} label="Additional location detail"/></div> : <details className="dossier-source-context"><summary>{location.scope && <strong>{location.scope}</strong>}{notes[0] && <span className="dossier-source-preview">{notes[0]}</span>}<span className="dossier-source-more">View context</span></summary><div>{notes.map(note => <p className="dossier-copy" key={note}>{note}</p>)}<RawDisclosure value={other} label="Additional location detail"/></div></details> : <span className={location.scope ? 'dossier-source-scope' : 'dossier-empty'}>{location.scope || 'No context recorded'}</span>}</td></tr>;
  })}</tbody></table></div>;
}

export function DetailFacts({ items }: { items: Array<[string, ReactNode]> }) {
  return <dl className="dossier-facts">{items.map(([label, value]) => <div key={label}><dt>{label}</dt><dd>{value ?? <span className="dossier-empty">Not recorded</span>}</dd></div>)}</dl>;
}
