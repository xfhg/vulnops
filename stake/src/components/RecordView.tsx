import type { ReactNode } from 'react';
import { FileCode2, ArrowUpRight } from 'lucide-react';
import { human } from '../app/state';

export type EvidenceHandler = (reference: unknown, runId: string) => void;
export function EvidenceRefs({ refs, runId, onEvidence }: { refs?: unknown[]; runId: string; onEvidence: EvidenceHandler }) {
  if (!refs?.length) return null;
  return <div className="evidence-refs">{refs.map((ref, i) => {
    const label = typeof ref === 'string' ? ref : ref && typeof ref === 'object' ? String((ref as Record<string, unknown>).artifact_ref ?? (ref as Record<string, unknown>).file ?? 'Evidence reference') : 'Evidence reference';
    return <button key={i} className="evidence-chip" onClick={() => onEvidence(ref, runId)} title={label}><FileCode2 size={13} /><span>{label}</span><ArrowUpRight size={12} /></button>;
  })}</div>;
}
export function RecordView({ value, depth = 0 }: { value: unknown; depth?: number }): ReactNode {
  if (value === null || value === undefined || value === '') return <span className="muted">Unknown</span>;
  if (typeof value === 'boolean') return <span>{value ? 'Yes' : 'No'}</span>;
  if (typeof value !== 'object') return <span className="record-text">{String(value)}</span>;
  if (Array.isArray(value)) return value.length ? <ul className="record-list">{value.map((item, i) => <li key={i}><RecordView value={item} depth={depth + 1} /></li>)}</ul> : <span className="muted">None recorded</span>;
  return <dl className={'record-fields ' + (depth ? 'record-fields-nested' : '')}>{Object.entries(value).map(([key, child]) => <div key={key}><dt>{human(key)}</dt><dd><RecordView value={child} depth={depth + 1} /></dd></div>)}</dl>;
}
export function Prose({ children }: { children: unknown }) { return <p className="prose">{typeof children === 'string' ? children : children == null ? 'Not recorded.' : String(children)}</p>; }
