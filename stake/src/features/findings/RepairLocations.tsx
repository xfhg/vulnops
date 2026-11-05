import { lazy, Suspense } from 'react';
import { ArrowUp, FileCode2 } from 'lucide-react';
import type { FindingRecord, RepairAction } from '../../domain/types';
import { Button } from '../../components/ui';
import { CopySourceCitation, RawDisclosure, sourceReference } from './DossierPrimitives';
import { repairSourceExamples } from './repair-source';

const CodeBlock = lazy(() => import('../../components/CodeBlock'));

export default function RepairLocations({ finding, action, onActionSelect }: {
  finding: FindingRecord; action: RepairAction; onActionSelect?: (id: string) => void;
}) {
  if (!action.locations?.length) return <p className="dossier-empty">No source locations recorded.</p>;
  return <div className="repair-location-guides">{action.locations.map((location, index) => {
    const reference = sourceReference(location), file = typeof location.file === 'string' ? location.file : '';
    const name = file.split('/').at(-1) || 'File not recorded';
    const start = location.line ?? location.start_line;
    const line = typeof start === 'number' ? `${start}${typeof location.end_line === 'number' && location.end_line !== start ? `–${location.end_line}` : ''}` : 'Not recorded';
    const notes = [...new Set([location.mechanism, location.description].filter((text): text is string => typeof text === 'string' && Boolean(text)))];
    const examples = repairSourceExamples(finding, action, location);
    const other = Object.fromEntries(Object.entries(location).filter(([key]) => !['file', 'line', 'start_line', 'end_line', 'scope', 'mechanism', 'description'].includes(key)));
    return <section key={index} tabIndex={-1} data-detail-record={JSON.stringify(['repair-location', action.id, index])} className="repair-location-guide" aria-label={`Repair location ${name}:${line}`}>
      <header><div><span className="repair-location-kicker">CHANGE LOCATION {index + 1} · {action.id}</span><h5><FileCode2 size={16} aria-hidden="true"/>{name}<span>Line {line}</span></h5></div>{onActionSelect && <Button variant="ghost" size="sm" onClick={() => onActionSelect(action.id)}><ArrowUp size={13} aria-hidden="true"/>Read full implementation change</Button>}</header>
      <div className="repair-location-path"><code>{file || 'Source path not recorded'}</code>{reference && <CopySourceCitation reference={reference}/>}</div>
      <div className="repair-location-context"><h6>Why this location matters</h6>{location.scope && <code>{location.scope}</code>}{notes.length ? notes.map(note => <p key={note}>{note}</p>) : <p className="dossier-empty">No location-specific explanation recorded. The implementation change applies to this recorded target.</p>}</div>
      <div className="repair-location-excerpts"><h6>Recorded source</h6>{examples.length ? examples.map(example => <div key={example.id}><p className="repair-location-excerpt-label">Original excerpt · {example.id}</p><Suspense fallback={<pre className="code-content">{example.content}</pre>}><CodeBlock example={example}/></Suspense><div className="repair-location-citations">{(example.evidence_refs ?? []).map((ref, refIndex) => <code key={refIndex}>{typeof ref === 'string' ? ref : `${ref.execution_id} · ${ref.artifact_ref}`}</code>)}</div></div>) : <p className="dossier-empty">No source excerpt is recorded for this location. Use the file path and line above in your checkout.</p>}</div>
      <RawDisclosure value={other} label="Additional location detail"/>
    </section>;
  })}</div>;
}
