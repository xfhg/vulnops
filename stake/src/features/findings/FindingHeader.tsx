import { useEffect, useId, useRef, useState } from 'react';
import { ArrowRight, FileCode2, ShieldCheck, Wrench } from 'lucide-react';
import type { FindingRecord } from '../../domain/types';
import { dateLabel, human } from '../../app/state';
import { Badge, Button } from '../../components/ui';
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from '../../components/ui/data-display';
import './finding-header.css';

export default function FindingHeader({ finding, onRepair, onReproduce }: { finding: FindingRecord; onRepair?: () => void; onReproduce?: () => void }) {
  const summary = finding.attackSummary || finding.impact || 'This record preserves an unresolved or non-promoted assessment outcome.';
  const [expanded, setExpanded] = useState(false);
  const [overflows, setOverflows] = useState(false);
  const summaryRef = useRef<HTMLParagraphElement>(null);
  const summaryId = useId();
  useEffect(() => { setExpanded(false); }, [finding.key]);
  useEffect(() => {
    const paragraph = summaryRef.current;
    if (!paragraph) return;
    const measure = () => setOverflows(paragraph.scrollHeight > parseFloat(getComputedStyle(paragraph).lineHeight) * 3 + 1);
    measure();
    if (typeof ResizeObserver === 'undefined') return;
    const observer = new ResizeObserver(measure);
    observer.observe(paragraph);
    return () => observer.disconnect();
  }, [summary]);
  return <header className="finding-header">
    <div className="finding-header-grid">
      <div className="finding-header-main">
        <div className="detail-badges"><span className="finding-identifier mono">{finding.id}</span>
          <Badge tone={finding.severity}>{finding.severity}</Badge>
          <Badge tone={finding.cohort === 'confirmed' ? 'neutral' : 'amber'}>{human(finding.cohort)}</Badge>
          {finding.classification && <Badge>{human(finding.classification)}</Badge>}
          {finding.origin === 'historical' && <Badge>Historical</Badge>}
        </div>
        <h1>{finding.title}</h1>
        <div className="finding-summary">
          <p id={summaryId} ref={summaryRef} className={'finding-summary-text ' + (expanded ? 'expanded' : '')}>{summary}</p>
          {overflows && <Button variant="ghost" size="sm" className="finding-summary-toggle" aria-expanded={expanded} aria-controls={summaryId} onClick={() => setExpanded(value => !value)}>{expanded ? 'Show less' : 'Read full summary'}</Button>}
        </div>
        {onRepair && <div className="finding-header-actions"><Button size="sm" onClick={onRepair}><Wrench size={14}/>Read repair instructions<ArrowRight size={14}/></Button><Button variant="ghost" size="sm" onClick={onReproduce}>Read reproduction steps</Button></div>}
      </div>
      <dl className="finding-header-facts" aria-label="Finding facts">
        <div className="finding-fact-wide"><dt><FileCode2 size={14} aria-hidden="true"/>Repository</dt><dd className="finding-repositories">{finding.repositories.length ? finding.repositories.map(repository => <span key={repository}>{repository}</span>) : 'Unknown'}</dd></div>
        <div className="finding-fact-wide"><dt><ShieldCheck size={14} aria-hidden="true"/>Verification</dt><dd>{human(finding.verificationLevel)}</dd></div>
        <div className="finding-fact-count"><dt>Recorded steps</dt><dd>{finding.stepCount}</dd></div>
        <div className="finding-fact-count"><dt>Proposed repairs</dt><dd>{finding.repairCount}</dd></div>
      </dl>
    </div>
    <Accordion type="single" collapsible className="finding-context">
      <AccordionItem value="context"><AccordionTrigger aria-label="Assessment context"><span>Assessment context</span><small>{human(finding.sourceView)} source</small></AccordionTrigger>
        <AccordionContent><dl className="finding-context-facts">
          <div><dt>Owning execution</dt><dd>{finding.runId}</dd></div>
          <div><dt>Assessment scope</dt><dd>{finding.scopeId || 'Unknown'}</dd></div>
          <div><dt>Source view</dt><dd>{human(finding.sourceView)}</dd></div>
          <div><dt>Assessment started</dt><dd>{dateLabel(finding.scope?.started_at)}</dd></div>
        </dl></AccordionContent>
      </AccordionItem>
    </Accordion>
  </header>;
}
