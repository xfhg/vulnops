import { GitCommitHorizontal, ShieldCheck, ShieldX } from 'lucide-react';
import type { FindingRecord } from '../../domain/types';
import type { EvidenceHandler } from '../../components/RecordView';
import { human, dateLabel } from '../../app/state';
import { Badge } from '../../components/ui';
import { DetailFacts, DetailSection, EvidenceList, NarrativeList, RawDisclosure, SourceLocations } from './DossierPrimitives';
import './review-panels.css';

export function VerificationPanel({ finding, onEvidence }: { finding: FindingRecord; onEvidence: EvidenceHandler }) {
  const checks = finding.raw.remediation?.verification_checks ?? [];
  return <DetailSection title="Fix verification" description="Expected attack rejection and legitimate behavior, with each check’s recorded status." aside={<Badge>{checks.length} {checks.length === 1 ? 'check' : 'checks'}</Badge>}>
    <div className="review-checks">{checks.length ? checks.map((check, index) => <article tabIndex={-1} data-detail-record={JSON.stringify(['check', check.id])} className="verification-card review-check" key={`${check.id}-${index}`}>
      <header><div><span className="dossier-label">CHECK {String(index + 1).padStart(2, '0')} · {check.id || 'ID not recorded'}</span><h3>{check.description || 'Verification check'}</h3></div><Badge tone={check.status === 'proposed' ? 'amber' : 'neutral'}>{human(check.status)}</Badge></header>
      <div className="review-expectations"><section><h4><ShieldX size={15}/>Attack rejection</h4><NarrativeList value={check.attack_expected} empty="Expected rejection not recorded."/></section><section><h4><ShieldCheck size={15}/>Legitimate operation</h4><NarrativeList value={check.legitimate_expected} empty="Expected legitimate behavior not recorded."/></section></div>
      <EvidenceList refs={check.evidence_refs} runId={finding.runId} onEvidence={onEvidence} label="Check evidence"/>
      <RawDisclosure value={check} label="Complete verification check"/>
    </article>) : <p className="dossier-empty">No verification checks recorded.</p>}</div>
  </DetailSection>;
}

export function EvidencePanel({ finding, onEvidence }: { finding: FindingRecord; onEvidence: EvidenceHandler }) {
  const raw = finding.raw, scope = finding.scope, review = raw.verification;
  return <div className="dossier-stack">
    <div className="dossier-two-column">
      <DetailSection title="Assessed scope"><DetailFacts items={[
        ['Owning execution', finding.runId], ['Assessment', scope?.assessment_id ?? finding.scopeId ?? 'Not recorded'],
        ['Source view', human(finding.sourceView)], ['Assessment started', dateLabel(scope?.started_at)],
      ]}/><RawDisclosure value={scope} label="Complete assessment scope"/></DetailSection>
      <DetailSection title="Independent review"><DetailFacts items={[
        ['Evidence level', human(review?.level)], ['Reviewer', review?.actor ?? 'Not recorded'], ['Model', review?.model ?? 'Not recorded'],
      ]}/><EvidenceList refs={[
        ...(raw.independent_verification_ref ? [raw.independent_verification_ref] : []),
        ...(review?.source_validation_refs ?? []), ...(review?.reproduction_ref ? [review.reproduction_ref] : []),
      ]} runId={finding.runId} onEvidence={onEvidence} label="Review references"/><RawDisclosure value={review} label="Complete review record"/></DetailSection>
    </div>
    <DetailSection title="Repository revisions" aside={<GitCommitHorizontal size={18} aria-hidden="true"/>}>
      {scope?.repositories?.length ? <ul className="review-repositories">{scope.repositories.map((repository, index) => <li key={index}><div><strong>{repository.name || repository.path || 'Repository name not recorded'}</strong>{repository.path && repository.path !== repository.name && <small>{repository.path}</small>}</div><code>{repository.commit || 'Revision not recorded'}</code></li>)}</ul> : <p className="dossier-empty">No repository revisions recorded in this assessment scope.</p>}
    </DetailSection>
    <DetailSection title="Trace and provenance" description="Source locations in their recorded order." aside={<Badge>{raw.trace?.length ?? 0} locations</Badge>}>
      <SourceLocations locations={raw.trace ?? []} runId={finding.runId} onEvidence={onEvidence} label="Recorded source trace"/>
      <EvidenceList refs={raw.source_refs} runId={finding.runId} onEvidence={onEvidence} label="Contributing records"/>
      <RawDisclosure value={raw} label="Contributors and complete accepted record"/>
    </DetailSection>
  </div>;
}
