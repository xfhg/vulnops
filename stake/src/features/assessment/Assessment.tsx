import { useState, type ReactNode } from 'react';
import { ArrowRight, ArrowUpRight, BookOpen, Braces, CalendarDays, ChevronLeft, ChevronRight, Database, FileJson, FileText, Fingerprint, GitBranch, Info, Layers, ListChecks, Search, ShieldCheck } from 'lucide-react';
import type { AssessmentSummary, RepositoryRecord } from '../../domain/types';
import { Badge, Button, Empty, Tabs, TabsContent, TabsList, TabsTrigger } from '../../components/ui';
import { Card, CardContent, CardDescription, CardHeader, CardTitle, Accordion, AccordionItem, AccordionTrigger, AccordionContent, Separator } from '../../components/ui/data-display';
import { EvidenceRefs, RecordView, type EvidenceHandler } from '../../components/RecordView';
import { dateLabel, human } from '../../app/state';
import { accountingTotals, cohortsFor, count, countLabel, investigationCount, record, rows, text, titleCase } from './model';
import './assessment.css';

type Tab = 'overview' | 'scope' | 'questions' | 'evidence';
const tabLabels: Array<[Tab, string, typeof Layers]> = [['overview', 'Overview', Layers], ['scope', 'Source scope', GitBranch], ['questions', 'Open questions', ListChecks], ['evidence', 'Evidence', FileJson]];
const kindLabel = (a: AssessmentSummary) => a.kind === 'audit' ? 'Ordinary audit' : 'Advantage';
const short = (value: string, limit = 140) => value.length > limit ? value.slice(0, limit - 1) + '…' : value;

function Panel({ title, description, children, className = '', aside }: { title: string; description?: string; children: ReactNode; className?: string; aside?: ReactNode }) {
  return <Card className={'asmt-panel ' + className}><CardHeader className="asmt-panel-heading"><div><CardTitle>{title}</CardTitle>{description && <CardDescription>{description}</CardDescription>}</div>{aside}</CardHeader><CardContent>{children}</CardContent></Card>;
}
function Facts({ items }: { items: Array<[string, ReactNode]> }) {
  return <dl className="asmt-facts">{items.map(([label, value]) => <div key={label}><dt>{label}</dt><dd>{value ?? <span className="asmt-unknown">Unknown</span>}</dd></div>)}</dl>;
}
function NumberCard({ label, value, detail, accent = false }: { label: string; value: number | null; detail: string; accent?: boolean }) {
  return <div className={'asmt-number-card' + (accent ? ' asmt-number-accent' : '')}><span>{label}</span><strong className={value === null ? 'asmt-number-unknown' : ''}>{countLabel(value)}</strong><small>{detail}</small></div>;
}

function RecordedItems({ items, runId, onEvidence, noun = 'records' }: { items: unknown[]; runId: string; onEvidence: EvidenceHandler; noun?: string }) {
  const [page, setPage] = useState(0), size = 6;
  const activePage = Math.min(page, Math.max(0, Math.ceil(items.length / size) - 1));
  if (!items.length) return <p className="asmt-empty-inline">No {noun} included in this publication.</p>;
  return <div className="asmt-records"><Accordion type="multiple" className="asmt-record-accordion">{items.slice(activePage * size, (activePage + 1) * size).map((item, offset) => {
    const index = activePage * size + offset, data = record(item), resolution = record(data.resolution);
    const identity = text(data.id) ?? text(data.finding_id) ?? text(data.question_id) ?? text(data.objective_id) ?? text(data.baseline_id) ?? text(data.evidence_id);
    const narrative = text(item) ?? text(data.reason) ?? text(data.explanation) ?? text(data.missing_fact) ?? text(resolution.reason) ?? text(resolution.missing_fact) ?? text(data.success_condition);
    const heading = text(data.title) ?? identity ?? (narrative ? short(narrative, 100) : `Recorded item ${index + 1}`);
    const status = text(data.status) ?? text(data.disposition) ?? text(data.outcome) ?? text(resolution.outcome);
    const refs = [...rows(data.evidence_refs), ...(data.evidence_ref ? [data.evidence_ref] : []), ...(data.reference ? [data.reference] : [])];
    const missing = text(data.missing_fact) ?? text(resolution.missing_fact), next = text(data.next_action) ?? text(resolution.next_action);
    return <AccordionItem value={`record-${index}`} key={index} className="asmt-record-item"><AccordionTrigger className="asmt-record-trigger"><span><span className="asmt-record-title">{heading}</span>{identity && narrative && <span className="asmt-record-preview">{short(narrative)}</span>}</span>{status && <Badge className="asmt-status-label">{human(status)}</Badge>}</AccordionTrigger><AccordionContent><div className="asmt-record-content">
      {narrative && <p>{narrative}</p>}{(missing || next) && <Facts items={[...(missing ? [['Missing fact', missing] as [string, ReactNode]] : []), ...(next ? [['Next action', next] as [string, ReactNode]] : [])]}/>}
      {Array.isArray(data.finding_ids) && data.finding_ids.length > 0 && <div className="asmt-related"><span>Related findings</span>{data.finding_ids.map(id => <code key={String(id)}>{String(id)}</code>)}</div>}
      <EvidenceRefs refs={refs} runId={runId} onEvidence={onEvidence}/>
      {typeof item === 'object' && <details className="asmt-raw-detail"><summary>Complete record</summary><div className="asmt-raw-scroll"><RecordView value={item}/></div></details>}
    </div></AccordionContent></AccordionItem>;
  })}</Accordion>{items.length > size && <div className="asmt-pagination"><span>{activePage * size + 1}–{Math.min((activePage + 1) * size, items.length)} of {items.length} {noun}</span><div><Button variant="ghost" size="icon" aria-label={`Previous ${noun}`} disabled={activePage === 0} onClick={() => setPage(activePage - 1)}><ChevronLeft size={16}/></Button><Button variant="ghost" size="icon" aria-label={`Next ${noun}`} disabled={(activePage + 1) * size >= items.length} onClick={() => setPage(activePage + 1)}><ChevronRight size={16}/></Button></div></div>}</div>;
}

function RepositoryTable({ repositories }: { repositories: RepositoryRecord[] }) {
  if (!repositories.length) return <p className="asmt-empty-inline">Repository and revision metadata were not recorded.</p>;
  return <div className="asmt-table-scroll"><table className="asmt-repository-table"><thead><tr><th>Repository</th><th>Source prefix</th><th>Assessed revision</th></tr></thead><tbody>{repositories.map((r, i) => <tr key={String(r.path ?? i)}><td><span className="asmt-repo-name"><Database size={15}/>{r.name ?? r.path ?? 'Unknown repository'}</span></td><td><code>{r.path ?? 'Unknown'}</code></td><td>{r.commit ? <code className="asmt-revision">{r.commit}</code> : <span className="asmt-unknown">Unknown</span>}</td></tr>)}</tbody></table></div>;
}
function BaselinePanel({ assessment: a, onEvidence }: { assessment: AssessmentSummary; onEvidence: EvidenceHandler }) {
  return <Panel title="Assessment lineage" description="The relationship to earlier evidence stays explicit." aside={<GitBranch size={18}/>}>
    {a.baselineId ? <><div className="asmt-lineage"><div><span className="asmt-kicker">BASELINE</span><code>{a.baselineId}</code><span className="asmt-availability"><span/>{a.baselineLoaded ? 'Available in this workspace' : 'Not supplied in this workspace'}</span></div><ArrowRight size={19} aria-hidden="true"/><div><span className="asmt-kicker">THIS ASSESSMENT</span><strong>{kindLabel(a)}</strong><p>{a.counts.addedOutcomes} added {a.counts.addedOutcomes === 1 ? 'outcome' : 'outcomes'} · {a.counts.revalidations} {a.counts.revalidations === 1 ? 'revalidation' : 'revalidations'}</p></div></div>
      <Accordion type="multiple" className="asmt-sub-accordion"><AccordionItem value="baseline-decisions"><AccordionTrigger>Baseline decisions<Badge>{a.baselineReconciliation.length}</Badge></AccordionTrigger><AccordionContent><RecordedItems items={a.baselineReconciliation} runId={a.id} onEvidence={onEvidence} noun="decisions"/></AccordionContent></AccordionItem></Accordion></>
      : <div className="asmt-standalone"><span className="asmt-icon-tile"><Fingerprint size={22}/></span><div><strong>No baseline relationship recorded</strong><p>Findings retain this assessment's own source scope. No earlier assessment is inferred.</p></div></div>}
  </Panel>;
}
function OverviewTab({ assessment: a, onEvidence, onTab }: { assessment: AssessmentSummary; onEvidence: EvidenceHandler; onTab: (tab: Tab) => void }) {
  const outcome = record(a.accounting.outcome_assessment), views = [...new Set(a.scopes.map(scope => scope.source_view).filter(Boolean))];
  return <div className="asmt-tab-layout"><div className="asmt-two-column"><Panel title="What this assessment establishes" description="Accepted conclusions apply to the recorded scope." className="asmt-outcome-panel">
    {text(outcome.headline) ? <p className="asmt-outcome-copy">{String(outcome.headline)}</p> : <div className="asmt-outcome-copy"><p>{a.counts.confirmed} confirmed {a.counts.confirmed === 1 ? 'finding is' : 'findings are'} recorded in this assessment.</p><p>{a.counts.needsEnvironment > 0 ? `${a.counts.needsEnvironment} ${a.counts.needsEnvironment === 1 ? 'dossier still requires' : 'dossiers still require'} environment evidence.` : 'Execution status remains specific to each claim; confirmation alone does not establish reproduction.'}</p></div>}
    <Separator/><div className="asmt-outcome-footer"><ShieldCheck size={16}/><span>Review verdicts are preserved. This viewer performs no new source assessment.</span></div>
  </Panel><Panel title="Assessment at a glance" description="Scope and publication are separate events."><Facts items={[
    ['Assessment type', kindLabel(a)], ['Source view', views.length ? views.map(view => human(view)).join(' · ') : null],
    ['Assessment started', a.scopes.length ? [...new Set(a.scopes.map(scope => dateLabel(scope.started_at)))].join(' · ') : 'Unknown'], ['Published', dateLabel(a.publishedAt)],
  ]}/><Button variant="ghost" className="asmt-inline-action" onClick={() => onTab('scope')}>Inspect source scope<ArrowUpRight size={15}/></Button></Panel></div>
    <BaselinePanel assessment={a} onEvidence={onEvidence}/>
    <div className="asmt-next-reads"><button onClick={() => onTab('questions')}><span className="asmt-icon-tile"><Search size={20}/></span><span><strong>Inspect remaining questions</strong><small>Missing facts, next actions and later-source applicability</small></span><ArrowRight size={18}/></button><button onClick={() => onTab('evidence')}><span className="asmt-icon-tile"><BookOpen size={20}/></span><span><strong>Open the original evidence</strong><small>Report, accepted findings and evidence availability</small></span><ArrowRight size={18}/></button></div>
  </div>;
}
function ScopeTab({ assessment: a }: { assessment: AssessmentSummary }) {
  return <div className="asmt-tab-layout"><Panel title="Repositories & revisions" description="Repository identities recorded by this publication. No current checkout is loaded." aside={<Badge>{a.repositories.length || 'Unknown'} repositories</Badge>}><RepositoryTable repositories={a.repositories}/></Panel>
    <Panel title="Recorded assessment scopes" description="Keep each assessed source view and its revisions together." aside={<Badge>{a.scopes.length || 'Unknown'} scopes</Badge>}>
      {!a.scopes.length ? <div className="asmt-missing-scope"><Fingerprint size={23}/><strong>Assessment scope metadata is unavailable</strong><p>Assessment date, source view and per-scope revisions remain unknown. Values are not borrowed from another execution.</p></div> : <Accordion type="multiple" defaultValue={a.scopes.length === 1 ? ['scope-0'] : []} className="asmt-scope-accordion">{a.scopes.map((scope, index) => <AccordionItem value={`scope-${index}`} key={scope.assessment_id ?? index}><AccordionTrigger><span><strong>{scope.source_view ? titleCase(scope.source_view) + ' source' : 'Source view unknown'}</strong><small>{scope.assessment_id ?? 'Scope identity unknown'}</small></span><span className="asmt-scope-date"><CalendarDays size={14}/>{dateLabel(scope.started_at)}</span></AccordionTrigger><AccordionContent>
        <Facts items={[
          ['Assessment started', dateLabel(scope.started_at)], ['Source view', scope.source_view ? human(scope.source_view) : null], ['Producing execution', scope.run_id || null], ['Producing attempt', scope.attempt_id ? <code>{scope.attempt_id}</code> : null], ['Patch reference', text(scope.patch_ref) ? <code>{String(scope.patch_ref)}</code> : 'Not recorded'],
        ]}/><h3 className="asmt-subheading">Revisions in this scope</h3><RepositoryTable repositories={scope.repositories}/>
        {scope.limitations.length > 0 && <div className="asmt-scope-limits"><h3 className="asmt-subheading">Scope limitations</h3><ul>{scope.limitations.map((limitation, i) => <li key={i}>{limitation}</li>)}</ul></div>}
        <details className="asmt-raw-detail"><summary>Complete scope metadata</summary><div className="asmt-raw-scroll"><RecordView value={scope}/></div></details>
      </AccordionContent></AccordionItem>)}</Accordion>}
    </Panel><div className="asmt-footnote"><Info size={16}/><p>Recorded paths and revisions describe the assessment's evidence. Later publication does not establish applicability to today's source.</p></div>
  </div>;
}
function QuestionsTab({ assessment: a, onEvidence }: { assessment: AssessmentSummary; onEvidence: EvidenceHandler }) {
  const cohorts = cohortsFor(a), totals = accountingTotals(a);
  return <div className="asmt-tab-layout"><div className="asmt-questions-intro"><div><h2>What remains open</h2><p>Follow the missing fact and next action. These cohorts can overlap and are not additional confirmed vulnerabilities.</p></div><span className="asmt-outline-label">RECORDED OUTCOMES</span></div>
    <div className="asmt-question-metrics"><NumberCard label="Environment evidence" value={a.counts.needsEnvironment} detail="Dossiers awaiting a prerequisite"/><NumberCard label="Unresolved paths" value={investigationCount(a, 'unresolved_paths')} detail="Recorded investigation total"/><NumberCard label="Later-source applicability" value={a.counts.unresolvedApplicability} detail="Historical findings awaiting assessment"/></div>
    <Panel title="Questions, claims & follow-up" description="Open a cohort to inspect its recorded outcomes. Shown, total and omitted counts stay separate.">
      {cohorts.length ? <Accordion type="multiple" className="asmt-cohort-accordion">{cohorts.map(cohort => <AccordionItem value={cohort.key} key={cohort.key}><AccordionTrigger><span><strong>{cohort.title}</strong><small>{cohort.description}</small></span><Badge>{countLabel(cohort.total)}</Badge></AccordionTrigger><AccordionContent><div className="asmt-cohort-meta"><span><strong>{cohort.items.length}</strong> included here</span><span>Total: <strong>{countLabel(cohort.total)}</strong></span><span>Omitted: <strong>{countLabel(cohort.omitted)}</strong></span></div><RecordedItems items={cohort.items} runId={a.id} onEvidence={onEvidence}/></AccordionContent></AccordionItem>)}</Accordion> : <p className="asmt-empty-inline">No question cohorts were included in this publication. Missing accounting remains unknown.</p>}
    </Panel><Panel title="Investigation accounting" description="Recorded totals describe their own cohorts and should not be summed as unique findings."><Accordion type="multiple" className="asmt-sub-accordion"><AccordionItem value="totals"><AccordionTrigger>Recorded investigation totals<Badge>{totals.length} fields</Badge></AccordionTrigger><AccordionContent>{totals.length ? <dl className="asmt-total-table">{totals.map(([key, value]) => <div key={key}><dt>{titleCase(key)}</dt><dd className={value === null ? 'asmt-unknown' : ''}>{countLabel(value)}</dd></div>)}</dl> : <p className="asmt-empty-inline">Investigation totals were not recorded.</p>}</AccordionContent></AccordionItem></Accordion></Panel>
  </div>;
}
function EvidenceTab({ assessment: a, onEvidence }: { assessment: AssessmentSummary; onEvidence: EvidenceHandler }) {
  const quality = record(a.accounting.evidence_quality), availability = a.availability;
  const artifacts = [
    { title: 'Machine-readable report', description: 'Published findings, source scope and outcome accounting.', label: 'Report JSON', path: 'report/security-report.json', icon: FileJson },
    { title: 'Readable report', description: 'The original narrative with complete attack and repair guidance.', label: 'Report Markdown', path: 'report/security-report.md', icon: FileText },
    { title: 'Canonical final findings', description: 'The accepted dossier authority used by this publication.', label: 'Final findings', path: 'final-verification/findings.json', icon: ShieldCheck },
  ];
  return <div className="asmt-tab-layout"><div className="asmt-artifacts">{artifacts.map(artifact => <Card key={artifact.path} className="asmt-artifact-card"><CardHeader><span className="asmt-artifact-icon"><artifact.icon size={22}/></span><CardTitle>{artifact.title}</CardTitle><CardDescription>{artifact.description}</CardDescription></CardHeader><CardContent><Button variant="outline" onClick={() => onEvidence(artifact.path, a.id)}>{artifact.label}<ArrowUpRight size={14}/></Button></CardContent></Card>)}</div>
    <div className="asmt-two-column"><Panel title="Evidence availability" description="Supporting records and finding verdicts are separate concerns."><Facts items={[
      ['Baseline accounting', availability?.counts_complete === true ? 'Recorded as complete' : availability?.counts_complete === false ? 'Recorded as incomplete' : null], ['Unavailable cohorts', Array.isArray(availability?.unavailable_cohorts) ? String(availability.unavailable_cohorts.length) : null], ['Import diagnostics', String(a.diagnostics.length)],
    ]}/><Accordion type="multiple" className="asmt-sub-accordion"><AccordionItem value="availability"><AccordionTrigger>Availability details<Badge>{rows(availability?.limitations).length + a.diagnostics.length}</Badge></AccordionTrigger><AccordionContent>{rows(availability?.unavailable_cohorts).length > 0 && <div className="asmt-unavailable-cohorts">{rows(availability?.unavailable_cohorts).map((cohort, index) => <code key={index}>{String(cohort)}</code>)}</div>}<RecordedItems items={[...rows(availability?.limitations), ...a.diagnostics]} runId={a.id} onEvidence={onEvidence} noun="diagnostics"/></AccordionContent></AccordionItem></Accordion></Panel>
    <Panel title="Evidence quality" description="Recorded evidence limitations, not new verification results."><Facts items={[
      ['Recorded diagnostics', countLabel(count(quality.total))], ['Affected items', countLabel(count(quality.affected_item_count))], ['Omitted diagnostics', countLabel(count(quality.truncated))],
    ]}/><Accordion type="multiple" className="asmt-sub-accordion"><AccordionItem value="quality"><AccordionTrigger>Evidence diagnostics<Badge>{rows(quality.diagnostics).length} shown</Badge></AccordionTrigger><AccordionContent><RecordedItems items={rows(quality.diagnostics)} runId={a.id} onEvidence={onEvidence} noun="diagnostics"/></AccordionContent></AccordionItem></Accordion></Panel></div>
    <Panel title="What opening this report checks" description="The viewer consumes accepted records; it does not create a new assessment." className="asmt-checks-panel"><div className="asmt-check-grid"><div><Braces size={18}/><strong>Publication structure</strong><p>Required companions are readable and carry compatible identity.</p></div><div><ListChecks size={18}/><strong>Final-finding agreement</strong><p>Published dossiers agree with the recorded canonical final authority.</p></div><div><Fingerprint size={18}/><strong>Original scope retained</strong><p>Source dates, revisions and independent-review conclusions remain attached.</p></div></div><p className="asmt-checks-limit">Loading does not repeat strict evidence-closure verification, authenticate the publisher, review current source or reproduce an attack.</p></Panel>
    <Accordion type="multiple" className="asmt-advanced"><AccordionItem value="advanced"><AccordionTrigger><span><strong>Advanced provenance & accounting</strong><small>All imported assessment fields, including operational detail</small></span><Badge>Advanced</Badge></AccordionTrigger><AccordionContent><div className="asmt-raw-scroll"><RecordView value={a}/></div></AccordionContent></AccordionItem></Accordion>
  </div>;
}

export default function Assessment({ assessments, onEvidence, selectedAssessmentId, onAssessmentChange }: { assessments: AssessmentSummary[]; onEvidence: EvidenceHandler; selectedAssessmentId?: string; onAssessmentChange?: (id: string) => void }) {
  const [selectedId, setSelectedId] = useState(assessments[0]?.id ?? ''), [tab, setTab] = useState<Tab>('overview');
  const active = assessments.find(a => a.id === (selectedAssessmentId ?? selectedId)) ?? assessments[0];
  if (!active) return <Empty title="No assessment available" description="Load a completed report to inspect its source scope and evidence."/>;
  return <div className="asmt-workspace"><header className="asmt-page-heading"><div><p className="asmt-kicker">ASSESSMENT CONTEXT</p><h1>Know the scope.<br/><span>Understand the limits.</span></h1><p>The assessed source, remaining questions and evidence behind each conclusion.</p></div><div className="asmt-heading-mark" aria-hidden="true"><Fingerprint size={37} strokeWidth={1.2}/></div></header>
    <section className="asmt-identity-bar" aria-label="Selected assessment"><div className="asmt-identity-main"><span className="asmt-type-marker">{kindLabel(active)}</span><strong>{active.repository || 'Recorded assessment'}</strong><code>{active.id}</code></div>{assessments.length > 1 && <label className="asmt-switcher"><span>Assessment</span><select aria-label="Assessment" value={active.id} onChange={event => { setSelectedId(event.target.value); setTab('overview'); onAssessmentChange?.(event.target.value); }}>{assessments.map(a => <option key={a.id} value={a.id}>{kindLabel(a)} · {dateLabel(a.publishedAt)} · {a.id}</option>)}</select></label>}</section>
    <div className="asmt-summary-strip" aria-label="Assessment summary"><NumberCard label="Confirmed findings" value={active.counts.confirmed} detail="Within this recorded assessment" accent/><NumberCard label="Needs environment" value={active.counts.needsEnvironment} detail="Excluded from confirmed totals"/><NumberCard label="Recorded repositories" value={active.repositories.length || null} detail="Publication source inventory"/><NumberCard label={active.kind === 'advantage' ? 'Added outcomes' : 'Confirmed chains'} value={active.kind === 'advantage' ? active.counts.addedOutcomes : active.counts.confirmedChains} detail={active.kind === 'advantage' ? `${active.counts.revalidations} revalidations remain separate` : 'Explicitly recorded composition'}/></div>
    <Tabs value={tab} onValueChange={value => setTab(value as Tab)} className="asmt-tabs" key={active.id}><TabsList aria-label="Assessment sections">{tabLabels.map(([value, label, Icon]) => <TabsTrigger key={value} value={value}><Icon size={15}/>{label}</TabsTrigger>)}</TabsList><TabsContent value="overview"><OverviewTab assessment={active} onEvidence={onEvidence} onTab={setTab}/></TabsContent><TabsContent value="scope"><ScopeTab assessment={active}/></TabsContent><TabsContent value="questions"><QuestionsTab assessment={active} onEvidence={onEvidence}/></TabsContent><TabsContent value="evidence"><EvidenceTab assessment={active} onEvidence={onEvidence}/></TabsContent></Tabs>
  </div>;
}
