import { useId, useMemo, useState, type ReactNode } from 'react';
import { ArrowRight, ArrowUpRight, CircleHelp, FileStack, GitBranch, Layers3, ShieldCheck, ShieldAlert, Wrench } from 'lucide-react';
import type { AssessmentSummary, FindingFilters, FindingSummary, Severity } from '../../domain/types';
import { buildOverviewModel } from '../../domain/overview';
import { Badge, Button, Empty, Tabs, TabsContent, TabsList, TabsTrigger } from '../../components/ui';
import { Card, CardContent, CardDescription, CardFooter, CardHeader } from '../../components/ui/data-display';
import { dateLabel, human } from '../../app/state';
import './overview.css';

interface OverviewProps {
  assessments: AssessmentSummary[];
  findings: FindingSummary[];
  onFinding: (finding: FindingSummary) => void;
  onView: (view: string) => void;
  onExplore?: (filters: FindingFilters) => void;
  scopedRepository?: string;
  unattributedReviewCount?: number;
}
type PriorityTab = 'high' | 'confirmed' | 'environment';
const confirmedFilters: FindingFilters = { disposition: 'confirmed', origin: 'assessed' };
const severityLabels: Record<Severity, string> = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info', unknown: 'Unknown' };
const severityOrder: Severity[] = ['critical', 'high', 'medium', 'low', 'info', 'unknown'];
const number = (value: number) => value.toLocaleString('en-US');

function OverviewCard({ title, description, action, className = '', children }: { title: string; description?: string; action?: ReactNode; className?: string; children: ReactNode }) {
  return <Card role="region" aria-label={title} className={`overview-card ${className}`}>
    <CardHeader className="overview-card-heading"><div><h2>{title}</h2>{description && <CardDescription>{description}</CardDescription>}</div>{action}</CardHeader>
    {children}
  </Card>;
}

function Metric({ label, value, description, detail, icon: Icon, onClick, accessibleName, featured = false }: {
  label: string; value: number; description: string; detail?: string; icon: typeof ShieldCheck; onClick: () => void; accessibleName: string; featured?: boolean;
}) {
  const id = useId();
  return <Card className={`metric-card overview-metric${featured ? ' overview-metric-featured' : ''}`}><button className="overview-metric-action" onClick={onClick} aria-label={accessibleName} aria-describedby={`${id}-value ${id}-detail`}>
    <span className="metric-label"><span>{label}</span><span className="overview-metric-icon"><Icon size={16} strokeWidth={1.7} aria-hidden="true" /></span></span>
    <span className="overview-metric-number"><strong className="overview-metric-value" id={`${id}-value`}>{number(value)}</strong>{featured && value > 0 && <span className="overview-metric-cue">Prioritize</span>}</span>
    <span className="metric-foot" id={`${id}-detail`}>{description}{detail && <span>{detail}</span>}</span>
    <ArrowUpRight size={15} className="overview-metric-arrow" aria-hidden="true" />
  </button></Card>;
}

function PriorityTable({ findings, onFinding }: { findings: FindingSummary[]; onFinding: (finding: FindingSummary) => void }) {
  return <table className="priority-list overview-priority-table" aria-label="Priority findings">
    <thead><tr><th scope="col">Finding / impact</th><th scope="col">Severity</th><th scope="col">Repository</th><th scope="col">Procedure</th><th scope="col">Repair guidance</th></tr></thead>
    <tbody>{findings.map(finding => <tr className="priority-row" data-finding-key={finding.key} data-severity={finding.severity} key={finding.key}>
      <td className="overview-finding-cell"><button className="overview-finding-link" aria-label={`Open ${finding.id}: ${finding.title}`} title={finding.title} onClick={() => onFinding(finding)}>
        <span className="row-id"><strong>{finding.id}</strong><span title={finding.runId}>{finding.runId}</span></span>
        <h3>{finding.title}</h3><p>{finding.impact || finding.attackSummary || 'Impact not recorded in the summary.'}</p><ArrowUpRight size={15} aria-hidden="true" />
      </button></td>
      <td><span className="overview-cell-label">Severity</span><Badge tone={finding.severity}>{severityLabels[finding.severity]}</Badge></td>
      <td className="overview-repository-cell"><span className="overview-cell-label">Repository</span><span title={finding.repositories.join(', ')}>{finding.repositories.length ? finding.repositories.join(', ') : 'Not attributed'}</span></td>
      <td><span className="overview-cell-label">Procedure</span><span className="overview-row-number">{finding.hasDossier ? `${number(finding.stepCount)} steps` : 'Not recorded'}</span></td>
      <td><span className="overview-cell-label">Repair guidance</span><span className="overview-row-number">{finding.repairCount ? `${number(finding.repairCount)} ${finding.repairCount === 1 ? 'action' : 'actions'}` : finding.hasDossier ? 'No actions recorded' : 'Unknown'}</span></td>
    </tr>)}</tbody>
  </table>;
}

export default function Overview({ assessments, findings, onFinding, onView, onExplore, scopedRepository, unattributedReviewCount = 0 }: OverviewProps) {
  const model = useMemo(() => buildOverviewModel(assessments, findings), [assessments, findings]);
  const [priorityTab, setPriorityTab] = useState<PriorityTab>('high');
  if (!assessments.length) return <Empty title="No assessment in this scope" description="Select an available assessment to explore its results." />;
  const explore = (filters: FindingFilters) => onExplore ? onExplore(filters) : onView('findings');
  const priority = priorityTab === 'high' ? model.highImpact : priorityTab === 'environment' ? model.needsEnvironment : model.priority;
  const priorityFilters: FindingFilters = priorityTab === 'high' ? { ...confirmedFilters, severity: 'critical,high' } : priorityTab === 'environment' ? { disposition: 'needs_environment', origin: 'assessed' } : confirmedFilters;
  const critical = model.severity.find(bucket => bucket.severity === 'critical')!.count;
  const high = model.severity.find(bucket => bucket.severity === 'high')!.count;
  const inventoryNotes = [
    ...(model.context.unknownInventoryRepositories ? [`${number(model.context.unknownInventoryRepositories)} inventory ${model.context.unknownInventoryRepositories === 1 ? 'entry is' : 'entries are'} unattributed`] : []),
    ...(model.context.assessmentsWithoutRepositoryInventory ? [`${number(model.context.assessmentsWithoutRepositoryInventory)} ${model.context.assessmentsWithoutRepositoryInventory === 1 ? 'report inventory is' : 'report inventories are'} not recorded`] : []),
  ];
  const advantageCount = assessments.filter(assessment => assessment.kind === 'advantage').length;
  const additions = model.confirmation.additional;
  const confirmationContext = [
    `${number(model.confirmation.ordinary.length)} ordinary`, `${number(additions.length)} added`,
    `${number(model.confirmation.revalidations.length)} revalidated`,
    ...(model.confirmation.corrections.length ? [`${number(model.confirmation.corrections.length)} corrected`] : []),
    ...(model.confirmation.other.length ? [`${number(model.confirmation.other.length)} other`] : []),
  ].join(' · ');
  const contributions = [
    { label: 'New roots', classification: 'new_root', count: additions.filter(finding => finding.classification === 'new_root').length },
    { label: 'New chains', classification: 'new_chain', count: additions.filter(finding => finding.classification === 'new_chain').length },
    { label: 'Impact expansions', classification: 'impact_expansion', count: additions.filter(finding => finding.classification === 'impact_expansion').length },
    { label: 'Revalidations', classification: 'baseline_revalidation', count: model.confirmation.revalidations.length },
    { label: 'Corrections', classification: 'baseline_correction', count: model.confirmation.corrections.length },
  ];
  const guidance = model.repairGuidance;
  const emptyTitle = priorityTab === 'environment' ? 'No environment-dependent outcomes' : !model.confirmed.length ? 'No confirmed outcomes' : 'No high or critical outcomes';
  const emptyDescription = priorityTab === 'environment' ? 'No outcomes in this selection are recorded as needing environment evidence.' : !model.confirmed.length ? 'Review Assessment for open questions and recorded limitations before drawing conclusions.' : 'The All confirmed tab includes the other recorded severities.';

  return <div className="assessment-overview">
    <header className="overview-heading"><div><p className="eyebrow">ASSESSMENT INTELLIGENCE</p><h1>Assessment overview</h1><p>Prioritize assessed outcomes and move from evidence to repair guidance.</p></div>
      <div className="overview-context"><Button variant="ghost" size="sm" onClick={() => onView('assessment')}><FileStack size={15} aria-hidden="true" />{number(model.context.loadedAssessmentCount)} {model.context.loadedAssessmentCount === 1 ? 'report' : 'reports'}<ArrowUpRight size={13} aria-hidden="true" /></Button>
        <span><Layers3 size={14} aria-hidden="true" />{model.context.inventoryRepositoryCount ? `${number(model.context.inventoryRepositoryCount)} ${model.context.inventoryRepositoryCount === 1 ? 'repository' : 'repositories'} in inventory` : 'Repository inventory not recorded'}</span>
        {inventoryNotes.length > 0 && <span className="overview-inventory-note">{inventoryNotes.join(' · ')}</span>}
        {scopedRepository && <span className="overview-scope-label" title={scopedRepository}>Selected: {scopedRepository}</span>}
      </div>
    </header>

    <div className="metric-grid" aria-label="Assessed outcome metrics">
      <Metric label="Confirmed outcomes" value={model.confirmed.length} icon={ShieldCheck} description="Assessed outcome records" detail={confirmationContext} accessibleName="Explore confirmed outcomes" onClick={() => explore(confirmedFilters)} />
      <Metric label="High & critical" value={model.highImpact.length} icon={ShieldAlert} description={`${number(critical)} critical · ${number(high)} high`} detail="Confirmed outcomes only" featured accessibleName="Explore high and critical outcomes" onClick={() => explore({ ...confirmedFilters, severity: 'critical,high' })} />
      <Metric label="Recorded chains" value={model.chains.length} icon={GitBranch} description="Explicitly recorded compositions" detail="Confirmed outcomes only" accessibleName="Explore recorded chains" onClick={() => explore({ ...confirmedFilters, kind: 'chain' })} />
      <Metric label="Needs environment" value={model.needsEnvironment.length} icon={CircleHelp} description="External evidence still required" detail="Separate from confirmed outcomes" accessibleName="Explore environment-required outcomes" onClick={() => explore({ disposition: 'needs_environment', origin: 'assessed' })} />
    </div>
    <p className="overview-count-note">Counts describe assessed records in this selection. The same issue can appear in more than one report.</p>

    <OverviewCard title="Priority findings" description="Ordered by assessed severity, with the recorded steps and guidance ready to open." className="overview-priority-card">
      <Tabs value={priorityTab} onValueChange={value => setPriorityTab(value as PriorityTab)}>
        <div className="overview-priority-toolbar"><TabsList aria-label="Priority finding cohorts">
          <TabsTrigger value="high" aria-label="High impact" className="overview-high-impact-tab">High impact<span>{number(model.highImpact.length)}</span></TabsTrigger>
          <TabsTrigger value="confirmed" aria-label="All confirmed">All confirmed<span>{number(model.confirmed.length)}</span></TabsTrigger>
          <TabsTrigger value="environment" aria-label="Needs environment">Needs environment<span>{number(model.needsEnvironment.length)}</span></TabsTrigger>
        </TabsList></div>
        <TabsContent value={priorityTab} className="overview-priority-content">
          {priority.length ? <PriorityTable findings={priority.slice(0, 5)} onFinding={onFinding} /> : <Empty title={emptyTitle} description={emptyDescription} action={model.confirmed.length && priorityTab === 'high' ? <Button variant="outline" size="sm" onClick={() => setPriorityTab('confirmed')}>See all confirmed</Button> : <Button variant="outline" size="sm" onClick={() => onView('assessment')}>Review assessment</Button>} />}
        </TabsContent>
      </Tabs>
      <CardFooter className="overview-priority-footer"><span>Showing {number(Math.min(priority.length, 5))} of {number(priority.length)} {priorityTab === 'environment' ? 'environment-dependent' : 'confirmed'} records</span><Button size="sm" className="overview-priority-cta" onClick={() => explore(priorityFilters)}>View matching findings<ArrowRight size={14} aria-hidden="true" /></Button></CardFooter>
    </OverviewCard>

    <div className="overview-lower-grid">
      <div className="overview-column overview-scope-column">
      <OverviewCard title="Confirmed outcomes by repository" description="Severity distribution of findings associated with each repository." className="overview-repositories">
        <CardContent>
          {model.repositories.length ? <div className="overview-repository-list">{model.repositories.map(row => {
            const buckets = severityOrder.map(severity => ({ severity, count: row.findings.filter(finding => finding.severity === severity).length })).filter(bucket => bucket.count > 0);
            return <article className="overview-repository-row" key={row.repository ?? 'unattributed'}>
              <button className="overview-repository-link" aria-label={row.repository ? `Explore confirmed outcomes in ${row.repository}` : 'Review repository attribution'} onClick={() => row.repository ? explore({ ...confirmedFilters, repository: row.repository }) : onView('assessment')}>
                <span>{row.repository || 'Repository not attributed'}</span><strong>{number(row.confirmed)}<small>confirmed</small></strong><ArrowUpRight size={14} aria-hidden="true" />
              </button>
              <div className="overview-severity-meter" aria-hidden="true">{buckets.map(bucket => <span key={bucket.severity} style={{ width: `${bucket.count / row.confirmed * 100}%`, background: `var(--severity-${bucket.severity})` }} />)}</div>
              <div className="overview-severity-labels">{buckets.map(bucket => row.repository ? <button key={bucket.severity} aria-label={`Explore ${bucket.severity} outcomes in ${row.repository}`} onClick={() => explore({ ...confirmedFilters, repository: row.repository!, severity: bucket.severity })}><i style={{ background: `var(--severity-${bucket.severity})` }} aria-hidden="true" />{severityLabels[bucket.severity]}<strong>{number(bucket.count)}</strong></button> : <span key={bucket.severity}>{severityLabels[bucket.severity]}<strong>{number(bucket.count)}</strong></span>)}</div>
            </article>;
          })}</div> : <p className="overview-inline-empty">No confirmed repository associations in this selection.</p>}
          <p className="overview-small-note">A finding can reference several repositories; these rows overlap.</p>
          {unattributedReviewCount > 0 && <div className="overview-attribution-note"><span>{number(unattributedReviewCount)} review {unattributedReviewCount === 1 ? 'record has' : 'records have'} no repository attribution. Repository filters cannot place {unattributedReviewCount === 1 ? 'it' : 'them'}.</span><Button variant="ghost" size="sm" onClick={() => onView('assessment')}>Review repository attribution<ArrowUpRight size={13} aria-hidden="true" /></Button></div>}
        </CardContent>
      </OverviewCard>

      <OverviewCard title="Report context" description={scopedRepository ? 'Outcome counts follow the selected repository; dates belong to the original publications.' : 'Each outcome retains its owning execution and recorded source scope.'} className="overview-report-context" action={<Button variant="ghost" size="sm" onClick={() => onView('assessment')}>Assessment<ArrowUpRight size={13} aria-hidden="true" /></Button>}>
        <CardContent className="scope-cards">{assessments.map(assessment => {
          const rows = model.findings.filter(finding => finding.runId === assessment.id);
          return <article className="scope-card" key={assessment.id}><div className="overview-report-heading"><Badge>{assessment.kind === 'audit' ? 'Ordinary audit' : 'Advantage'}</Badge><span>{human(assessment.mode || 'assessment')}</span><span>Published {dateLabel(assessment.publishedAt)}</span></div>
            <button className="overview-report-link" onClick={() => explore({ assessment: assessment.id, origin: 'assessed' })} aria-label={`Explore findings from ${assessment.id}`}><strong>{assessment.repository || 'Application name not recorded'}</strong><ArrowUpRight size={14} aria-hidden="true" /></button>
            <p className="scope-run" title={assessment.id}>{assessment.id}</p><div className="overview-report-counts"><span><strong>{number(rows.filter(finding => finding.cohort === 'confirmed').length)}</strong> confirmed</span><span><strong>{number(rows.filter(finding => finding.cohort === 'needs_environment').length)}</strong> need environment</span></div>
          </article>;
        })}</CardContent>
      </OverviewCard>
      </div>

      <div className="overview-column overview-action-column">
      <OverviewCard title="Developer handoff" description="Repair guidance attached to confirmed outcomes in this selection." className="overview-handoff">
        <CardContent><div className="overview-guidance-heading"><strong className="overview-guidance-count">{number(guidance.withGuidance)}<span> / {number(model.confirmed.length)}</span></strong><span>outcomes with recorded guidance</span></div>
          {model.confirmed.length > 0 && <div className="overview-guidance-meter" role="meter" aria-label="Confirmed outcomes with recorded repair guidance" aria-valuemin={0} aria-valuemax={model.confirmed.length} aria-valuenow={guidance.withGuidance}><span style={{ width: `${guidance.withGuidance / model.confirmed.length * 100}%` }} /></div>}
          <dl className="overview-guidance-facts"><div><dt>No recorded actions</dt><dd>{number(guidance.withoutGuidance)}</dd></div><div><dt>Guidance unknown</dt><dd>{number(guidance.unknownGuidance)}</dd></div></dl>
          <div className="overview-action-records"><Wrench size={18} aria-hidden="true" /><strong>{number(guidance.actionRecords)}</strong><span>recorded action entries<small>Recommendations, not completed fixes.</small></span></div>
        </CardContent>
        <CardFooter><Button variant="outline" size="sm" onClick={() => onView('remediation')}>Review repair guidance<ArrowUpRight size={14} aria-hidden="true" /></Button><Button variant="ghost" size="sm" onClick={() => explore(confirmedFilters)}>Open confirmed findings</Button></CardFooter>
      </OverviewCard>

      {advantageCount > 0 && <OverviewCard title="Advantage contribution" description="Confirmed Advantage outcomes, with baseline reviews kept separate." action={<span className="overview-added-total">{number(additions.length)} added {additions.length === 1 ? 'outcome' : 'outcomes'}</span>} className="overview-advantage">
        <CardContent><div className="overview-contribution-grid">{contributions.map((item, index) => <button key={item.classification} className={`overview-contribution-item ${index > 2 ? 'overview-baseline-contribution' : ''}`} aria-label={`Explore Advantage ${item.label.toLowerCase()}`} onClick={() => explore({ ...confirmedFilters, classification: item.classification })}><span>{item.label}</span><strong>{number(item.count)}</strong><ArrowUpRight size={13} aria-hidden="true" /></button>)}</div>
          {model.confirmation.other.length > 0 && <p className="overview-small-note">{number(model.confirmation.other.length)} confirmed {model.confirmation.other.length === 1 ? 'record has' : 'records have'} no classified contribution in the available metadata.</p>}
          <p className="overview-small-note">Added outcomes comprise new roots, new chains and impact expansions. Imported history is excluded.</p>
        </CardContent>
      </OverviewCard>}

      </div>
    </div>
  </div>;
}
