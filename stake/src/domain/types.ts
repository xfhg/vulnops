/** JSON evidence stays unchanged; these interfaces describe consumed fields only. */
export type JsonRecord = Record<string, unknown>;
export type ExecutionKind = 'audit' | 'advantage';
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'unknown';
export type Cohort = 'confirmed' | 'needs_environment' | 'unconfirmed' | 'non_promoted' | 'rejected';
export type Classification = 'new_root' | 'new_chain' | 'impact_expansion' | 'baseline_correction' | 'baseline_revalidation';
export type EvidenceReference = string | ({ execution_id: string; artifact_ref: string } & JsonRecord);

export interface SourceLocation extends JsonRecord {
  file: string;
  line?: number;
  start_line?: number;
  end_line?: number;
  scope?: string;
  mechanism?: string;
  description?: string;
}
export interface TraceEntry extends SourceLocation { kind: string }
export interface ProcedureStep extends JsonRecord {
  id: string;
  action: string;
  controlled_input?: string;
  why_it_works?: string;
  expected_result?: string;
  observed_result?: string | null;
  evidence_status?: string;
  component_ids?: string[];
  primitive_ids?: string[];
  example_ids?: string[];
  evidence_refs?: EvidenceReference[];
  observation_refs?: EvidenceReference[];
}
export interface TechnicalExample extends JsonRecord {
  id: string;
  kind: string;
  content: string;
  execution_status?: string;
  substitutions?: Array<{ original: string; replacement: string; reason: string }>;
  evidence_refs?: EvidenceReference[];
  observation_refs?: EvidenceReference[];
}
export interface RepairAction extends JsonRecord {
  id: string;
  change: string;
  rationale?: string;
  breaks_steps?: string[];
  component_ids?: string[];
  example_ids?: string[];
  locations?: SourceLocation[];
  evidence_refs?: EvidenceReference[];
}
export interface VerificationCheck extends JsonRecord {
  id: string;
  description?: string;
  attack_expected?: string;
  legitimate_expected?: string;
  status?: string;
  evidence_refs?: EvidenceReference[];
}
export interface RawComponent extends JsonRecord {
  id: string;
  name: string;
  repository?: string;
  entrypoints?: string[];
  locations?: SourceLocation[];
  service?: { name?: string | null; binding?: string; limitation?: string; evidence_refs?: EvidenceReference[] };
  evidence_refs?: EvidenceReference[];
}
export interface PrimitiveStep extends JsonRecord {
  primitive_id: string;
  input_capability?: string;
  output_capability?: string;
  boundary_crossed?: string;
  evidence_refs?: EvidenceReference[];
}
export interface Transition extends JsonRecord {
  producer_id: string;
  consumer_id: string;
  resolution?: JsonRecord;
  obligations?: Record<string, JsonRecord>;
}
/** Fields are optional because unconfirmed records need not contain a dossier. */
export interface RawFinding extends JsonRecord {
  id?: string;
  finding_id?: string;
  title?: string;
  severity?: string;
  verdict?: string;
  status?: string;
  finding_kind?: string;
  category?: string;
  origin?: string;
  attack_summary?: string;
  impact?: string;
  intended_behavior?: string;
  conditions?: string[];
  impact_limits?: string[];
  attacker?: { perspective?: string; starting_access?: string; boundary_crossed?: string };
  assessment_context?: { assessment_id?: string; attempt_id?: string };
  affected_components?: RawComponent[];
  root_causes?: SourceLocation[];
  trace?: TraceEntry[];
  exploitation?: { rationale?: string; setup?: string[]; steps: ProcedureStep[] };
  technical_examples?: TechnicalExample[];
  remediation?: {
    actions: RepairAction[];
    verification_checks?: VerificationCheck[];
    containment?: unknown[];
    detection?: unknown[];
    limitations?: string[];
    unresolved_decisions?: unknown[];
  };
  verification?: { level?: string; actor?: string; model?: string; reproduction_ref?: EvidenceReference | null; source_validation_refs?: EvidenceReference[] };
  primitive_steps?: PrimitiveStep[];
  transitions?: Transition[];
  source_refs?: JsonRecord[];
}
export interface RepositoryRecord extends JsonRecord { name?: string; path?: string; commit?: string | null; remote_url?: string }
export interface AssessmentScope extends JsonRecord {
  assessment_id: string | null;
  run_id: string;
  attempt_id: string | null;
  source_view: string | null;
  started_at: string | null;
  repositories: RepositoryRecord[];
  limitations: string[];
}
export interface AdmittedBundle extends JsonRecord {
  run_id: string;
  execution_kind: ExecutionKind;
  report: JsonRecord;
  final: JsonRecord | null;
  inputPath?: string;
  repository?: string;
  repositories?: RepositoryRecord[];
  assessment?: JsonRecord;
}
export interface ImportFailure { inputPath?: string; runId?: string; code?: string; message: string }
export interface Diagnostic { code: string; message: string; runId?: string; findingKey?: string; reference?: string }
export interface ComponentSummary {
  id: string;
  key: string;
  name: string;
  repository: string | null;
  entrypoints: string[];
  serviceBinding: string | null;
  serviceName: string | null;
}
export interface FindingSummary {
  key: string;
  runId: string;
  id: string;
  title: string;
  severity: Severity;
  verdict: string | null;
  status: string | null;
  kind: string | null;
  classification: Classification | null;
  origin: 'assessed' | 'historical';
  cohort: Cohort;
  hasDossier: boolean;
  scope: AssessmentScope | null;
  scopeId: string | null;
  sourceView: string | null;
  repositories: string[];
  components: ComponentSummary[];
  verificationLevel: string | null;
  attackSummary: string | null;
  impact: string | null;
  repairCount: number;
  stepCount: number;
  traceCount: number;
  /** Executions in which this record is presented as imported history. */
  historicalIn: string[];
  conflicted: boolean;
  diagnostics: Diagnostic[];
}
export interface FindingRecord extends FindingSummary { raw: RawFinding }
export interface AssessmentCounts {
  total: number;
  confirmed: number;
  needsEnvironment: number;
  severity: Record<Severity, number>;
  confirmedChains: number;
  historical: number;
  historicalConfirmed: number;
  historicalNeedsEnvironment: number;
  unconfirmed: number | null;
  nonPromoted: number | null;
  rejected: number | null;
  addedOutcomes: number;
  newRoots: number;
  newChains: number;
  impactExpansions: number;
  revalidations: number;
  corrections: number;
  sourceOnly: number;
  dynamicallyVerified: number;
  unresolvedQuestions: number | null;
  unresolvedApplicability: number | null;
}
export interface AssessmentSummary {
  id: string;
  kind: ExecutionKind;
  mode: string | null;
  repository: string | null;
  repositories: RepositoryRecord[];
  scopes: AssessmentScope[];
  publishedAt: string | null;
  counts: AssessmentCounts;
  findingKeys: string[];
  historicalFindingKeys: string[];
  baselineId: string | null;
  baselineLoaded: boolean;
  baselineReconciliation: JsonRecord[];
  unresolvedApplicability: JsonRecord[];
  limitations: string[];
  availability: JsonRecord | null;
  accounting: JsonRecord;
  diagnostics: Diagnostic[];
}
export interface Assessment extends AssessmentSummary { report: JsonRecord }
export interface FindingRelation {
  key: string;
  kind: 'baseline';
  from: string;
  to: string;
  classification: Classification;
  sourceView: string | null;
  available: boolean;
}
export interface IdentityConflict { key: string; runId: string; findingId: string; representedIn: string[]; message: string }
export interface Workspace {
  assessments: Assessment[];
  findings: FindingRecord[];
  failures: ImportFailure[];
  conflicts: IdentityConflict[];
  relations: FindingRelation[];
}
export interface WorkspaceSummary extends Omit<Workspace, 'assessments' | 'findings'> {
  assessments: AssessmentSummary[];
  findings: FindingSummary[];
}
export interface FindingFilters {
  query?: string;
  assessment?: string;
  runId?: string;
  repository?: string;
  component?: string;
  severity?: string;
  disposition?: string;
  cohort?: string;
  kind?: string;
  classification?: string;
  origin?: string;
  sort?: 'severity' | 'title' | 'id';
  direction?: 'asc' | 'desc';
}
export interface CodeLocation {
  key: string;
  runId: string;
  scopeId: string | null;
  sourceView: string | null;
  repository: string | null;
  file: string;
  line: number | null;
  endLine: number | null;
  scope: string | null;
  findingKeys: string[];
  componentKeys: string[];
  roles: Array<'trace' | 'root_cause' | 'component' | 'repair' | 'citation'>;
  explanations: string[];
}
