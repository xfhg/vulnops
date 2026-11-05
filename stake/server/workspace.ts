import { randomUUID } from 'node:crypto';
import { resolve } from 'node:path';
import type { ImportFailure, Workspace } from '../src/domain/types.js';
import type { PersistenceOutcome, SourceFieldErrors, SourceLoadRequest, SourcePair, WorkspaceSourceState, WorkspaceVersion } from '../src/domain/sources.js';
import { summaryWorkspace } from '../src/domain/index.js';
import { importBundles, importPair, PairAdmissionError, type ImportResult } from './admission.js';
import { checkPrerequisites, type BridgeOptions } from './bridge.js';
import { EvidenceRegistry } from './references.js';
import { SettingsStore } from './settings.js';

export interface SourceHooks { beforeLoad?: () => Promise<void>; beforeSave?: () => Promise<void> }
export interface CoordinatorOptions extends BridgeOptions { runs: string[]; cwd?: string; configDir?: string; sourceHooks?: SourceHooks }
export class StartupError extends Error { constructor(message: string, public failures: ImportFailure[] = []) { super(message); } }
export class SourceLoadError extends Error {
  constructor(public status: number, public code: string, message: string, public generation: string, public fieldErrors?: SourceFieldErrors) { super(message); }
}

export function makeSnapshot(imported: ImportResult, options: BridgeOptions = {}) {
  const generation = randomUUID();
  const workspace = imported.workspace;
  const summary = summaryWorkspace(workspace);
  return Object.freeze({
    generation, workspace, summary,
    sources: imported.bundles.map((bundle) => ({ inputPath: bundle.inputPath, runId: bundle.run_id, kind: bundle.execution_kind })),
    byKey: new Map(workspace.findings.map((finding) => [finding.key, finding])),
    summaries: new Map(summary.findings.map((finding) => [finding.key, finding])),
    references: new EvidenceRegistry(imported.bundles, workspace, options, generation),
  });
}
export type WorkspaceSnapshot = ReturnType<typeof makeSnapshot>;
const noPersistence: PersistenceOutcome = { status: 'not_applicable' };

function eligiblePair(imported: ImportResult): SourcePair | null {
  if (imported.workspace.failures.length || imported.bundles.length !== 2) return null;
  const ordinary = imported.bundles.filter((bundle) => bundle.execution_kind === 'audit');
  const advantage = imported.bundles.filter((bundle) => bundle.execution_kind === 'advantage');
  return ordinary.length === 1 && advantage.length === 1 ? { ordinaryPath: ordinary[0]!.inputPath, advantagePath: advantage[0]!.inputPath } : null;
}

export class WorkspaceCoordinator {
  private active: WorkspaceSnapshot;
  private state: Omit<WorkspaceSourceState, 'generation' | 'sources'>;
  private constructor(private readonly options: CoordinatorOptions, private readonly store: SettingsStore, snapshot: WorkspaceSnapshot, state: Omit<WorkspaceSourceState, 'generation' | 'sources'>, private readonly startupPair: SourcePair | null) {
    this.active = snapshot; this.state = state;
  }

  static async create(options: CoordinatorOptions): Promise<WorkspaceCoordinator> {
    // Even setup requires the reader to be operable; never disguise a missing
    // Python/bridge prerequisite as a malformed saved preference.
    await checkPrerequisites(options);
    const store = new SettingsStore({ directory: options.configDir });
    const saved = await store.read(options.runs.map((path) => resolve(options.cwd ?? process.cwd(), path)));
    let imported: ImportResult;
    let origin: WorkspaceSourceState['origin'] = 'empty';
    let startupPair: SourcePair | null = null;
    let fieldErrors: SourceFieldErrors | undefined;
    const diagnostics = [...saved.diagnostics];
    if (options.runs.length) {
      imported = await importBundles(options.runs, options);
      if (!imported.workspace.assessments.length) throw new StartupError('No supplied publication could be loaded.', imported.workspace.failures);
      origin = 'cli'; startupPair = eligiblePair(imported);
    } else if (saved.valid && saved.pair) {
      try { imported = (await importPair(saved.pair, options)).imported; origin = 'saved'; }
      catch (error) {
        imported = await importBundles([], options);
        diagnostics.push('The remembered report pair could not be loaded. Correct both source paths to continue.');
        if (error instanceof PairAdmissionError) fieldErrors = error.fieldErrors;
      }
    } else imported = await importBundles([], options);
    return new WorkspaceCoordinator(options, store, makeSnapshot(imported, options), {
      origin, savedPair: saved.pair, loading: !!startupPair, lastLoad: null,
      persistence: origin === 'saved' ? { status: 'remembered' } : noPersistence,
      diagnostics, ...(fieldErrors ? { fieldErrors } : {}),
    }, startupPair);
  }

  get snapshot(): WorkspaceSnapshot { return this.active; }
  get workspace(): Workspace { return this.active.workspace; }
  get sources(): WorkspaceSourceState { return { ...this.state, generation: this.active.generation, sources: this.active.sources }; }
  get version(): WorkspaceVersion { return { generation: this.active.generation, loading: this.state.loading, lastLoadId: this.state.lastLoad?.id ?? null }; }

  private async remember(pair: SourcePair, roots: string[]): Promise<PersistenceOutcome> {
    try {
      await this.options.sourceHooks?.beforeSave?.();
      await this.store.save(pair, roots);
      this.state.savedPair = pair;
      this.state.diagnostics = [];
      this.state.fieldErrors = undefined;
      return { status: 'remembered' };
    } catch {
      return { status: 'session_only', message: 'Loaded for this session; paths could not be remembered. Previous saved settings were left unchanged.' };
    }
  }

  /** Called only after listening; the startup lock is already held. */
  async finishStartup(): Promise<void> {
    if (!this.startupPair) return;
    try { this.state.persistence = await this.remember(this.startupPair, this.active.sources.map((source) => source.inputPath)); }
    finally { this.state.loading = false; }
  }

  async load(request: SourceLoadRequest): Promise<WorkspaceSourceState> {
    if (this.state.loading) throw new SourceLoadError(409, 'load_in_progress', 'A report load is already in progress. Wait for its result before trying again.', this.active.generation);
    if (request.expectedGeneration !== this.active.generation) throw new SourceLoadError(409, 'workspace_changed', 'The workspace changed. Refresh the source selection before loading reports.', this.active.generation);
    this.state.loading = true;
    const id = randomUUID();
    try {
      await this.options.sourceHooks?.beforeLoad?.();
      const { imported, pair } = await importPair(request, this.options);
      const candidate = makeSnapshot(imported, this.options);
      const persistence = await this.remember(pair, [...this.active.sources, ...candidate.sources].map((source) => source.inputPath));
      // No awaits between publishing these values: all readers observe a whole
      // generation, including its persistence result and current source list.
      this.active = candidate;
      this.state = { ...this.state, origin: 'settings', loading: false, persistence, diagnostics: [],
        fieldErrors: undefined, lastLoad: { id, status: 'success', generation: candidate.generation,
          message: persistence.status === 'remembered' ? 'Reports loaded and paths remembered.' : persistence.message!, persistence } };
      return this.sources;
    } catch (error) {
      const fields = error instanceof PairAdmissionError ? error.fieldErrors : undefined;
      const message = error instanceof PairAdmissionError ? error.message : 'The report pair could not be prepared. Existing reports remain loaded.';
      this.state.loading = false;
      this.state.fieldErrors = fields;
      this.state.lastLoad = { id, status: 'failed', generation: this.active.generation, message, persistence: noPersistence, ...(fields ? { fieldErrors: fields } : {}) };
      throw new SourceLoadError(fields ? 422 : 500, fields ? 'invalid_sources' : 'load_failed', message, this.active.generation, fields);
    }
  }
}
