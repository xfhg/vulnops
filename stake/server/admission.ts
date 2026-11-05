import { realpath } from 'node:fs/promises';
import { resolve } from 'node:path';
import type { AdmittedBundle, ImportFailure, Workspace } from '../src/domain/types.js';
import { normalizeWorkspace } from '../src/domain/index.js';
import { bridgeCall, BridgeError, checkPrerequisites, type BridgeOptions } from './bridge.js';
import type { SourcePair, SourceFieldErrors } from '../src/domain/sources.js';
import { validSourcePath } from './settings.js';

export interface ImportedBundle extends AdmittedBundle { inputPath: string; markdown: string }
export interface ImportResult { bundles: ImportedBundle[]; workspace: Workspace }
export class PairAdmissionError extends Error {
  constructor(public fieldErrors: SourceFieldErrors) { super('Both report folders must pass admission before the workspace can change.'); }
}

export async function importPair(pair: SourcePair, options: BridgeOptions = {}): Promise<{ imported: ImportResult; pair: SourcePair }> {
  const errors: SourceFieldErrors = {};
  const canonical: Partial<SourcePair> = {};
  for (const role of ['ordinaryPath', 'advantagePath'] as const) {
    if (!validSourcePath(pair[role])) { errors[role] = 'Enter a nonempty absolute directory path without control characters (at most 16 KiB).'; continue; }
    try { canonical[role] = await realpath(pair[role]); }
    catch { errors[role] = 'Input run directory is unavailable.'; }
  }
  if (canonical.ordinaryPath && canonical.ordinaryPath === canonical.advantagePath) {
    errors.ordinaryPath = errors.advantagePath = 'Ordinary and Advantage reports must resolve to different run directories.';
  }
  if (Object.keys(errors).length) throw new PairAdmissionError(errors);
  const resolved = canonical as SourcePair;
  const imported = await importBundles([resolved.ordinaryPath, resolved.advantagePath], options);
  for (const [role, kind] of [['ordinaryPath', 'audit'], ['advantagePath', 'advantage']] as const) {
    const bundle = imported.bundles.find((item) => item.inputPath === resolved[role]);
    if (!bundle) errors[role] = imported.workspace.failures.find((failure) => failure.inputPath === resolved[role])?.message ?? 'Publication could not be admitted.';
    else if (bundle.execution_kind !== kind) errors[role] = `Select ${kind === 'audit' ? 'an ordinary' : 'an Advantage'} publication for this field.`;
  }
  if (Object.keys(errors).length) throw new PairAdmissionError(errors);
  return { imported, pair: resolved };
}

function freeze(value: unknown): void {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const item of Object.values(value)) freeze(item);
  }
}

export async function importBundles(paths: string[], options: BridgeOptions & { cwd?: string } = {}): Promise<ImportResult> {
  await checkPrerequisites(options);
  const failures: ImportFailure[] = [];
  const roots = new Set<string>();
  for (const input of paths) {
    const inputPath = resolve(options.cwd ?? process.cwd(), input);
    try { roots.add(await realpath(inputPath)); }
    catch { failures.push({ inputPath, code: 'unavailable', message: 'Input run directory is unavailable.' }); }
  }
  const results = await Promise.all([...roots].map(async (inputPath) => {
    try {
      const bundle = await bridgeCall<ImportedBundle>({ operation: 'admit', root: inputPath }, options);
      return { ...bundle, inputPath };
    } catch (error) {
      failures.push({ inputPath, code: error instanceof BridgeError ? error.code : 'invalid_input',
        message: error instanceof BridgeError ? error.message : 'Publication could not be loaded.' });
      return null;
    }
  }));
  const groups = new Map<string, ImportedBundle[]>();
  for (const bundle of results) if (bundle) groups.set(bundle.run_id, [...(groups.get(bundle.run_id) ?? []), bundle]);
  const unique: ImportedBundle[] = [];
  for (const [runId, candidates] of groups) {
    if (candidates.length === 1) unique.push(candidates[0]!);
    else for (const candidate of candidates) failures.push({ inputPath: candidate.inputPath, runId,
      code: 'execution_conflict', message: 'Distinct supplied roots claim the same execution. Select only one root for this execution.' });
  }
  const workspace = normalizeWorkspace(unique, failures);
  const available = new Set(workspace.assessments.map((assessment) => assessment.id));
  const bundles = unique.filter((bundle) => available.has(bundle.run_id));
  // Serving cannot change this captured publication authority. Optional evidence
  // is separately cached on its first admitted read for this workspace snapshot.
  for (const bundle of bundles) freeze(bundle);
  freeze(workspace);
  return { bundles, workspace };
}
