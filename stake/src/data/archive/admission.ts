import { canonicalJson, normalizeWorkspace } from '../../domain';
import type { JsonRecord, Workspace } from '../../domain/types';
import { artifactSizeLimit, parseArtifactJson, validatePublicationContent } from './hygiene';
import { ArchiveError, type ArchiveBundle, type ArchiveProgress, type PublicationReader } from './types';

const record = (value: unknown): value is JsonRecord => value !== null && typeof value === 'object' && !Array.isArray(value);
const own = (value: JsonRecord, key: string) => Object.prototype.hasOwnProperty.call(value, key);
const string = (value: unknown) => typeof value === 'string' && value.length > 0;
const metadataKeys = new Set(['execution_kind', 'repository', 'repositories', 'model_routing', 'producer_routes', 'target_fingerprint', 'markdown_sha256', 'published_at', 'publication_method', 'retained_evidence', 'mode', 'options', 'baseline', 'action_source', 'patch_binding', 'source', 'gap_exploration']);
function invalidIdentity(): never { throw new ArchiveError('invalid_publication', 'Publication identity or metadata structure is invalid.'); }

/** Consumed publication-metadata.schema.json contract, differential-tested against Python. */
export function validatePublicationMetadata(value: unknown): asserts value is JsonRecord {
  if (!record(value) || Object.keys(value).some(key => !metadataKeys.has(key))) invalidIdentity();
  if (!['audit', 'advantage'].includes(String(value.execution_kind)) || !string(value.repository) || !Array.isArray(value.repositories)
    || value.repositories.some(repository => !record(repository)) || !record(value.model_routing) || !record(value.producer_routes)
    || Object.values(value.producer_routes).some(route => !record(route))) invalidIdentity();
  for (const key of ['target_fingerprint', 'markdown_sha256']) if (own(value, key) && (typeof value[key] !== 'string' || !/^[0-9a-f]{64}$/.test(value[key]))) invalidIdentity();
  if (own(value, 'published_at') && !string(value.published_at)) invalidIdentity();
  if (own(value, 'publication_method') && value.publication_method !== 'retained_evidence') invalidIdentity();
  if (own(value, 'mode') && !['standard', 'deep', 'diff', 'actions'].includes(String(value.mode))) invalidIdentity();
  for (const key of ['options', 'baseline']) if (own(value, key) && !record(value[key])) invalidIdentity();
  for (const key of ['action_source', 'patch_binding']) if (own(value, key) && value[key] !== null && !record(value[key])) invalidIdentity();
  if (own(value, 'source')) {
    const source = value.source;
    if (!record(source) || Object.keys(source).some(key => !['source_run_id', 'source_scan', 'source_repository', 'finding_source'].includes(key))) invalidIdentity();
    for (const key of ['source_run_id', 'source_scan', 'source_repository']) if (own(source, key) && typeof source[key] !== 'string') invalidIdentity();
    if (own(source, 'finding_source') && source.finding_source !== null && !record(source.finding_source)) invalidIdentity();
  }
  for (const [key, ref] of [['retained_evidence', 'report/publication-receipt.json'], ['gap_exploration', 'gap-exploration/results.json']] as const) {
    if (!own(value, key)) continue;
    const binding = value[key];
    if (!record(binding) || Object.keys(binding).some(name => !['ref', 'sha256'].includes(name)) || binding.ref !== ref
      || typeof binding.sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(binding.sha256)) invalidIdentity();
  }
}

async function document(reader: PublicationReader, root: string, path: string): Promise<JsonRecord> {
  const value = parseArtifactJson(await reader.readText(root, path, artifactSizeLimit(path) ?? undefined), path);
  if (!record(value)) throw new ArchiveError('invalid_content', `${path}: expected a JSON object.`);
  return value;
}

export async function admitPublication(reader: PublicationReader, root: string): Promise<ArchiveBundle> {
  async function required<T>(path: string, read: () => Promise<T>): Promise<T> {
    try { return await read(); }
    catch (error) {
      if (error instanceof ArchiveError) throw new ArchiveError(error.code, `${path}: ${error.message}`);
      throw new ArchiveError('invalid_content', `${path}: publication content could not be read.`);
    }
  }
  const report = await required('report/security-report.json', () => document(reader, root, 'report/security-report.json'));
  if (report.schema_version !== '2.0') throw new ArchiveError('unsupported', 'Expected a supported schema 2.0 publication.');
  if (own(report, 'publication') && !record(report.publication)) invalidIdentity();
  const initialMetadata = record(report.publication) ? report.publication : {};
  if ((own(report, 'mode') ? report.mode : initialMetadata.mode) === 'actions') throw new ArchiveError('unsupported', 'Actions-only Advantage reports are not supported.');
  const markdown = await required('report/security-report.md', async () => {
    const text = await reader.readText(root, 'report/security-report.md');
    validatePublicationContent(text, null); return text;
  });
  const final = await required('final-verification/findings.json', () => document(reader, root, 'final-verification/findings.json'));
  if (!Array.isArray(final.findings) || canonicalJson(final.findings) !== canonicalJson(report.findings))
    throw new ArchiveError('invalid_authority', 'report/security-report.json findings differ from final-verification/findings.json.');
  let runId = report.run_id, metadata: JsonRecord;
  if (report.publication === undefined) {
    const names = ['run-manifest.json', 'advantage-manifest.json'].filter(name => reader.has(root, name));
    if (names.length !== 1) throw new ArchiveError('invalid_publication', 'Legacy publication requires exactly one completed identity manifest.');
    const old = await required(names[0], () => document(reader, root, names[0]));
    if (!own(report, 'run_id')) runId = old.run_id;
    if (old.status !== 'complete' || old.run_id !== runId) throw new ArchiveError('invalid_publication', 'Legacy publication is not its completed execution.');
    metadata = Object.fromEntries(['repository', 'repositories', 'model_routing', 'mode', 'options', 'patch_binding', 'target_fingerprint', 'baseline', 'action_source'].filter(key => own(old, key)).map(key => [key, old[key]]));
    metadata.execution_kind = names[0] === 'advantage-manifest.json' ? 'advantage' : 'audit';
    metadata.producer_routes = {};
    metadata.source = Object.fromEntries(['source_run_id', 'source_scan', 'source_repository', 'finding_source'].filter(key => own(old, key)).map(key => [key, old[key]]));
  } else { validatePublicationMetadata(report.publication); metadata = { ...report.publication }; }
  if (metadata.mode === 'actions') throw new ArchiveError('unsupported', 'Actions-only Advantage reports are not supported.');
  if (!record(own(report, 'summary') ? report.summary : report.counts) || !Array.isArray(report.findings)
    || !string(runId) || !string(metadata.repository) || !['audit', 'advantage'].includes(String(metadata.execution_kind))) invalidIdentity();
  for (const [key, type] of [['repositories', 'array'], ['model_routing', 'object'], ['producer_routes', 'object']])
    if (own(metadata, key) && (type === 'array' ? !Array.isArray(metadata[key]) : !record(metadata[key]))) invalidIdentity();
  if (own(report, 'execution_kind') && report.execution_kind !== metadata.execution_kind || own(final, 'run_id') && final.run_id !== runId) invalidIdentity();
  const bundle: ArchiveBundle = { ...metadata, report, final, run_id: runId as string, execution_kind: metadata.execution_kind as 'audit' | 'advantage',
    inputPath: root, markdown, assessment: record(report.assessment) ? report.assessment : {} };
  validatePublicationContent(bundle, null);
  return bundle;
}

export async function admitArchive(reader: PublicationReader, roots: string[], onProgress?: (progress: ArchiveProgress) => void): Promise<{ bundles: ArchiveBundle[]; workspace: Workspace }> {
  if (roots.length !== 2) throw new ArchiveError('invalid_layout', 'Select one ZIP containing exactly two sibling report folders.');
  const bundles: ArchiveBundle[] = [];
  for (const root of roots) {
    onProgress?.({ phase: 'validating', completed: bundles.length, total: 2 });
    bundles.push(await admitPublication(reader, root));
  }
  if (bundles[0].run_id === bundles[1].run_id) throw new ArchiveError('execution_conflict', 'Distinct report folders claim the same execution.');
  if (new Set(bundles.map(bundle => bundle.execution_kind)).size !== 2) throw new ArchiveError('invalid_roles', 'The ZIP must contain one ordinary and one Advantage publication.');
  const workspace = normalizeWorkspace(bundles);
  if (workspace.failures.length || workspace.assessments.length !== 2) throw new ArchiveError('invalid_publication', workspace.failures[0]?.message ?? 'Both publications must pass structural admission.');
  onProgress?.({ phase: 'validating', completed: 2, total: 2 });
  return { bundles, workspace };
}
