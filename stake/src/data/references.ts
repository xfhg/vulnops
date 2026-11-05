import type { AdmittedBundle, Workspace } from '../domain/types';

export interface ReferenceEntry {
  token: string;
  executionId: string;
  reference: string;
  label: string;
  kind: 'artifact' | 'source' | 'denied';
  message?: string;
}
export interface EvidenceResult extends ReferenceEntry {
  status: 'available' | 'unavailable' | 'source' | 'denied';
  content?: unknown;
  format?: 'json' | 'text';
}

export interface EvidenceBundle extends AdmittedBundle { inputPath: string; markdown: string }
export interface ArtifactValue { content: unknown; format: 'json' | 'text' }
export interface EvidenceIO {
  createToken: (generation: string, owner: string, reference: string) => string;
  readArtifact: (bundle: EvidenceBundle, path: string) => Promise<ArtifactValue>;
  selectArtifact: (value: unknown, reference: string) => ArtifactValue | Promise<ArtifactValue>;
  describeError: (error: unknown) => { denied: boolean; message: string };
}

const prefixes = new Set(['repo-context', 'tool-collection', 'sast', 'campaign-planning', 'intrusion', 'gap-exploration', 'synthesis', 'final-verification', 'report', 'baseline', 'planning', 'investigation', 'handoff']);
const forbidden = new Set(['drafts', 'recovery-archives', 'runtime', 'work', '.harness', 'raw', 'raw-output', '__pycache__']);
const refFields = new Set(['artifact_ref', 'evidence_ref', 'evidence_refs', 'observation_refs', 'source_validation_refs', 'independent_verification_ref', 'reproduction_ref', 'graph_receipt_refs', 'canonical_refs', 'result_ref', 'actions_ref', 'reference', 'ref', 'source_ref', 'source_refs']);
const keyFor = (owner: string, ref: string) => JSON.stringify([owner, ref]);
const object = (value: unknown): value is Record<string, unknown> => !!value && typeof value === 'object' && !Array.isArray(value);

export function referenceParts(reference: string): { path: string; selector: string } | null {
  if (!reference || reference.length > 4096 || /[\x00-\x1f\\]/.test(reference)) return null;
  const offset = reference.search(/[:#]/);
  const path = offset < 0 ? reference : reference.slice(0, offset);
  const selector = offset < 0 ? '' : reference.slice(offset + 1);
  const pieces = path.split('/');
  if (pieces.some((piece) => !piece || piece === '.' || piece === '..') || path.startsWith('/') || /^(?:https?|file|ftp|data|javascript|vbscript|mailto):/i.test(reference) || /^[a-z][a-z0-9+.-]*:\/\//i.test(reference)) return null;
  return { path, selector };
}

export class SharedEvidenceRegistry {
  private readonly entries = new Map<string, ReferenceEntry>();
  private readonly lookup = new Map<string, string>();
  private readonly roots: Map<string, EvidenceBundle>;
  private readonly cache = new Map<string, Promise<EvidenceResult>>();
  private readonly artifacts = new Map<string, Promise<{ content: unknown; format: 'json' | 'text' }>>();

  constructor(bundles: EvidenceBundle[], workspace: Workspace, private readonly generation: string, private readonly io: EvidenceIO) {
    this.roots = new Map(bundles.map((bundle) => [bundle.run_id, bundle]));
    for (const bundle of bundles) {
      for (const reference of ['report/security-report.json', 'report/security-report.md', 'final-verification/findings.json']) this.register(bundle.run_id, reference);
      this.artifacts.set(keyFor(bundle.run_id, 'report/security-report.json'), Promise.resolve({ content: bundle.report, format: 'json' }));
      this.artifacts.set(keyFor(bundle.run_id, 'report/security-report.md'), Promise.resolve({ content: bundle.markdown, format: 'text' }));
      this.artifacts.set(keyFor(bundle.run_id, 'final-verification/findings.json'), Promise.resolve({ content: bundle.final, format: 'json' }));
      this.collect(bundle.report, bundle.run_id);
    }
    // Normalized historical records carry their original execution owner; their
    // untyped references must not accidentally point at Advantage's local files.
    for (const finding of workspace.findings) this.collect(finding.raw, finding.runId);
  }

  private register(owner: string, original: unknown): ReferenceEntry | undefined {
    let ref = original;
    if (object(original) && typeof original.artifact_ref === 'string') {
      if (typeof original.execution_id === 'string') owner = original.execution_id;
      ref = original.artifact_ref;
    }
    if (typeof ref !== 'string') return undefined;
    const key = keyFor(owner, ref);
    const prior = this.lookup.get(key);
    if (prior) return this.entries.get(prior);
    const token = this.io.createToken(this.generation, owner, ref);
    const split = referenceParts(ref);
    let kind: ReferenceEntry['kind'] = 'source';
    let message: string | undefined;
    if (!split) { kind = 'denied'; message = 'Noncanonical reference is not navigable.'; }
    else {
      const segments = split.path.split('/');
      if (forbidden.has(segments[0]!) || segments.some((segment) => forbidden.has(segment)) || ['context.json', 'input.json', 'dispatch.json', 'run-manifest.json', 'advantage-manifest.json', 'task-ledger.json', '.recovery-invalidation.json'].includes(segments.at(-1)!)) {
        kind = 'denied'; message = 'Runtime and diagnostic artifacts are not delivered evidence.';
      } else if (prefixes.has(segments[0]!)) {
        kind = /\.(json|md|txt)$/.test(split.path) ? 'artifact' : 'denied';
        if (kind === 'denied') message = 'Unsupported evidence format.';
      }
    }
    const entry: ReferenceEntry = { token, executionId: owner, reference: ref,
      label: kind === 'denied' ? 'Unavailable reference' : ref, kind, ...(message ? { message } : {}) };
    this.lookup.set(key, token);
    this.entries.set(token, entry);
    if (kind === 'source' && split?.selector.includes(',')) {
      // A recorded disjoint source citation also admits each exact range for
      // the citation map. These entries remain inert; no source is read.
      for (const range of split.selector.split(',').map((part) => part.trim())) {
        if (/^[1-9]\d*(?:-[1-9]\d*)?$/.test(range)) this.register(owner, `${split.path}:${range}`);
      }
    }
    return entry;
  }

  private collect(value: unknown, owner: string, depth = 0): void {
    if (depth > 64) return;
    if (Array.isArray(value)) { for (const item of value) this.collect(item, owner, depth + 1); return; }
    if (!object(value)) return;
    let nextOwner = owner;
    if (typeof value.execution_id === 'string' && typeof value.artifact_ref === 'string') {
      this.register(owner, value);
      nextOwner = value.execution_id;
    }
    for (const [field, item] of Object.entries(value)) {
      // Historical wrappers are processed separately using normalized ownership.
      if (field === 'historical_findings') continue;
      if (refFields.has(field)) {
        const values = Array.isArray(item) ? item : [item];
        for (const ref of values) this.register(nextOwner, ref);
      }
      if (field === 'file' && typeof item === 'string') {
        const line = value.line ?? value.start_line;
        this.register(nextOwner, `${item}${typeof line === 'number' ? `:${line}` : ''}`);
        if (typeof line === 'number' && typeof value.end_line === 'number' && value.end_line !== line) this.register(nextOwner, `${item}:${line}-${value.end_line}`);
      }
      this.collect(item, nextOwner, depth + 1);
    }
  }

  find(owner: string, reference: unknown): ReferenceEntry | undefined {
    let value: string;
    if (typeof reference === 'string') value = reference;
    else if (object(reference) && typeof reference.artifact_ref === 'string') {
      if (typeof reference.execution_id === 'string') owner = reference.execution_id;
      value = reference.artifact_ref;
    } else if (object(reference) && object(reference.artifact_ref)) {
      return this.find(owner, reference.artifact_ref);
    } else return undefined;
    const token = this.lookup.get(keyFor(owner, value));
    return token ? this.entries.get(token) : undefined;
  }

  async read(token: string): Promise<EvidenceResult | undefined> {
    const entry = this.entries.get(token);
    if (!entry) return undefined;
    let result = this.cache.get(token);
    if (!result) { result = this.load(entry); this.cache.set(token, result); }
    return result;
  }

  private async load(entry: ReferenceEntry): Promise<EvidenceResult> {
    if (entry.kind === 'source') return { ...entry, status: 'source', message: 'Assessed source citation. A source checkout is not loaded; no current source is read.' };
    if (entry.kind === 'denied') return { ...entry, status: 'denied' };
    const bundle = this.roots.get(entry.executionId);
    if (!bundle) return { ...entry, status: 'unavailable', message: 'The owning execution was not supplied as an available input.' };
    try {
      const split = referenceParts(entry.reference)!;
      const artifactKey = keyFor(entry.executionId, split.path);
      let artifact = this.artifacts.get(artifactKey);
      if (!artifact) {
        artifact = this.io.readArtifact(bundle, split.path);
        this.artifacts.set(artifactKey, artifact);
      }
      const whole = await artifact;
      let value = whole;
      if (entry.reference !== split.path) {
        if (whole.format !== 'json') throw new EvidenceSelectorError('unsupported_selector', 'Text artifacts cannot carry record selectors.');
        value = await this.io.selectArtifact(whole.content, entry.reference);
      }
      this.collect(value.content, entry.executionId);
      return { ...entry, status: 'available', ...value };
    } catch (error) {
      const problem = error instanceof EvidenceSelectorError ? { denied: false, message: error.message } : this.io.describeError(error);
      return { ...entry, status: problem.denied ? 'denied' : 'unavailable', message: problem.message };
    }
  }
}

/** Bounded selector diagnostics never echo artifact content. */
export class EvidenceSelectorError extends Error {
  constructor(public code: 'unsupported_selector' | 'missing_record' | 'ambiguous_record', message = 'Evidence selector is missing, ambiguous, or unsupported.') { super(message); }
}
