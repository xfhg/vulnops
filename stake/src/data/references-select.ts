import { EvidenceSelectorError, referenceParts } from './references';

/** Mirrors scripts/evidence_refs.py; extensions outside these collections are inert. */
export const RECORD_COLLECTIONS: Readonly<Record<string, readonly string[]>> = Object.freeze({
  'repo-context.json': ['projects', 'actors'],
  'security-surfaces.json': ['entry_points', 'trust_boundaries', 'attack_paths'],
  'threat-model.json': ['assets', 'trust_boundaries', 'entrypoints', 'subsystems', 'threats', 'hunt_mappings', 'attack_paths', 'attack_classes', 'attack_objectives', 'investigation_questions'],
  'hunt-plan.json': ['cells', 'tasks', 'attack_objectives', 'investigation_questions'],
  'coverage-ledger.json': ['cells', 'tasks', 'attack_objectives', 'investigation_questions'],
  'wishlist.json': ['items'],
  'evidence-index.json': ['records', 'primitives', 'attack_objectives', 'investigation_questions'],
  'campaign-plan.json': ['campaigns', 'attack_objectives', 'investigation_questions'],
  'discovery.json': ['questions', 'relationships', 'scanner_triage', 'attack_objectives', 'investigation_questions'],
  'sca-advisories.json': ['advisories'],
  'secrets-redacted.json': ['candidates'],
  'dependency-limitations.json': ['limitations'],
  'intrusion-results.json': ['results'],
  'findings.json': ['findings', 'unreviewed'],
});

const object = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === 'object' && !Array.isArray(value);
const own = (value: Record<string, unknown>, key: string): unknown => Object.hasOwn(value, key) ? value[key] : undefined;
const truthy = (value: unknown): boolean => Boolean(value) && !(Array.isArray(value) && value.length === 0) && !(object(value) && Object.keys(value).length === 0);

/** RFC6901 only: no URI decoding, prototype lookup, array aliases or JSONPath. */
export function resolveEvidencePointer(value: unknown, pointer: string): unknown {
  if (!pointer) return value;
  if (!pointer.startsWith('/')) throw new EvidenceSelectorError('unsupported_selector');
  for (const raw of pointer.slice(1).split('/')) {
    if (/~(?![01])/.test(raw)) throw new EvidenceSelectorError('unsupported_selector');
    const key = raw.replace(/~1/g, '/').replace(/~0/g, '~');
    if (Array.isArray(value)) {
      if (!/^(0|[1-9][0-9]*)$/.test(key)) throw new EvidenceSelectorError('unsupported_selector');
      const index = Number(key);
      if (!Number.isSafeInteger(index) || index >= value.length) throw new EvidenceSelectorError('missing_record');
      value = value[index];
    } else {
      if (!object(value) || !Object.hasOwn(value, key)) throw new EvidenceSelectorError('missing_record');
      value = value[key];
    }
  }
  return value;
}

/** Exact port of server/publication_bridge.py::select_value, not a recursive ID search. */
export function selectEvidenceValue(value: unknown, reference: string): unknown {
  const split = referenceParts(reference);
  if (!split) throw new EvidenceSelectorError('unsupported_selector');
  const { path, selector: identifier } = split;
  if (identifier.startsWith('/') && reference.includes('#')) return resolveEvidencePointer(value, identifier);
  if (!identifier) {
    if (/[:#]/.test(reference)) throw new EvidenceSelectorError('unsupported_selector');
    return value;
  }
  if (/[:#]/.test(identifier)) throw new EvidenceSelectorError('unsupported_selector');
  const name = path.split('/').at(-1)!;
  let collections = RECORD_COLLECTIONS[name] ?? [];
  if (path.startsWith('sast/deepdive/')) collections = ['candidates', 'cell_results', 'rabbit_holes', 'attack_objectives', 'investigation_questions', 'model_amendments'];
  else if (path.startsWith('repo-context/research/')) collections = ['observations', 'attack_paths'];
  else if (path.startsWith('intrusion/results/') || /^investigation\/passes\/[^/]+\/results\/[^/]+\.json$/.test(path)) collections = ['candidates', 'primitive_updates'];
  else if (path.startsWith('gap-exploration/')) collections = ['candidates', 'objectives', 'questions'];
  else if (path.startsWith('intrusion/waves/')) collections = ['primitives', 'attack_objectives', 'investigation_questions'];
  const rootKeys = ['hardening-notes.json', 'positive-patterns.json'].includes(name) ? []
    : path.startsWith('intrusion/results/') ? ['campaign_id'] : collections.length ? [] : ['id', 'finding_id', 'candidate_id'];
  const matches: unknown[] = [];
  const pending: Array<{ node: unknown; children: readonly string[]; keys: readonly string[] }> = [{ node: value, children: collections, keys: rootKeys }];
  while (pending.length) {
    const { node, children, keys } = pending.pop()!;
    if (Array.isArray(node)) {
      for (let index = node.length - 1; index >= 0; index--) pending.push({ node: node[index], children, keys });
    } else if (object(node)) {
      const owner = keys.map(key => own(node, key)).find(truthy);
      if (identifier === owner) { matches.push(node); continue; }
      for (let index = children.length - 1; index >= 0; index--) {
        const key = children[index]!;
        const intrusionResults = key === 'results' && path.startsWith('intrusion/');
        const nested = intrusionResults ? ['candidates', 'primitive_updates'] : key === 'projects' ? ['entry_points'] : key === 'model_amendments' ? ['entity'] : [];
        const childKeys = intrusionResults ? ['campaign_id'] : key === 'cell_results' ? ['cell_id'] : key === 'scanner_triage' ? ['evidence_id'] : key === 'limitations' ? ['code'] : ['id'];
        pending.push({ node: own(node, key), children: nested, keys: childKeys });
      }
    }
  }
  if (matches.length !== 1) throw new EvidenceSelectorError(matches.length ? 'ambiguous_record' : 'missing_record');
  return matches[0];
}
