import { ArchiveError } from './types';

const encoder = new TextEncoder();
const DEFAULT_LIMIT = 16 * 1024 * 1024;
const forbiddenKeys = new Set(['raw_output', 'raw_scanner_output', 'proof_token', 'stdout', 'stderr']);
const secretPatterns = [
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
  /ghp_[A-Za-z0-9]{20,}/,
  /AKIA[0-9A-Z]{16}/,
  /sk-[A-Za-z0-9]{20,}/,
  /\bauthorization\s*:\s*(?:bearer|basic)\s+(?!<redacted>(?:$|[\s"'\\,]))[^\s"'\\,]+/i,
];

/** Mirrors scripts/artifact_policy.py. Report JSON/Markdown have no legacy ceiling. */
export function artifactSizeLimit(relative: string): number | null {
  const parts = relative.split('/'), name = parts.at(-1) ?? '';
  if (parts.at(-2) === 'report' && ['security-report.json', 'security-report.md'].includes(name)) return null;
  if (relative === 'campaign-planning/discovery.json') return 2 * 1024 * 1024;
  if (name.endsWith('receipt.json')) return 64 * 1024;
  if (name === 'context.json' || parts.includes('report')) return 2 * 1024 * 1024;
  return DEFAULT_LIMIT;
}

/** Python JSON's default separators include a space after commas and colons. */
function publicationEncodedSize(value: unknown): number {
  const serialized = JSON.stringify(value);
  if (serialized === undefined) throw new ArchiveError('invalid_content', 'Publication contains an unsupported JSON value.');
  let quoted = false, escaped = false, spaces = 0;
  for (const character of serialized) {
    if (escaped) { escaped = false; continue; }
    if (quoted && character === '\\') { escaped = true; continue; }
    if (character === '"') quoted = !quoted;
    else if (!quoted && (character === ',' || character === ':')) spaces++;
  }
  return encoder.encode(serialized).byteLength + spaces;
}

export function validatePublicationContent(value: unknown, sizeLimit: number | null = DEFAULT_LIMIT): void {
  const pending: Array<[unknown, number]> = [[value, 0]];
  while (pending.length) {
    const [item, depth] = pending.pop()!;
    if (depth > 64) throw new ArchiveError('invalid_content', 'Publication exceeds the 64-level content bound.');
    if (typeof item === 'string') {
      if (secretPatterns.some(pattern => pattern.test(item))) throw new ArchiveError('denied', 'Artifact fails publication hygiene.');
      // Python's UTF-8 publication serializer rejects unpaired surrogate values.
      for (let index = 0; index < item.length; index++) {
        const code = item.charCodeAt(index);
        if (code >= 0xd800 && code <= 0xdbff) {
          const next = item.charCodeAt(++index);
          if (!(next >= 0xdc00 && next <= 0xdfff)) throw new ArchiveError('invalid_content', 'Artifact contains invalid Unicode text.');
        } else if (code >= 0xdc00 && code <= 0xdfff) throw new ArchiveError('invalid_content', 'Artifact contains invalid Unicode text.');
      }
    } else if (Array.isArray(item)) {
      for (const child of item) pending.push([child, depth + 1]);
    } else if (item && typeof item === 'object') {
      for (const [key, child] of Object.entries(item)) {
        if (forbiddenKeys.has(key)) throw new ArchiveError('denied', 'Raw execution, scanner or proof material is not publishable.');
        pending.push([key, depth + 1], [child, depth + 1]);
      }
    } else if (typeof item === 'number' && !Number.isFinite(item)) {
      throw new ArchiveError('invalid_content', 'Publication contains a non-finite number.');
    }
  }
  if (sizeLimit !== null && publicationEncodedSize(value) > sizeLimit)
    throw new ArchiveError('denied', 'Artifact exceeds its publication size limit.');
}

export function parseArtifactJson(text: string, relative: string): unknown {
  const limit = artifactSizeLimit(relative);
  validatePublicationContent(text, limit);
  let value: unknown;
  try { value = JSON.parse(text); }
  catch { throw new ArchiveError('invalid_content', 'Artifact is not valid UTF-8 JSON.'); }
  validatePublicationContent(value, limit);
  return value;
}
