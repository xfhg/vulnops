/** JSON tuples encode boundaries without collisions between user-controlled IDs. */
export function qualifiedKey(kind: string, ...parts: Array<string | number | null>): string {
  return JSON.stringify([kind, ...parts]);
}
export function findingKey(runId: string, id: string): string {
  return qualifiedKey('finding', runId, id);
}
export function localEntityKey(key: string, kind: string, id: string | number): string {
  return qualifiedKey('entity', key, kind, id);
}
export function evidenceKey(runId: string, artifact: string, selector: string | null = null): string {
  return qualifiedKey('evidence', runId, artifact, selector);
}
/** Object key ordering is presentation-irrelevant; array order and values are not. */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null';
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const object = value as Record<string, unknown>;
  return `{${Object.keys(object).sort().map(key => `${JSON.stringify(key)}:${canonicalJson(object[key])}`).join(',')}}`;
}
