import { deflateRawSync } from 'node:zlib';
import { makePublication, type PublicationOptions } from './fixtures/bundles';

export interface ZipFixtureEntry {
  name: string; text?: string; bytes?: Uint8Array; method?: number; flags?: number; attributes?: number;
  declaredSize?: number; crc?: number; localOffset?: number;
}
const encoder = new TextEncoder();
export function crc32(bytes: Uint8Array): number {
  let result = 0xffffffff;
  for (const byte of bytes) {
    result ^= byte;
    for (let index = 0; index < 8; index++) result = (result >>> 1) ^ (0xedb88320 & -(result & 1));
  }
  return (result ^ 0xffffffff) >>> 0;
}

/** Minimal ZIP fixture builder deliberately permits malformed metadata. No real reports. */
export function zipFixture(entries: ZipFixtureEntry[]): Blob {
  const localParts: Uint8Array[] = [], centralParts: Uint8Array[] = [];
  let offset = 0;
  for (const entry of entries) {
    const name = encoder.encode(entry.name), bytes = entry.bytes ?? encoder.encode(entry.text ?? '');
    const compressed = entry.method === 8 ? new Uint8Array(deflateRawSync(bytes)) : bytes;
    const checksum = entry.crc ?? crc32(bytes), size = entry.declaredSize ?? bytes.length;
    const local = new Uint8Array(30 + name.length), lh = new DataView(local.buffer);
    lh.setUint32(0, 0x04034b50, true); lh.setUint16(4, 20, true); lh.setUint16(6, entry.flags ?? 0x800, true);
    lh.setUint16(8, entry.method ?? 0, true); lh.setUint32(14, checksum, true); lh.setUint32(18, compressed.length, true);
    lh.setUint32(22, size, true); lh.setUint16(26, name.length, true); local.set(name, 30);
    const central = new Uint8Array(46 + name.length), ch = new DataView(central.buffer);
    ch.setUint32(0, 0x02014b50, true); ch.setUint16(4, 0x0314, true); ch.setUint16(6, 20, true);
    ch.setUint16(8, entry.flags ?? 0x800, true); ch.setUint16(10, entry.method ?? 0, true);
    ch.setUint32(16, checksum, true); ch.setUint32(20, compressed.length, true); ch.setUint32(24, size, true);
    ch.setUint16(28, name.length, true); ch.setUint32(38, entry.attributes ?? (entry.name.endsWith('/') ? 0x41ed0010 : 0x81a40000), true);
    ch.setUint32(42, entry.localOffset ?? offset, true); central.set(name, 46);
    localParts.push(local, compressed); centralParts.push(central); offset += local.length + compressed.length;
  }
  const directorySize = centralParts.reduce((sum, item) => sum + item.length, 0);
  const end = new Uint8Array(22), eh = new DataView(end.buffer);
  eh.setUint32(0, 0x06054b50, true); eh.setUint16(8, entries.length, true); eh.setUint16(10, entries.length, true);
  eh.setUint32(12, directorySize, true); eh.setUint32(16, offset, true);
  return new Blob([...localParts, ...centralParts, end] as BlobPart[]);
}

export function publicationEntries(root: string, options: PublicationOptions = {}): ZipFixtureEntry[] {
  const bundle = makePublication(options);
  const result = [
    { name: `${root}/report/security-report.json`, text: JSON.stringify(bundle.report) },
    { name: `${root}/report/security-report.md`, text: bundle.markdown },
    { name: `${root}/final-verification/findings.json`, text: JSON.stringify(bundle.final) },
  ];
  if (options.legacy) result.push({ name: `${root}/${options.kind === 'advantage' ? 'advantage-manifest' : 'run-manifest'}.json`, text: JSON.stringify({ run_id: bundle.run_id, status: 'complete', repository: bundle.repository, repositories: bundle.repositories, mode: options.kind === 'advantage' ? 'standard' : undefined }) });
  return result;
}
export function pairEntries(wrapper = ''): ZipFixtureEntry[] {
  return [...publicationEntries(`${wrapper}renamed-a`), ...publicationEntries(`${wrapper}renamed-b`, { kind: 'advantage', runId: 'advantage-fixture' })];
}
