import { BlobReader, ZipReader, type Entry, type FileEntry } from '@zip.js/zip.js/lib/zip-core-native.js';
import { admitArchive } from './admission';
import { ARCHIVE_BUDGETS, ArchiveError, checkAborted, freezeArchiveValue, safeArchiveError, type ArchiveProgress, type ArchiveSession, type PublicationReader } from './types';

export type ArchiveBudgets = { [K in keyof typeof ARCHIVE_BUDGETS]: number };

/** ZIP backslashes are separator variants, never part of an evidence filename. */
export function normalizeArchivePath(name: string, directory = false): string {
  if (!name || /[\x00-\x1f\x7f]/.test(name)) throw new ArchiveError('unsafe_path', 'The ZIP contains an unsafe entry path.');
  const normalized = name.replaceAll('\\', '/');
  if (normalized.startsWith('/') || /^[a-z]:/i.test(normalized)) throw new ArchiveError('unsafe_path', 'Absolute ZIP entry paths are not supported.');
  const path = directory && normalized.endsWith('/') ? normalized.slice(0, -1) : normalized;
  if (path.split('/').some(part => !part || part === '.' || part === '..')) throw new ArchiveError('unsafe_path', 'The ZIP contains a noncanonical entry path.');
  return path;
}
const packaging = (path: string) => path.split('/').includes('__MACOSX') || path.split('/').at(-1) === '.DS_Store';

export function discoverReportRoots(paths: Iterable<string>): string[] {
  const roots = [...new Set([...paths].filter(path => !packaging(path) && path.endsWith('/report/security-report.json'))
    .map(path => path.slice(0, -'/report/security-report.json'.length)).filter(root => root.split('/').length <= 2))].sort();
  if (roots.length !== 2 || roots.some(root => !root || root.split('/').length !== roots[0].split('/').length)
    || roots[0].split('/').slice(0, -1).join('/') !== roots[1].split('/').slice(0, -1).join('/'))
    throw new ArchiveError('invalid_layout', 'Select one ZIP with two sibling report folders, optionally inside one common wrapper.');
  return roots;
}

/** Blob-backed reads stay in the import worker; optional evidence is expanded only on demand. */
export class ZipPublicationReader implements PublicationReader {
  private readonly files = new Map<string, FileEntry>();
  private readonly entries = new Map<string, Entry>();
  private readonly cache = new Map<string, Promise<{ text: string; bytes: number }>>();
  private actualBytes = 0;
  private disposed = false;
  private readonly lifetime = new AbortController();
  private readonly zip: ZipReader<Blob>;
  private constructor(private readonly blob: Blob, private readonly budgets: ArchiveBudgets) {
    // Native deflate avoids WASM/eval or secondary worker downloads. This class
    // already runs in our dedicated, locally bundled worker.
    this.zip = new ZipReader(new BlobReader(blob), { useWebWorkers: false, useCompressionStream: true,
      strictness: 'strict', filenameValidation: 'tolerant', checkCrc32: true });
  }

  static async open(blob: Blob, signal?: AbortSignal, onProgress?: (progress: ArchiveProgress) => void, budgets: ArchiveBudgets = ARCHIVE_BUDGETS): Promise<ZipPublicationReader> {
    checkAborted(signal);
    if (blob.size > budgets.compressedBytes) throw new ArchiveError('archive_limit', 'The compressed ZIP exceeds the 256 MiB import budget.');
    const reader = new ZipPublicationReader(blob, budgets);
    try { await reader.index(signal, onProgress); return reader; }
    catch (error) { reader.dispose(); checkAborted(signal); throw safeArchiveError(error); }
  }

  private async index(signal?: AbortSignal, onProgress?: (progress: ArchiveProgress) => void): Promise<void> {
    let count = 0, declared = 0;
    const occupied: Array<[number, number]> = [];
    for await (const entry of this.zip.getEntriesGenerator()) {
      checkAborted(signal);
      if (++count > this.budgets.entries) throw new ArchiveError('archive_limit', 'The ZIP exceeds the 20,000-entry import budget.');
      const path = normalizeArchivePath(entry.filename, entry.directory);
      if (this.entries.has(path)) throw new ArchiveError('duplicate_path', 'Two ZIP entries resolve to the same path.');
      const fileType = (entry.externalFileAttributes >>> 16) & 0xf000;
      if (entry.symlink || fileType && fileType !== 0x8000 && fileType !== 0x4000 || fileType === 0x4000 && !entry.directory || fileType === 0x8000 && entry.directory)
        throw new ArchiveError('unsupported_entry', 'Links and special ZIP entries are not supported.');
      if (entry.encrypted) throw new ArchiveError('encrypted_archive', 'Encrypted ZIP entries are not supported.');
      if (![0, 8].includes(entry.compressionMethod)) throw new ArchiveError('unsupported_compression', 'Only stored and DEFLATE ZIP entries are supported.');
      if (![entry.uncompressedSize, entry.compressedSize, entry.offset].every(size => Number.isSafeInteger(size) && size >= 0))
        throw new ArchiveError('invalid_archive', 'The ZIP declares invalid entry sizes or offsets.');
      declared += entry.uncompressedSize;
      if (declared > this.budgets.expandedBytes) throw new ArchiveError('archive_limit', 'The ZIP exceeds the 1 GiB declared expansion budget.');
      if (entry.directory && (entry.uncompressedSize || entry.compressedSize)) throw new ArchiveError('unsupported_entry', 'Directory entries cannot contain file data.');
      // Check every local header without inflating unreferenced/runtime entries.
      const header = new DataView(await this.blob.slice(entry.offset, entry.offset + 30).arrayBuffer());
      if (header.byteLength !== 30 || header.getUint32(0, true) !== 0x04034b50) throw new ArchiveError('invalid_archive', 'A ZIP entry has a missing or truncated local header.');
      const end = entry.offset + 30 + header.getUint16(26, true) + header.getUint16(28, true) + entry.compressedSize;
      if (end > (this.zip.directoryOffset ?? this.blob.size)) throw new ArchiveError('invalid_archive', 'A ZIP entry extends beyond its data region.');
      if (entry.directory) {
        // DirectoryEntry has no getData() preflight. Check its local header too,
        // including otherwise-ignored packaging directories.
        const name = new Uint8Array(await this.blob.slice(entry.offset + 30, entry.offset + 30 + header.getUint16(26, true)).arrayBuffer());
        if (name.length !== entry.rawFilename.length || name.some((byte, index) => byte !== entry.rawFilename[index])
          || header.getUint16(8, true) !== entry.compressionMethod || header.getUint16(6, true) & 1
          || header.getUint32(18, true) !== 0 || header.getUint32(22, true) !== 0)
          throw new ArchiveError('invalid_archive', 'A ZIP directory has inconsistent local metadata.');
      }
      occupied.push([entry.offset, end]);
      this.entries.set(path, entry);
      if (!entry.directory) {
        await entry.getData(new WritableStream(), { checkOverlappingEntryOnly: true, signal, useWebWorkers: false });
        this.files.set(path, entry);
      }
      if (count === 1 || count % 32 === 0) onProgress?.({ phase: 'reading', completed: count });
    }
    occupied.sort((a, b) => a[0] - b[0]);
    for (let index = 1; index < occupied.length; index++) if (occupied[index][0] < occupied[index - 1][1])
      throw new ArchiveError('invalid_archive', 'ZIP entry data overlaps another entry.');
    for (const path of this.entries.keys()) {
      const parts = path.split('/');
      for (let index = 1; index < parts.length; index++) if (this.files.has(parts.slice(0, index).join('/')))
        throw new ArchiveError('duplicate_path', 'A ZIP file aliases another entry’s parent directory.');
    }
    checkAborted(signal);
    onProgress?.({ phase: 'reading', completed: count, total: count });
  }

  roots(): string[] { return discoverReportRoots(this.files.keys()); }
  has(root: string, path: string): boolean { return this.files.has(`${root}/${path}`); }
  async readText(root: string, path: string, limit = this.budgets.entryBytes): Promise<string> {
    if (this.disposed) throw new ArchiveError('retired_archive', 'This archive is no longer active.');
    if (normalizeArchivePath(root) !== root || normalizeArchivePath(path) !== path) throw new ArchiveError('unsafe_path', 'The archive reference is not canonical.');
    const key = `${root}/${path}`, entry = this.files.get(key);
    if (!entry || packaging(key)) throw new ArchiveError('unavailable', 'Referenced artifact was not delivered.');
    const maximum = Math.min(limit, this.budgets.entryBytes);
    if (!Number.isFinite(maximum) || maximum < 0 || entry.uncompressedSize > maximum)
      throw new ArchiveError('entry_limit', 'Artifact exceeds its publication or browser entry size limit.');
    let pending = this.cache.get(key);
    if (!pending) {
      pending = this.readEntry(entry, maximum);
      this.cache.set(key, pending);
    }
    const result = await pending;
    if (result.bytes > maximum) throw new ArchiveError('entry_limit', 'Artifact exceeds its publication or browser entry size limit.');
    return result.text;
  }

  private async readEntry(entry: FileEntry, maximum: number): Promise<{ text: string; bytes: number }> {
    const controller = new AbortController();
    const abort = () => controller.abort();
    this.lifetime.signal.addEventListener('abort', abort, { once: true });
    const timer = setTimeout(() => controller.abort(), this.budgets.timeoutMs);
    const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
    const chunks: string[] = [];
    let bytes = 0;
    try {
      await entry.getData(new WritableStream<Uint8Array>({ write: chunk => {
        bytes += chunk.byteLength;
        this.actualBytes += chunk.byteLength;
        if (bytes > maximum || bytes > entry.uncompressedSize) throw new ArchiveError('entry_limit', 'An expanded artifact exceeds its declared or permitted size.');
        if (this.actualBytes > this.budgets.expandedBytes) throw new ArchiveError('archive_limit', 'Consumed entries exceed the 1 GiB actual expansion budget.');
        try { chunks.push(decoder.decode(chunk, { stream: true })); }
        catch { throw new ArchiveError('invalid_content', 'Artifact is not valid UTF-8 text.'); }
      }}), { checkCrc32: true, useWebWorkers: false, useCompressionStream: true, signal: controller.signal });
      if (bytes !== entry.uncompressedSize) throw new ArchiveError('invalid_archive', 'An expanded artifact differs from its declared size.');
      try { chunks.push(decoder.decode()); }
      catch { throw new ArchiveError('invalid_content', 'Artifact is not valid UTF-8 text.'); }
      return { text: chunks.join(''), bytes };
    } catch (error) {
      if (controller.signal.aborted) throw new ArchiveError(this.disposed ? 'retired_archive' : 'timeout', this.disposed ? 'This archive is no longer active.' : 'Artifact reading exceeded its runtime allowance.');
      throw safeArchiveError(error);
    } finally { clearTimeout(timer); this.lifetime.signal.removeEventListener('abort', abort); }
  }

  dispose(): void {
    this.disposed = true; this.lifetime.abort(); this.cache.clear(); this.files.clear(); this.entries.clear();
    void this.zip.close().catch(() => undefined);
  }
}

/** Also used by Node-based parity tests; production calls this inside archive.worker.ts. */
export async function openArchiveInProcess(blob: Blob, signal?: AbortSignal, onProgress?: (progress: ArchiveProgress) => void, budgets: ArchiveBudgets = ARCHIVE_BUDGETS): Promise<ArchiveSession> {
  let reader: ZipPublicationReader | undefined;
  const controller = new AbortController();
  const abort = () => { controller.abort(); reader?.dispose(); };
  signal?.addEventListener('abort', abort, { once: true });
  const timer = setTimeout(abort, budgets.timeoutMs);
  try {
    checkAborted(signal);
    reader = await ZipPublicationReader.open(blob, controller.signal, onProgress, budgets);
    const admitted = await admitArchive(reader, reader.roots(), onProgress);
    checkAborted(controller.signal);
    freezeArchiveValue(admitted);
    const captured = reader;
    return { ...admitted, readText: (root, path, limit) => captured.readText(root, path, limit), dispose: () => captured.dispose() };
  } catch (error) {
    reader?.dispose(); checkAborted(signal);
    if (controller.signal.aborted) throw new ArchiveError('timeout', 'Archive import exceeded its runtime allowance.');
    throw safeArchiveError(error);
  } finally { clearTimeout(timer); signal?.removeEventListener('abort', abort); }
}
