import { describe, expect, it } from 'vitest';
import { ARCHIVE_BUDGETS } from '../src/data/archive/types';
import { discoverReportRoots, normalizeArchivePath, openArchiveInProcess, ZipPublicationReader } from '../src/data/archive/reader';
import { pairEntries, publicationEntries, zipFixture } from './browser-archive-fixtures';

describe('portable ZIP reader', () => {
  it.each(['', 'wrapper/'])('admits renamed sibling roots with wrapper %j, ignores safe packaging and nested history', async wrapper => {
    const entries = pairEntries(wrapper);
    entries.push({ name: '__MACOSX/._ordinary', text: 'packaging' }, { name: `${wrapper}renamed-a/.DS_Store`, text: 'packaging' },
      { name: `${wrapper}renamed-a/baseline/old/report/security-report.json`, text: 'not a candidate' },
      { name: `${wrapper}renamed-a/run-manifest.json`, text: '{ corrupt retired control' });
    const session = await openArchiveInProcess(zipFixture(entries));
    expect(session.bundles.map(bundle => bundle.execution_kind)).toEqual(['audit', 'advantage']);
    expect(session.bundles.map(bundle => bundle.inputPath)).toEqual([`${wrapper}renamed-a`, `${wrapper}renamed-b`]);
    expect(session.workspace.findings).toHaveLength(2);
    expect(Object.isFrozen(session.workspace.findings[0].raw)).toBe(true);
    session.dispose();
    await expect(session.readText(`${wrapper}renamed-a`, 'report/security-report.md')).rejects.toMatchObject({ code: 'retired_archive' });
  });

  it('supports native DEFLATE and validates required CRCs, while optional corrupt data stays lazy', async () => {
    const entries = pairEntries().map(entry => ({ ...entry, method: 8 }));
    entries.push({ name: 'renamed-a/sast/lazy.json', text: '{}', method: 8, crc: 123 } as typeof entries[number]);
    const session = await openArchiveInProcess(zipFixture(entries));
    await expect(session.readText('renamed-a', 'sast/lazy.json')).rejects.toMatchObject({ code: 'invalid_archive' });
    expect(session.workspace.assessments).toHaveLength(2);
    session.dispose();
    entries[0] = { ...entries[0], crc: 123 } as typeof entries[number];
    await expect(openArchiveInProcess(zipFixture(entries))).rejects.toMatchObject({ code: 'invalid_archive' });
  });

  it.each(['../escape', '/absolute', 'C:/drive', 'a/./b', 'a//b', 'a\u0000b', 'a\\..\\b'])('rejects unsafe path %j even in ignored metadata', async path => {
    await expect(openArchiveInProcess(zipFixture([...pairEntries(), { name: path, text: '' }]))).rejects.toBeDefined();
  });
  it('normalizes slash variants and rejects normalized collisions and file-parent aliases', async () => {
    expect(normalizeArchivePath('a\\b')).toBe('a/b');
    const good = pairEntries().map(entry => ({ ...entry, name: entry.name.replaceAll('/', '\\') }));
    const session = await openArchiveInProcess(zipFixture(good)); session.dispose();
    for (const extras of [ [{ name: 'extra/file', text: '' }, { name: 'extra\\file', text: '' }], [{ name: 'extra', text: '' }, { name: 'extra/file', text: '' }] ])
      await expect(openArchiveInProcess(zipFixture([...pairEntries(), ...extras]))).rejects.toMatchObject({ code: 'duplicate_path' });
  });
  it.each([
    { name: 'link', attributes: 0xa1ff0000 }, { name: 'device', attributes: 0x21a40000 },
    { name: 'encrypted', flags: 0x801 }, { name: 'unsupported', method: 12 },
  ])('rejects unsafe entry metadata $name', async entry => {
    await expect(openArchiveInProcess(zipFixture([...pairEntries(), { ...entry, text: '' }]))).rejects.toBeDefined();
  });
  it('rejects truncated and overlapping entry structure before admission', async () => {
    const zip = zipFixture(pairEntries());
    await expect(openArchiveInProcess(zip.slice(0, zip.size - 15))).rejects.toMatchObject({ code: 'invalid_archive' });
    await expect(openArchiveInProcess(zipFixture([...pairEntries(), { name: 'overlap', text: '', localOffset: 0 }]))).rejects.toMatchObject({ code: 'invalid_archive' });
    const directoryZip = zipFixture([{ name: '__MACOSX/' }, ...pairEntries()]);
    const changed = new Uint8Array(await directoryZip.arrayBuffer()); changed[30] = 120;
    await expect(openArchiveInProcess(new Blob([changed]))).rejects.toMatchObject({ code: 'invalid_archive' });
  });
  it('requires exactly two sibling candidate roots rather than selecting by archive order', async () => {
    expect(() => discoverReportRoots(['a/report/security-report.json'])).toThrow();
    expect(() => discoverReportRoots(['a/report/security-report.json', 'wrapper/b/report/security-report.json'])).toThrow();
    await expect(openArchiveInProcess(zipFixture([...pairEntries(), ...publicationEntries('third', { runId: 'third' })]))).rejects.toMatchObject({ code: 'invalid_layout' });
  });
  it('bounds compressed bytes, counts, declared and consumed entries', async () => {
    const zip = zipFixture(pairEntries());
    for (const budgets of [{ compressedBytes: 10 }, { entries: 3 }, { expandedBytes: 100 }, { entryBytes: 100 }])
      await expect(openArchiveInProcess(zip, undefined, undefined, { ...ARCHIVE_BUDGETS, ...budgets })).rejects.toBeDefined();
    const inflated = zipFixture([{ name: 'large', text: 'x'.repeat(1000), method: 8, declaredSize: 1 }]);
    const reader = await ZipPublicationReader.open(inflated);
    await expect(reader.readText('large', 'unused')).rejects.toMatchObject({ code: 'unavailable' });
    reader.dispose();
    // A DEFLATE stream cannot evade the actual-output bound by understating its central size.
    await expect(openArchiveInProcess(zipFixture(pairEntries().map((entry, index) => index ? entry : { ...entry, method: 8, declaredSize: 1 })))).rejects.toBeDefined();
  });
  it('cancels while indexing and leaves no usable partially admitted session', async () => {
    const controller = new AbortController();
    await expect(openArchiveInProcess(zipFixture(pairEntries()), controller.signal, () => controller.abort())).rejects.toMatchObject({ code: 'cancelled' });
    await expect(openArchiveInProcess(zipFixture(pairEntries()), controller.signal)).rejects.toMatchObject({ code: 'cancelled' });
  });
  it('enforces UTF-8 and exact available paths without reading outside the virtual root', async () => {
    const session = await openArchiveInProcess(zipFixture([...pairEntries(), { name: 'renamed-a/sast/bad.txt', bytes: new Uint8Array([0xff]) }]));
    await expect(session.readText('renamed-a', '../renamed-b/report/security-report.json')).rejects.toMatchObject({ code: 'unsafe_path' });
    await expect(session.readText('renamed-a', 'sast/bad.txt')).rejects.toMatchObject({ code: 'invalid_content' });
    await expect(session.readText('renamed-a', 'missing.json')).rejects.toMatchObject({ code: 'unavailable' });
    session.dispose();
  });
});
