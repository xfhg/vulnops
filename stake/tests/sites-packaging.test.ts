import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdir, mkdtemp, readFile, readdir, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createHash } from 'node:crypto';
// @ts-expect-error This dependency-free CLI intentionally runs directly as Node ESM.
import { prepareSource, packageRelease, verifyRelease } from '../scripts/prepare-sites.mjs';

const exec = promisify(execFile);
let temporary: string;
beforeEach(async () => { temporary = await realpath(await mkdtemp(join(tmpdir(), 'stake-package-test-'))); });
afterEach(async () => { await rm(temporary, { recursive: true, force: true }); });
async function put(root: string, path: string, content: string) { await mkdir(join(root, path, '..'), { recursive: true }); await writeFile(join(root, path), content); }
async function git(root: string, ...args: string[]) { return (await exec('git', args, { cwd: root })).stdout.trim(); }
async function sourceFixture() {
  const source = join(temporary, 'harness', 'stake');
  await mkdir(source, { recursive: true });
  const build = `import {mkdirSync,writeFileSync} from 'node:fs';mkdirSync('dist-browser/assets',{recursive:true});writeFileSync('dist-browser/index.html','<!doctype html><script src="assets/app.js"></script>');writeFileSync('dist-browser/assets/app.js','console.log("SYNTHETIC APP ONLY")');`;
  const manifest = { name: 'synthetic-sites-fixture', version: '1.0.0', private: true, type: 'module', scripts: { 'build:web': 'node src/build.ts' } };
  await put(source, 'package.json', JSON.stringify(manifest));
  await put(source, 'package-lock.json', JSON.stringify({ name: manifest.name, version: manifest.version, lockfileVersion: 3, requires: true, packages: { '': { name: manifest.name, version: manifest.version } } }));
  await put(source, 'src/build.ts', build);
  await put(source, 'src/app.tsx', 'export const app = "synthetic";');
  await put(source, 'src/style.css', ':root { color: #fff; }');
  await put(source, 'public/brand/vulnops-icon.svg', '<svg xmlns="http://www.w3.org/2000/svg"/>');
  await put(source, 'tsconfig.json', '{}'); await put(source, 'vite.config.ts', 'export default {};');
  await put(source, 'index.html', '<!doctype html>');
  await put(source, '.openai/hosting.json', JSON.stringify({ project_id: 'synthetic-opaque-project', static: { directory: 'dist' } }));
  return source;
}
async function committedSource() {
  const harness = await sourceFixture(), source = join(temporary, 'isolated');
  await prepareSource(harness, source);
  await git(source, 'init', '-b', 'main'); await git(source, 'config', 'user.name', 'Synthetic fixture'); await git(source, 'config', 'user.email', 'fixture@example.invalid');
  await git(source, 'add', '.'); await git(source, 'commit', '-m', 'Synthetic app source');
  const remote = join(temporary, 'remote.git'); await mkdir(remote); await git(remote, 'init', '--bare');
  await git(source, 'remote', 'add', 'origin', remote); await git(source, 'push', '-u', 'origin', 'main');
  return { source, sha: await git(source, 'rev-parse', 'HEAD') };
}

describe('Sites app-only packaging', () => {
  it('copies only selected app inputs, with reproducible inventories and no harness history or private data', async () => {
    const source = await sourceFixture();
    for (const path of ['scans/report.json', 'target/source.ts', '_temp/capture.png', '.harness/state.json', '.git/config', 'real-assessment.zip', '.env', 'test-results/capture.png', 'server/publication_bridge.py']) await put(source, path, 'SYNTHETIC EXCLUDED DATA');
    const first = await prepareSource(source, join(temporary, 'prepared-one'));
    const second = await prepareSource(source, join(temporary, 'prepared-two'));
    expect(first.inventory).toEqual(second.inventory);
    const paths = first.inventory.map((item: { path: string }) => item.path);
    expect(paths).toContain('src/app.tsx'); expect(paths).toContain('.openai/hosting.json');
    expect(paths.some((path: string) => /scans|target|_temp|\.harness|\.git\/|\.zip|\.env|test-results|server\//.test(path))).toBe(false);
    expect(await readdir(first.directory)).not.toContain('.git');
  });

  it('rejects symlink source files and unexpected archive/capture assets before preparing a destination', async () => {
    const source = await sourceFixture(), destination = join(temporary, 'prepared');
    await symlink(join(source, 'package.json'), join(source, 'src', 'linked.ts'));
    await expect(prepareSource(source, destination)).rejects.toThrow(/Symlinks/);
    await rm(join(source, 'src', 'linked.ts')); await put(source, 'public/report.zip', 'SYNTHETIC ARCHIVE');
    await expect(prepareSource(source, destination)).rejects.toThrow(/allowlist/);
    expect(await readdir(temporary)).not.toContain('prepared');
  });

  it('uses the Sites static object and rejects unsupported directory values or a bare string', async () => {
    const source = await sourceFixture(), destination = join(temporary, 'prepared');
    await put(source, '.openai/hosting.json', JSON.stringify({ project_id: 'synthetic-opaque-project', static: { directory: 'dist-browser' } }));
    await expect(prepareSource(source, destination)).rejects.toThrow('Hosting static.directory must be the supported directory "dist".');
    await put(source, '.openai/hosting.json', JSON.stringify({ project_id: 'synthetic-opaque-project', static: 'dist' }));
    await expect(prepareSource(source, destination)).rejects.toThrow('Hosting static.directory must be the supported directory "dist".');
    await rm(join(source, '.openai/hosting.json'));
    await prepareSource(source, destination);
    expect(JSON.parse(await readFile(join(destination, '.openai/hosting.json'), 'utf8'))).toEqual({ static: { directory: 'dist' } });
  });

  it('builds only the exact pushed tree and creates a deterministic static tar with verified provenance', async () => {
    const { source, sha } = await committedSource();
    await put(source, 'dist-browser/stale.json', 'SYNTHETIC STALE OUTPUT');
    const first = await packageRelease(source, sha, join(temporary, 'release-one.tar'));
    const second = await packageRelease(source, sha, join(temporary, 'release-two.tar'));
    expect(await readFile(first.archive)).toEqual(await readFile(second.archive));
    const list = (await exec('tar', ['-tf', first.archive])).stdout.trim().split('\n');
    expect(list).toEqual(['.openai/hosting.json', 'dist/assets/app.js', 'dist/index.html']);
    const hosting = JSON.parse((await exec('tar', ['-xOf', first.archive, '.openai/hosting.json'])).stdout);
    expect(hosting).toEqual({ project_id: 'synthetic-opaque-project', static: { directory: 'dist' } });
    const provenance = JSON.parse(await readFile(first.provenance, 'utf8'));
    expect(provenance.commit_sha).toBe(sha); expect(provenance.project_id).toBe('synthetic-opaque-project');
    expect(provenance.archive_sha256).toBe(createHash('sha256').update(await readFile(first.archive)).digest('hex'));
    expect(provenance.artifact_inventory.map((item: { path: string }) => item.path)).toEqual(list);
    expect(provenance.build_output_directory).toBe('dist-browser'); expect(provenance.static_directory).toBe('dist');
    expect(provenance.build_inventory.map((item: { path: string }) => item.path)).toEqual(['dist-browser/assets/app.js', 'dist-browser/index.html']);
    expect(provenance.build_inventory.map((item: { path: string }) => ({ ...item, path: item.path.replace(/^dist-browser\//, 'dist/') }))).toEqual(provenance.artifact_inventory.filter((item: { path: string }) => item.path !== '.openai/hosting.json'));
    expect(await readFile(join(source, 'dist-browser/stale.json'), 'utf8')).toBe('SYNTHETIC STALE OUTPUT');
    expect(provenance.source_inventory.some((item: { path: string }) => item.path.startsWith('src/'))).toBe(true);
    expect(await verifyRelease(first.archive, sha)).toMatchObject({ commit_sha: sha, project_id: 'synthetic-opaque-project', files: 3 });
    await expect(verifyRelease(first.archive, '0'.repeat(40))).rejects.toThrow(/differs/);
    await expect(packageRelease(source, sha, first.archive)).rejects.toThrow(/already exists/);
    await writeFile(second.archive, Buffer.from('SYNTHETIC ALTERED ARTIFACT'));
    await expect(verifyRelease(second.archive, sha)).rejects.toThrow(/changed/);
  });

  it('rejects changed source, a mismatched build commit and a commit not at the remote branch tip', async () => {
    const { source, sha } = await committedSource(), output = join(temporary, 'candidate.tar');
    await expect(packageRelease(source, '0'.repeat(40), output)).rejects.toThrow(/differs/);
    await put(source, 'src/app.tsx', 'export const app = "changed";');
    await expect(packageRelease(source, sha, output)).rejects.toThrow(/clean/);
    await git(source, 'add', '.'); await git(source, 'commit', '-m', 'Unpushed app change');
    await expect(packageRelease(source, await git(source, 'rev-parse', 'HEAD'), output)).rejects.toThrow(/pushed source branch HEAD/);
  });

  it('rejects forbidden committed files and inherited harness history even after the file was deleted', async () => {
    const { source } = await committedSource(), output = join(temporary, 'candidate.tar');
    await put(source, 'scans/report.json', 'SYNTHETIC PRIVATE DATA');
    await git(source, 'add', '.'); await git(source, 'commit', '-m', 'Invalid source fixture'); await git(source, 'push');
    await expect(packageRelease(source, await git(source, 'rev-parse', 'HEAD'), output)).rejects.toThrow(/non-allowlisted/);
    await git(source, 'rm', 'scans/report.json'); await git(source, 'commit', '-m', 'Remove fixture'); await git(source, 'push');
    await expect(packageRelease(source, await git(source, 'rev-parse', 'HEAD'), output)).rejects.toThrow(/history/);
  });
});
