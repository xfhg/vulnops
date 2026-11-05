#!/usr/bin/env node
/** Prepare isolated source, then build/package only an exact pushed app commit. */
import { constants } from 'node:fs';
import { lstat, readdir, readFile, writeFile, mkdir, mkdtemp, rm, open, copyFile, realpath } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { dirname, join, resolve, sep, posix } from 'node:path';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';

const execute = promisify(execFile);
const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const fixedSource = new Set(['package.json', 'package-lock.json', 'tsconfig.json', 'vite.config.ts', 'index.html', '.openai/hosting.json', 'scripts/prepare-sites.mjs', 'SITES.md', '.gitignore']);
const publicSource = new Set(['public/brand/vulnops-icon.svg']);
const prohibited = new Set(['.git', 'node_modules', 'scans', 'target', '_temp', '.harness', 'remediations', 'runtime', 'test-results', 'playwright-report', 'fixtures', '__fixtures__', '__snapshots__']);
const ignore = 'node_modules/\ndist-browser/\n.DS_Store\n';
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const buildDirectory = 'dist-browser';
const staticDirectory = 'dist';
const canonical = path => path && !path.includes('\\') && !/[\x00-\x1f]/.test(path) && path.split('/').every(part => part && part !== '.' && part !== '..');
export const allowedSourcePath = path => canonical(path) && !path.split('/').some(part => prohibited.has(part)) && (fixedSource.has(path) || publicSource.has(path) || (path.startsWith('src/') && /\.(?:ts|tsx|css)$/.test(path)));
const allowedArtifactPath = path => path === '.openai/hosting.json' || (canonical(path) && path.startsWith(`${staticDirectory}/`) && !path.split('/').some(part => part.startsWith('.') || prohibited.has(part)) && /\.(?:html|js|css|svg|woff2?|ttf|wasm|ico|png)$/.test(path));

async function exists(path) { try { await lstat(path); return true; } catch (error) { if (error.code === 'ENOENT') return false; throw error; } }
async function regularBytes(root, path) {
  let current = root;
  for (const part of path.split('/')) {
    current = join(current, part);
    const info = await lstat(current);
    if (info.isSymbolicLink()) throw new Error('Symlinks are not allowed in Sites inputs.');
    if (current !== join(root, path) && !info.isDirectory()) throw new Error('Sites input parent is not a directory.');
    if (current === join(root, path) && !info.isFile()) throw new Error('Sites inputs must be regular files.');
  }
  const handle = await open(join(root, path), constants.O_RDONLY | constants.O_NOFOLLOW);
  try { return await handle.readFile(); } finally { await handle.close(); }
}
async function walk(root, path) {
  const info = await lstat(join(root, path));
  if (info.isSymbolicLink()) throw new Error('Symlinks are not allowed in Sites inputs.');
  if (info.isFile()) return [path];
  if (!info.isDirectory()) throw new Error('Sites inputs must be regular files or directories.');
  const files = [];
  for (const entry of (await readdir(join(root, path))).sort()) files.push(...await walk(root, posix.join(path, entry)));
  return files;
}
async function inventory(root, paths) {
  return Promise.all([...paths].sort().map(async path => { const bytes = await regularBytes(root, path); return { path, bytes: bytes.length, sha256: digest(bytes) }; }));
}
async function command(program, args, cwd) {
  try { return (await execute(program, args, { cwd, maxBuffer: 16 * 1024 * 1024, env: { ...process.env, COPYFILE_DISABLE: '1' } })).stdout.trim(); }
  catch { throw new Error(`${program} preparation command failed; inspect the isolated checkout locally.`); }
}
function hosting(bytes, requireProject = true) {
  let value;
  try { value = JSON.parse(bytes.toString('utf8')); } catch { throw new Error('Hosting metadata is not valid JSON.'); }
  if (!value || typeof value !== 'object' || value.static?.directory !== staticDirectory) throw new Error('Hosting static.directory must be the supported directory "dist".');
  if (requireProject && (typeof value.project_id !== 'string' || !value.project_id.trim())) throw new Error('Bind the exact Sites project_id before packaging.');
  if (Object.keys(value).some(key => /token|secret|password|credential|environment/i.test(key))) throw new Error('Hosting metadata must not contain credentials or environment values.');
  return value;
}

export async function prepareSource(source, destination) {
  source = resolve(source); destination = resolve(destination);
  if ((await lstat(source)).isSymbolicLink()) throw new Error('The app source root cannot be a symlink.');
  if (destination === source || destination.startsWith(source + sep)) throw new Error('Use an isolated destination outside the app directory.');
  if (await exists(destination)) throw new Error('The isolated source destination must not already exist.');
  const paths = [];
  for (const folder of ['src', 'public']) {
    if (await exists(join(source, folder))) paths.push(...await walk(source, folder));
  }
  for (const path of fixedSource) if (path !== '.gitignore' && await exists(join(source, path))) paths.push(path);
  if (paths.some(path => !allowedSourcePath(path))) throw new Error('Unexpected file in app source/assets; review the explicit Sites allowlist.');
  for (const path of ['package.json', 'package-lock.json', 'tsconfig.json', 'vite.config.ts', 'index.html']) if (!paths.includes(path)) throw new Error(`Required app file is missing: ${path}`);
  // Pre-read every input before making a destination. No harness tree/history is copied.
  const contents = await Promise.all(paths.map(async path => [path, await regularBytes(source, path)]));
  const existingHosting = contents.find(([path]) => path === '.openai/hosting.json');
  if (existingHosting) hosting(existingHosting[1], false);
  else contents.push(['.openai/hosting.json', Buffer.from(JSON.stringify({ static: { directory: staticDirectory } }, null, 2) + '\n')]);
  contents.push(['.gitignore', Buffer.from(ignore)]);
  await mkdir(destination, { recursive: true });
  try {
    for (const [path, bytes] of contents) { await mkdir(dirname(join(destination, path)), { recursive: true }); await writeFile(join(destination, path), bytes, { flag: 'wx' }); }
    return { directory: destination, inventory: await inventory(destination, contents.map(([path]) => path)) };
  } catch (error) { await rm(destination, { recursive: true, force: true }); throw error; }
}

async function verifySource(source, sha) {
  if (!/^[0-9a-f]{40}$/.test(sha)) throw new Error('Use the full 40-character pushed commit SHA.');
  if ((await lstat(source)).isSymbolicLink() || await realpath(source) !== source) throw new Error('Use the canonical isolated source path.');
  if (await command('git', ['rev-parse', '--show-toplevel'], source) !== source) throw new Error('Source must be its own app-only Git repository.');
  if (await command('git', ['rev-parse', 'HEAD'], source) !== sha) throw new Error('Build commit differs from the selected publication commit.');
  if (await command('git', ['status', '--porcelain', '--untracked-files=all'], source)) throw new Error('The app-only checkout must be clean before packaging.');
  const branch = await command('git', ['symbolic-ref', '--short', 'HEAD'], source);
  const remote = await command('git', ['config', '--get', `branch.${branch}.remote`], source);
  const remoteBranch = await command('git', ['config', '--get', `branch.${branch}.merge`], source);
  if (!remote || remote === '.' || !remoteBranch.startsWith('refs/heads/')) throw new Error('Configure the isolated source branch upstream before packaging.');
  const remoteTip = await command('git', ['ls-remote', '--exit-code', remote, remoteBranch], source);
  if (remoteTip.split(/\s+/)[0] !== sha) throw new Error('The publication SHA must be the current pushed source branch HEAD.');
  const tree = await command('git', ['ls-tree', '-rz', '--full-tree', sha], source);
  const paths = tree.split('\0').filter(Boolean).map(row => {
    const match = /^(100644|100755) blob [a-f0-9]+\t(.+)$/s.exec(row);
    if (!match || !allowedSourcePath(match[2])) throw new Error('Committed source contains a non-allowlisted file, symlink, or submodule.');
    return match[2];
  });
  const historicalPaths = (await command('git', ['rev-list', '--objects', sha], source)).split('\n').map(row => row.slice(row.indexOf(' ') + 1)).filter(path => path && !/^[a-f0-9]{40}$/.test(path));
  const allowedDirectory = path => ['src', 'public', 'public/brand', '.openai', 'scripts'].includes(path) || (path.startsWith('src/') && canonical(path) && !path.split('/').some(part => prohibited.has(part)));
  if (historicalPaths.some(path => !allowedSourcePath(path) && !allowedDirectory(path))) throw new Error('Source history includes files outside the app allowlist; prepare a separate app-only repository.');
  return { paths, tree: await command('git', ['rev-parse', `${sha}^{tree}`], source), timestamp: Number(await command('git', ['show', '-s', '--format=%ct', sha], source)) };
}

/** Minimal deterministic POSIX tar: sorted regular files, no host metadata/history. */
async function writeTar(root, paths, output, timestamp) {
  const handle = await open(output, 'wx');
  try {
    for (const path of [...paths].sort()) {
      const bytes = await regularBytes(root, path), header = Buffer.alloc(512);
      let name = path, prefix = '';
      if (Buffer.byteLength(name) > 100) {
        const slash = path.lastIndexOf('/'); prefix = path.slice(0, slash); name = path.slice(slash + 1);
        if (Buffer.byteLength(name) > 100 || Buffer.byteLength(prefix) > 155) throw new Error('Artifact path exceeds the portable tar limit.');
      }
      header.write(name, 0, 100); header.write('0000644\0', 100, 8); header.write('0000000\0', 108, 8); header.write('0000000\0', 116, 8);
      header.write(bytes.length.toString(8).padStart(11, '0') + '\0', 124, 12); header.write(timestamp.toString(8).padStart(11, '0') + '\0', 136, 12);
      header.fill(32, 148, 156); header.write('0', 156); header.write('ustar\0', 257, 6); header.write('00', 263, 2); header.write(prefix, 345, 155);
      header.write([...header].reduce((sum, value) => sum + value, 0).toString(8).padStart(6, '0') + '\0 ', 148, 8);
      await handle.write(header); await handle.write(bytes);
      if (bytes.length % 512) await handle.write(Buffer.alloc(512 - bytes.length % 512));
    }
    await handle.write(Buffer.alloc(1024));
  } finally { await handle.close(); }
}

export async function packageRelease(source, sha, output) {
  source = resolve(source); output = resolve(output);
  if (!output.endsWith('.tar')) throw new Error('The deployment output must end in .tar.');
  if (output === source || output.startsWith(source + sep)) throw new Error('Write the release artifact outside the app-only source checkout.');
  if (await exists(output) || await exists(output + '.provenance.json')) throw new Error('Release output already exists; preserve it until saving succeeds.');
  const verified = await verifySource(source, sha);
  const temporary = await mkdtemp(join(tmpdir(), 'stake-sites-'));
  try {
    const snapshot = join(temporary, 'source'); await mkdir(snapshot);
    // This tree is from the commit, never from potentially stale local build output.
    await command('git', ['archive', '--format=tar', '--output', join(temporary, 'source.tar'), sha], source);
    await command('tar', ['-xf', join(temporary, 'source.tar'), '-C', snapshot], source);
    const binding = hosting(await regularBytes(snapshot, '.openai/hosting.json'));
    const sourceInventory = await inventory(snapshot, verified.paths);
    await command('npm', ['ci', '--no-audit', '--no-fund', '--cache', join(temporary, 'npm-cache')], snapshot);
    await command('npm', ['run', 'build:web'], snapshot);
    // Reject build-time tracked-source changes as well as a concurrently replaced source HEAD.
    if (JSON.stringify(await inventory(snapshot, verified.paths)) !== JSON.stringify(sourceInventory)) throw new Error('The build changed its committed source inputs.');
    await verifySource(source, sha);
    const buildPaths = await walk(snapshot, buildDirectory);
    const publishedPath = path => `${staticDirectory}/${path.slice(buildDirectory.length + 1)}`;
    const paths = ['.openai/hosting.json', ...buildPaths.map(publishedPath)];
    if (!paths.includes(`${staticDirectory}/index.html`) || paths.some(path => !allowedArtifactPath(path))) throw new Error('Static output contains a missing entrypoint or non-allowlisted asset.');
    const buildInventory = await inventory(snapshot, buildPaths);
    // Sites accepts static.directory:"dist". Keep the local browser build separate from
    // CLI assets; only this fresh, byte-for-byte artifact copy uses dist/.
    const staging = join(temporary, 'artifact');
    for (const path of ['.openai/hosting.json', ...buildPaths]) {
      const target = path === '.openai/hosting.json' ? path : publishedPath(path);
      await mkdir(dirname(join(staging, target)), { recursive: true });
      await writeFile(join(staging, target), await regularBytes(snapshot, path), { flag: 'wx' });
    }
    const artifactInventory = await inventory(staging, paths);
    const archive = join(temporary, 'deployment.tar'); await writeTar(staging, paths, archive, verified.timestamp);
    const provenance = { format: 1, commit_sha: sha, tree_sha: verified.tree, project_id: binding.project_id, build_output_directory: buildDirectory, static_directory: staticDirectory, source_inventory: sourceInventory, build_inventory: buildInventory, artifact_inventory: artifactInventory, archive_sha256: digest(await readFile(archive)) };
    await mkdir(dirname(output), { recursive: true });
    await copyFile(archive, output, constants.COPYFILE_EXCL);
    await writeFile(output + '.provenance.json', JSON.stringify(provenance, null, 2) + '\n', { flag: 'wx' });
    return { archive: output, provenance: output + '.provenance.json', commit_sha: sha, project_id: binding.project_id, files: artifactInventory.length, archive_sha256: provenance.archive_sha256 };
  } finally { await rm(temporary, { recursive: true, force: true }); }
}

/** Recheck the saved candidate immediately before passing its path to Sites. */
export async function verifyRelease(archive, expectedSha) {
  archive = resolve(archive);
  const metadata = JSON.parse(await readFile(archive + '.provenance.json', 'utf8'));
  if (!/^[0-9a-f]{40}$/.test(expectedSha) || metadata.commit_sha !== expectedSha) throw new Error('Artifact build commit differs from the selected publication commit.');
  const bytes = await readFile(archive);
  if (digest(bytes) !== metadata.archive_sha256) throw new Error('The release archive changed after packaging.');
  const entries = [];
  let offset = 0, binding;
  while (offset + 512 <= bytes.length) {
    const header = bytes.subarray(offset, offset + 512);
    if (header.every(value => value === 0)) break;
    const string = (start, length) => new TextDecoder('utf-8', { fatal: true }).decode(header.subarray(start, start + length)).split('\0')[0];
    const prefix = string(345, 155), path = [prefix, string(0, 100)].filter(Boolean).join('/');
    const size = Number.parseInt(string(124, 12), 8), content = bytes.subarray(offset + 512, offset + 512 + size);
    if (!allowedArtifactPath(path) || header[156] !== 48 || !Number.isSafeInteger(size) || size < 0 || content.length !== size || entries.some(entry => entry.path === path)) throw new Error('The release archive inventory is invalid.');
    entries.push({ path, bytes: size, sha256: digest(content) });
    if (path === '.openai/hosting.json') binding = hosting(content);
    offset += 512 + Math.ceil(size / 512) * 512;
  }
  if (!binding || binding.project_id !== metadata.project_id || !entries.some(entry => entry.path === `${staticDirectory}/index.html`) || JSON.stringify(entries) !== JSON.stringify(metadata.artifact_inventory)) throw new Error('Release inventory or project binding differs from its provenance.');
  const mappedBuild = Array.isArray(metadata.build_inventory) && metadata.build_inventory.every(entry => typeof entry.path === 'string' && entry.path.startsWith(`${buildDirectory}/`))
    ? metadata.build_inventory.map(entry => ({ ...entry, path: `${staticDirectory}/${entry.path.slice(buildDirectory.length + 1)}` })) : null;
  if (metadata.build_output_directory !== buildDirectory || metadata.static_directory !== staticDirectory || JSON.stringify(mappedBuild) !== JSON.stringify(entries.filter(entry => entry.path !== '.openai/hosting.json'))) throw new Error('Published assets differ from the recorded browser build.');
  return { archive, commit_sha: expectedSha, project_id: binding.project_id, archive_sha256: metadata.archive_sha256, files: entries.length };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [operation, first, second, third] = process.argv.slice(2);
  try {
    if (operation === 'prepare' && first && !second) console.log(JSON.stringify(await prepareSource(packageRoot, first), null, 2));
    else if (operation === 'package' && first && second && third) console.log(JSON.stringify(await packageRelease(first, second, third), null, 2));
    else if (operation === 'verify' && first && second && !third) console.log(JSON.stringify(await verifyRelease(first, second), null, 2));
    else throw new Error('Usage: node scripts/prepare-sites.mjs prepare <destination> | package <source> <full-pushed-sha> <output.tar> | verify <output.tar> <publication-sha>');
  } catch (error) { console.error(error instanceof Error ? error.message : 'Sites preparation failed.'); process.exitCode = 1; }
}
