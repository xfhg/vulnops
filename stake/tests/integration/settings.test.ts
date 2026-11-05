import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { lstat, mkdir, mkdtemp, readFile, readdir, realpath, rm, stat, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { SettingsStore, settingsDirectory } from '../../server/settings';

let temporary: string;
beforeEach(async () => { temporary = await mkdtemp(join(tmpdir(), 'stake-settings-')); });
afterEach(async () => { await rm(temporary, { recursive: true, force: true }); });
async function pair(suffix = '') {
  const result = { ordinaryPath: join(temporary, `ordinary ${suffix}`), advantagePath: join(temporary, `advantage ${suffix}`) };
  await Promise.all(Object.values(result).map((path) => mkdir(path, { recursive: true })));
  return result;
}

describe('local paths-only settings', () => {
  it('resolves platform locations and a literal absolute portable override', () => {
    expect(settingsDirectory({ platform: 'darwin', home: '/users/example', env: {} })).toBe('/users/example/Library/Application Support/VulnOps/stake');
    expect(settingsDirectory({ platform: 'linux', home: '/users/example', env: {} })).toBe('/users/example/.config/vulnops/stake');
    expect(settingsDirectory({ platform: 'linux', home: '/users/example', env: { XDG_CONFIG_HOME: '/config' } })).toBe('/config/vulnops/stake');
    expect(settingsDirectory({ platform: 'linux', home: '/users/example', env: { XDG_CONFIG_HOME: 'relative' } })).toBe('/users/example/.config/vulnops/stake');
    expect(settingsDirectory({ platform: 'win32', home: 'C:\\Users\\Example', env: {} })).toBe('C:\\Users\\Example\\AppData\\Roaming\\VulnOps\\stake');
    expect(settingsDirectory({ platform: 'win32', home: 'C:\\Users\\Example', env: { APPDATA: 'D:\\Roaming' } })).toBe('D:\\Roaming\\VulnOps\\stake');
    expect(settingsDirectory({ platform: 'linux', env: { STAKE_CONFIG_DIR: '/portable path/literal$(value)' } })).toBe('/portable path/literal$(value)');
    expect(() => settingsDirectory({ directory: 'relative' })).toThrow('absolute');
  });

  it('does not create a settings directory while reading an absent preference', async () => {
    const directory = join(temporary, 'absent');
    expect(await new SettingsStore({ directory }).read()).toEqual({ pair: null, valid: false, diagnostics: [] });
    await expect(lstat(directory)).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('writes canonical absolute paths and format metadata only, with private modes', async () => {
    const selected = await pair();
    const alias = join(temporary, 'ordinary alias'); await symlink(selected.ordinaryPath, alias);
    const directory = join(temporary, 'private settings');
    const store = new SettingsStore({ directory });
    await store.save({ ...selected, ordinaryPath: alias });
    const saved = JSON.parse(await readFile(join(directory, 'sources.json'), 'utf8'));
    expect(saved).toEqual({ version: 1, ordinaryPath: await realpath(selected.ordinaryPath), advantagePath: await realpath(selected.advantagePath) });
    expect(await store.read()).toEqual({ pair: { ordinaryPath: saved.ordinaryPath, advantagePath: saved.advantagePath }, valid: true, diagnostics: [] });
    if (process.platform !== 'win32') {
      expect((await stat(directory)).mode & 0o777).toBe(0o700);
      expect((await stat(join(directory, 'sources.json'))).mode & 0o777).toBe(0o600);
    }
  });

  it('keeps prior complete bytes and cleans only its temporary file after an interrupted save', async () => {
    const first = await pair('first'), second = await pair('second');
    const directory = join(temporary, 'config');
    await new SettingsStore({ directory }).save(first);
    const file = join(directory, 'sources.json'), before = await readFile(file);
    await writeFile(join(directory, 'unrelated.tmp'), 'keep');
    await expect(new SettingsStore({ directory, beforeRename: async () => { throw new Error('synthetic interruption'); } }).save(second)).rejects.toThrow('interruption');
    expect(await readFile(file)).toEqual(before);
    expect((await readdir(directory)).sort()).toEqual(['sources.json', 'unrelated.tmp']);
  });

  it('allows concurrent complete-file writers without mixed paths', async () => {
    const first = await pair('first'), second = await pair('second');
    const directory = join(temporary, 'config');
    await Promise.all([new SettingsStore({ directory }).save(first), new SettingsStore({ directory }).save(second)]);
    const result = await new SettingsStore({ directory }).read();
    const canonical = await Promise.all([first, second].map(async (value) => ({ ordinaryPath: await realpath(value.ordinaryPath), advantagePath: await realpath(value.advantagePath) })));
    expect(result.valid).toBe(true); expect(canonical).toContainEqual(result.pair);
    expect(await readdir(directory)).toEqual(['sources.json']);
  });

  it('recovers safe paths from an unsupported document but never treats it as valid', async () => {
    const selected = await pair();
    const directory = join(temporary, 'config'); await mkdir(directory);
    const file = join(directory, 'sources.json');
    const bytes = JSON.stringify({ version: 99, ...selected, marker: 'SYNTHETIC_NOT_FOR_DIAGNOSTICS' });
    await writeFile(file, bytes);
    const read = await new SettingsStore({ directory }).read();
    expect(read.valid).toBe(false); expect(read.pair).toEqual(selected);
    expect(read.diagnostics.join()).toContain('unsupported'); expect(read.diagnostics.join()).not.toContain('SYNTHETIC');
    expect(await readFile(file, 'utf8')).toBe(bytes);
  });

  it.each(['missing', 'malformed'])('retains the safe field when its saved counterpart is %s', async (kind) => {
    const selected = await pair(); const directory = join(temporary, 'config'); await mkdir(directory);
    const file = join(directory, 'sources.json');
    const bytes = JSON.stringify({ version: 1, ordinaryPath: selected.ordinaryPath, ...(kind === 'malformed' ? { advantagePath: 'relative invalid path' } : {}) });
    await writeFile(file, bytes);
    const result = await new SettingsStore({ directory }).read();
    expect(result).toMatchObject({ valid: false, pair: { ordinaryPath: selected.ordinaryPath, advantagePath: '' } });
    expect(result.diagnostics).toHaveLength(1); expect(await readFile(file, 'utf8')).toBe(bytes);
  });

  it.each(['malformed', 'extra', 'relative', 'oversized'])('returns bounded diagnostics for %s settings without rewriting', async (kind) => {
    const selected = await pair();
    const directory = join(temporary, 'config'); await mkdir(directory);
    const bytes = kind === 'malformed' ? '{SYNTHETIC_NOT_FOR_DIAGNOSTICS' : kind === 'oversized' ? 'X'.repeat(65_537) : JSON.stringify({ version: 1, ...selected, ...(kind === 'relative' ? { ordinaryPath: 'relative' } : { extra: 'SYNTHETIC_NOT_FOR_DIAGNOSTICS' }) });
    await writeFile(join(directory, 'sources.json'), bytes);
    const result = await new SettingsStore({ directory }).read();
    expect(result.valid).toBe(false); expect(result.diagnostics.join()).not.toContain('SYNTHETIC');
    expect(result.diagnostics.join().length).toBeLessThan(250);
    expect(await readFile(join(directory, 'sources.json'), 'utf8')).toBe(bytes);
  });

  it('rejects a directory and a symlink as settings files for both reading and saving', async () => {
    const selected = await pair();
    const directory = join(temporary, 'config'); await mkdir(join(directory, 'sources.json'), { recursive: true });
    const store = new SettingsStore({ directory });
    expect((await store.read()).valid).toBe(false);
    await expect(store.save(selected)).rejects.toThrow('regular');
    await rm(join(directory, 'sources.json'), { recursive: true });
    const outside = join(temporary, 'outside.json'); await writeFile(outside, 'untouched');
    await symlink(outside, join(directory, 'sources.json'));
    expect((await store.read()).valid).toBe(false);
    await expect(store.save(selected)).rejects.toThrow('regular');
    expect(await readFile(outside, 'utf8')).toBe('untouched');
  });

  it('never writes configuration into the checkout, report roots, or a symlink to them', async () => {
    const selected = await pair();
    const checkout = resolve('forbidden-stake-settings-fixture');
    await expect(new SettingsStore({ directory: checkout }).save(selected)).rejects.toThrow('inside');
    await expect(lstat(checkout)).rejects.toMatchObject({ code: 'ENOENT' });
    const inside = join(selected.ordinaryPath, 'config');
    await expect(new SettingsStore({ directory: inside }).save(selected)).rejects.toThrow('inside');
    await expect(lstat(inside)).rejects.toMatchObject({ code: 'ENOENT' });
    const alias = join(temporary, 'alias'); await symlink(selected.ordinaryPath, alias);
    await expect(new SettingsStore({ directory: join(alias, 'config') }).save(selected)).rejects.toThrow('inside');
    await expect(lstat(inside)).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('reports an invalid override and rejects non-absolute path saves', async () => {
    const store = new SettingsStore({ directory: 'relative' });
    expect((await store.read()).diagnostics.join()).toContain('absolute');
    await expect(store.save({ ordinaryPath: 'relative', advantagePath: '/absolute' })).rejects.toThrow('absolute');
  });

  it('returns a bounded recovery diagnostic for an unreadable settings location', async () => {
    const file = join(temporary, 'not-a-directory'); await writeFile(file, 'SYNTHETIC_NOT_FOR_DIAGNOSTICS');
    const store = new SettingsStore({ directory: join(file, 'settings') });
    const result = await store.read();
    expect(result.valid).toBe(false); expect(result.diagnostics).toHaveLength(1);
    expect(JSON.stringify(result)).not.toContain('SYNTHETIC');
  });
});
