import { constants } from 'node:fs';
import { lstat, mkdir, open, realpath, rename, unlink } from 'node:fs/promises';
import { dirname, isAbsolute, join, relative, resolve, sep, win32, posix } from 'node:path';
import { homedir } from 'node:os';
import { randomUUID } from 'node:crypto';
import type { SourcePair } from '../src/domain/sources.js';
import { packageRoot } from './bridge.js';

export const MAX_SETTINGS_BYTES = 65_536;
export const MAX_SOURCE_PATH_BYTES = 16_384;
export interface SavedSources extends SourcePair { version: 1 }
export interface SettingsRead { pair: SourcePair | null; valid: boolean; diagnostics: string[] }
export interface SettingsOptions {
  directory?: string;
  protectedRoots?: string[];
  /** Deterministic save failure/interruption seam; never exposed over HTTP. */
  beforeRename?: () => Promise<void>;
}

export function settingsDirectory(options: { platform?: NodeJS.Platform; home?: string; env?: NodeJS.ProcessEnv; directory?: string } = {}): string {
  const platform = options.platform ?? process.platform;
  const env = options.env ?? process.env;
  const home = options.home ?? homedir();
  const path = platform === 'win32' ? win32 : posix;
  const override = options.directory ?? env.STAKE_CONFIG_DIR;
  if (override !== undefined) {
    if (!override || !path.isAbsolute(override) || /[\x00-\x1f\x7f]/.test(override)) throw new Error('STAKE_CONFIG_DIR must be an absolute directory outside the checkout and report inputs.');
    return path.resolve(override);
  }
  if (platform === 'darwin') return path.join(home, 'Library', 'Application Support', 'VulnOps', 'stake');
  if (platform === 'win32') return path.join(env.APPDATA && path.isAbsolute(env.APPDATA) ? env.APPDATA : path.join(home, 'AppData', 'Roaming'), 'VulnOps', 'stake');
  return path.join(env.XDG_CONFIG_HOME && path.isAbsolute(env.XDG_CONFIG_HOME) ? env.XDG_CONFIG_HOME : path.join(home, '.config'), 'vulnops', 'stake');
}

export function validSourcePath(value: unknown): value is string {
  return typeof value === 'string' && !!value && isAbsolute(value) && !/[\x00-\x1f\x7f]/.test(value) && Buffer.byteLength(value) <= MAX_SOURCE_PATH_BYTES;
}
function contains(root: string, path: string): boolean {
  const rel = relative(root, path);
  return rel === '' || (!rel.startsWith(`..${sep}`) && rel !== '..' && !isAbsolute(rel));
}
// Resolve nonexistent descendants through their nearest existing ancestor so a
// symlinked parent cannot hide a protected destination before mkdir runs.
async function canonicalDestination(path: string): Promise<string> {
  try { return await realpath(path); }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    const parent = dirname(path);
    if (parent === path) throw error;
    return resolve(await canonicalDestination(parent), relative(parent, path));
  }
}

export class SettingsStore {
  private readonly configuredDirectory: string | null;
  private readonly locationError: string | null;
  constructor(private readonly options: SettingsOptions = {}) {
    try { this.configuredDirectory = settingsDirectory({ directory: options.directory }); this.locationError = null; }
    catch { this.configuredDirectory = null; this.locationError = 'Settings location is unavailable: use an absolute STAKE_CONFIG_DIR outside the checkout and report inputs.'; }
  }

  private async location(roots: string[] = []): Promise<{ directory: string; file: string }> {
    if (!this.configuredDirectory) throw new Error(this.locationError!);
    const directory = await canonicalDestination(this.configuredDirectory);
    for (const root of [resolve(packageRoot, '..'), ...(this.options.protectedRoots ?? []), ...roots]) {
      const protectedRoot = await canonicalDestination(resolve(root));
      if (contains(protectedRoot, directory)) throw new Error('Settings location is inside the checkout or a report input; remembering paths is unavailable.');
    }
    return { directory, file: join(directory, 'sources.json') };
  }

  async read(roots: string[] = []): Promise<SettingsRead> {
    let file: string;
    try { ({ file } = await this.location(roots)); }
    catch { return { pair: null, valid: false, diagnostics: [this.locationError ?? 'Settings location is unavailable or inside a protected input.'] }; }
    let handle;
    try {
      const info = await lstat(file);
      if (!info.isFile() || info.isSymbolicLink()) throw new Error('nonregular');
      handle = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
      const opened = await handle.stat();
      if (!opened.isFile() || opened.size > MAX_SETTINGS_BYTES) throw new Error('invalid_size');
      const bytes = Buffer.alloc(MAX_SETTINGS_BYTES + 1);
      let length = 0;
      while (length < bytes.length) {
        const { bytesRead } = await handle.read(bytes, length, bytes.length - length, null);
        if (!bytesRead) break;
        length += bytesRead;
      }
      if (length > MAX_SETTINGS_BYTES) throw new Error('invalid_size');
      const value: unknown = JSON.parse(bytes.subarray(0, length).toString('utf8'));
      if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('invalid_format');
      const record = value as Record<string, unknown>;
      const ordinaryPath = validSourcePath(record.ordinaryPath) ? record.ordinaryPath : '';
      const advantagePath = validSourcePath(record.advantagePath) ? record.advantagePath : '';
      // A damaged preference can still provide one safe field for setup. An
      // empty counterpart is recovery data, never a partially admitted pair.
      const pair = ordinaryPath || advantagePath ? { ordinaryPath, advantagePath } : null;
      if (record.version !== 1) return { pair, valid: false, diagnostics: ['Saved report settings use an unsupported format version. Select a valid pair to replace them.'] };
      if (!pair || !ordinaryPath || !advantagePath || Object.keys(record).sort().join(',') !== 'advantagePath,ordinaryPath,version') return { pair, valid: false, diagnostics: ['Saved report settings have an invalid format. Select a valid pair to replace them.'] };
      try { await this.location([pair.ordinaryPath, pair.advantagePath]); }
      catch { return { pair, valid: false, diagnostics: ['Settings location is unavailable or inside a protected input.'] }; }
      return { pair, valid: true, diagnostics: [] };
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return { pair: null, valid: false, diagnostics: [] };
      return { pair: null, valid: false, diagnostics: ['Saved report settings could not be read safely. Select a valid pair to replace them.'] };
    } finally { await handle?.close(); }
  }

  async save(pair: SourcePair, roots: string[] = []): Promise<void> {
    if (!validSourcePath(pair.ordinaryPath) || !validSourcePath(pair.advantagePath)) throw new Error('Settings require two absolute source paths.');
    // Admission already resolves these; repeat to prevent noncanonical callers
    // from persisting aliases and to protect the actual selected directories.
    const canonical = { ordinaryPath: await realpath(pair.ordinaryPath), advantagePath: await realpath(pair.advantagePath) };
    const protectedRoots = [...roots, canonical.ordinaryPath, canonical.advantagePath];
    const location = await this.location(protectedRoots);
    await mkdir(location.directory, { recursive: true, mode: 0o700 });
    const checked = await this.location(protectedRoots);
    if (checked.directory !== location.directory) throw new Error('Settings directory changed during saving.');
    const checkFile = async () => {
      try { const info = await lstat(location.file); if (!info.isFile() || info.isSymbolicLink()) throw new Error('Settings file is not a regular file.'); }
      catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
    };
    await checkFile();
    const temporary = join(location.directory, `.sources-${randomUUID()}.tmp`);
    let handle;
    try {
      handle = await open(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
      await handle.writeFile(JSON.stringify({ version: 1, ...canonical } satisfies SavedSources) + '\n', 'utf8');
      await handle.sync();
      await handle.close(); handle = undefined;
      await this.options.beforeRename?.();
      const finalLocation = await this.location(protectedRoots);
      if (finalLocation.directory !== location.directory) throw new Error('Settings directory changed during saving.');
      await checkFile();
      await rename(temporary, location.file);
    } finally {
      await handle?.close();
      await unlink(temporary).catch(() => {});
    }
  }
}
