#!/usr/bin/env node
import { spawn } from 'node:child_process';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createStakeServer, StartupError, type ServerOptions, type StakeServer } from './server.js';

export const usage = `VulnOps @stake — local report workspace

Usage: stake serve [--run <run-directory> ...] [--port <1-65535>] [--no-open]

Run directories are resolved from your invoking working directory.
Explicit --run inputs take precedence over the remembered report pair.
Without --run, load the remembered pair or open setup. Settings can load another pair.
Successful ordinary/Advantage pairs are remembered locally; STAKE_CONFIG_DIR overrides the settings directory.
Requires Python 3.10+ and the complete VulnOps checkout; set STAKE_PYTHON if needed.
After preparation/build, operation is offline and inputs remain read-only.`;

export function parseArgs(args: string[]): ServerOptions & { open: boolean } {
  if (args[0] !== 'serve') throw new Error('Expected the serve command.\n' + usage);
  const result: ServerOptions & { open: boolean } = { runs: [], open: true };
  for (let index = 1; index < args.length; index++) {
    const arg = args[index];
    if (arg === '--no-open') { result.open = false; continue; }
    if (arg === '--run') {
      const value = args[++index];
      if (!value || value.startsWith('--')) throw new Error('--run requires a directory path.');
      result.runs.push(value); continue;
    }
    if (arg === '--port') {
      const value = args[++index] ?? '';
      if (!/^\d+$/.test(value) || Number(value) < 1 || Number(value) > 65535) throw new Error('--port must be an integer from 1 to 65535.');
      result.port = Number(value); continue;
    }
    throw new Error('Unknown option.\n' + usage);
  }
  return result;
}

export function openBrowser(url: string): Promise<void> {
  return new Promise((resolveOpen, reject) => {
    const command = process.platform === 'darwin' ? 'open' : process.platform === 'win32' ? 'rundll32' : 'xdg-open';
    const args = process.platform === 'win32' ? ['url.dll,FileProtocolHandler', url] : [url];
    const child = spawn(command, args, { stdio: 'ignore', windowsHide: true });
    const timer = setTimeout(() => { child.kill(); reject(new Error('Browser opener timed out.')); }, 5000);
    child.once('error', () => { clearTimeout(timer); reject(new Error('Browser opener unavailable.')); });
    child.once('exit', (code) => { clearTimeout(timer); if (code === 0) resolveOpen(); else reject(new Error('Browser opener failed.')); });
  });
}

export async function runCli(args: string[], hooks: { log?: (message: string) => void; warn?: (message: string) => void; opener?: (url: string) => Promise<void>; options?: Partial<ServerOptions> } = {}): Promise<StakeServer | null> {
  const log = hooks.log ?? console.log;
  const warn = hooks.warn ?? console.error;
  if (args.includes('--help') || args.includes('-h')) { log(usage); return null; }
  const parsed = parseArgs(args);
  // npm runs package scripts from the package directory, but records the
  // operator's invocation directory separately (including --prefix launches).
  const cwd = process.env.npm_lifecycle_event && process.env.INIT_CWD ? process.env.INIT_CWD : process.cwd();
  const instance = await createStakeServer({ ...parsed, cwd, ...hooks.options });
  for (const failure of instance.workspace.failures) warn(`Input unavailable${failure.inputPath ? ` (${failure.inputPath})` : ''}: ${failure.message}`);
  for (const diagnostic of instance.sourceState.diagnostics) warn(diagnostic);
  if (instance.sourceState.persistence.status === 'session_only') warn(instance.sourceState.persistence.message!);
  log(instance.workspace.assessments.length ? `VulnOps @stake is serving ${instance.workspace.assessments.length} assessment(s): ${instance.url}` : `VulnOps @stake is ready for report setup: ${instance.url}`);
  if (parsed.open) {
    try { await (hooks.opener ?? openBrowser)(instance.url); }
    catch { warn(`The browser could not open automatically. Open ${instance.url} to continue.`); }
  }
  return instance;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  runCli(process.argv.slice(2)).then((instance) => {
    if (!instance) return;
    const stop = () => { void instance.close().finally(() => { process.exitCode = 0; }); };
    process.once('SIGINT', stop);
    process.once('SIGTERM', stop);
  }).catch((error: unknown) => {
    if (error instanceof StartupError) for (const failure of error.failures) console.error(`Input unavailable${failure.inputPath ? ` (${failure.inputPath})` : ''}: ${failure.message}`);
    console.error(error instanceof Error ? error.message : 'VulnOps @stake could not start.');
    process.exitCode = 1;
  });
}
