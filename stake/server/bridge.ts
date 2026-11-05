import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

export const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
export const defaultBridgePath = resolve(packageRoot, 'server/publication_bridge.py');

export class BridgeError extends Error {
  constructor(public code: string, message: string) { super(message); }
}

export interface BridgeOptions { python?: string; bridgePath?: string; timeoutMs?: number }

/** JSON over pipes; no shell, temporary output, raw stderr, or exec maxBuffer. */
export function bridgeCall<T>(request: unknown, options: BridgeOptions = {}): Promise<T> {
  return new Promise((resolveResult, reject) => {
    const child = spawn(options.python ?? process.env.STAKE_PYTHON ?? 'python3',
      ['-B', options.bridgePath ?? defaultBridgePath], {
        env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1', PYTHONNOUSERSITE: '1' },
        stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true,
      });
    const chunks: Buffer[] = [];
    let settled = false;
    const finish = (error?: Error, value?: T) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (error) reject(error); else resolveResult(value as T);
    };
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      finish(new BridgeError('timeout', 'Publication read exceeded its runtime allowance. Try loading a readable local bundle.'));
    }, options.timeoutMs ?? 120_000);
    child.stdout.on('data', (chunk: Buffer) => chunks.push(chunk));
    child.stderr.resume(); // Never copy potentially unsafe Python diagnostics.
    child.on('error', () => finish(new BridgeError('prerequisite', 'Python could not start. Install Python 3.10+ during preparation or set STAKE_PYTHON to its executable.')));
    child.stdin.on('error', () => { /* Reported by close/error. */ });
    child.on('close', (code) => {
      if (code !== 0) return finish(new BridgeError('bridge_failed', 'The read-only publication bridge failed. Check Python 3.10+ and the complete harness checkout.'));
      try {
        const result = JSON.parse(Buffer.concat(chunks).toString('utf8')) as { ok: boolean; value: T; code: string; message: string };
        if (!result.ok) finish(new BridgeError(result.code, result.message));
        else finish(undefined, result.value);
      } catch { finish(new BridgeError('bridge_failed', 'The publication bridge returned invalid data.')); }
    });
    child.stdin.end(JSON.stringify(request));
  });
}

export async function checkPrerequisites(options: BridgeOptions = {}): Promise<void> {
  const result = await bridgeCall<{ python: number[] }>({ operation: 'probe' }, options);
  if (result.python[0] !== 3 || (result.python[1] ?? 0) < 10)
    throw new BridgeError('prerequisite', 'Stake requires Python 3.10 or newer. Set STAKE_PYTHON to a supported interpreter.');
}
