import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { writePair } from '../fixtures/bundles.js';

const root = await mkdtemp(join(tmpdir(), 'stake-browser-'));
const pair = await writePair(root);
await writeFile(join(pair.ordinary.root, 'report/security-report.md'), '# Synthetic assessment\n\nExamples are inert and not executed.\n\n<script>window.STAKE_INJECTED = true</script>\n\n![remote](https://remote.invalid/secret.png)\n\n[remote link](https://remote.invalid/)');
const child = spawn(process.execPath, ['dist-server/cli.js', 'serve', '--run', pair.ordinary.root, '--run', pair.advantage.root, '--port', '43179', '--no-open'], {
  stdio: 'inherit', env: { ...process.env, STAKE_CONFIG_DIR: join(root, 'settings') },
});
async function stop() { child.kill('SIGTERM'); await rm(root, { recursive: true, force: true }); }
process.on('SIGTERM', () => void stop());
process.on('SIGINT', () => void stop());
child.once('exit', (code) => { void rm(root, { recursive: true, force: true }).finally(() => process.exit(code ?? 0)); });
