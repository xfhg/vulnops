import { test, expect, type BrowserContext, type Page } from '@playwright/test';
import { spawn, type ChildProcess } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, readdir, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, relative, resolve } from 'node:path';
import { createStakeServer, type StakeServer } from '../../server/server.js';
import type { SourcePair, WorkspaceSourceState } from '../../src/domain/sources.js';
import { makeFinding, writeBundle } from '../fixtures/bundles.js';

// Source switches never touch the shared 43179 workspace. Every server uses an
// isolated config directory; all publications and screenshot data are synthetic.
interface Pair extends SourcePair { label: string; ordinaryId: string; advantageId: string; title: string }
interface RunningCli { url: string; child: ChildProcess; stop: () => Promise<void> }
const staticRoot = resolve('dist');
const cliPath = resolve('dist-server/cli.js');
const supportReference = 'sast/verified-findings.json:C-001';

function deferred() {
  let resolvePromise!: () => void;
  const promise = new Promise<void>(done => { resolvePromise = done; });
  return { promise, resolve: resolvePromise };
}

async function temporaryRoot() { return realpath(await mkdtemp(join(tmpdir(), 'stake-source-browser-'))); }

async function pairFixture(parent: string, label: string, long = false): Promise<Pair> {
  const folder = long ? join(parent, `${label} ${'long publication folder '.repeat(6)}`, 'source publications with spaces') : parent;
  const ordinaryId = `audit-${label.toLowerCase()}`;
  const advantageId = `advantage-${label.toLowerCase()}`;
  const title = `${label} ordinary approval boundary`;
  const finding = makeFinding({ title, attack_summary: `${label} source-established approval flow.` });
  finding.remediation!.actions[0].change = `${label}: bind the approval session to its account.`;
  const ordinary = await writeBundle(join(folder, 'ordinary run'), { runId: ordinaryId, findings: [finding] });
  const advantage = await writeBundle(join(folder, 'advantage run'), { runId: advantageId, kind: 'advantage', baselineId: ordinaryId,
    findings: [makeFinding({ id: 'F-060', title: `${label} Advantage approval boundary` })] });
  for (const root of [ordinary.root, advantage.root]) {
    await writeFile(join(root, 'sast/verified-findings.json'), JSON.stringify([{ id: 'C-001', explanation: `${label} canonical support.` }]));
  }
  return { ordinaryPath: ordinary.root, advantagePath: advantage.root, ordinaryId, advantageId, label, title };
}

/** Include names and directories, not just known report hashes, to catch writes. */
async function inventory(pairs: Pair[]): Promise<string[]> {
  const entries: string[] = [];
  async function walk(root: string, path: string) {
    const children = await readdir(path, { withFileTypes: true });
    for (const child of children.sort((a, b) => a.name.localeCompare(b.name))) {
      const full = join(path, child.name), name = relative(root, full);
      entries.push(`${root}:${name}:${child.isDirectory() ? 'directory' : child.isFile() ? createHash('sha256').update(await readFile(full)).digest('hex') : 'other'}`);
      if (child.isDirectory()) await walk(root, full);
    }
  }
  for (const pair of pairs) for (const root of [pair.ordinaryPath, pair.advantagePath]) await walk(root, root);
  return entries;
}

async function localTraffic(context: BrowserContext) {
  const external: string[] = [];
  await context.route('**/*', route => {
    const url = new URL(route.request().url());
    if (url.hostname !== '127.0.0.1') { external.push(url.href); return route.abort(); }
    return route.continue();
  });
  return external;
}

async function startCli(configDir: string, cwd: string, runs: string[] = []): Promise<RunningCli> {
  const env: NodeJS.ProcessEnv = { ...process.env, STAKE_CONFIG_DIR: configDir };
  // This helper invokes Node directly, rather than emulating an npm lifecycle.
  delete env.npm_lifecycle_event;
  delete env.INIT_CWD;
  const child = spawn(process.execPath, [cliPath, 'serve', '--no-open', ...runs.flatMap(path => ['--run', path])], { cwd, env, stdio: ['ignore', 'pipe', 'pipe'] });
  let output = '';
  const stopped = new Promise<void>(done => child.once('exit', () => done()));
  const stop = async () => {
    if (child.exitCode !== null || child.signalCode !== null) return;
    child.kill('SIGTERM');
    const timeout = setTimeout(() => child.kill('SIGKILL'), 3000);
    await stopped;
    clearTimeout(timeout);
  };
  try {
    const url = await new Promise<string>((accept, reject) => {
      const timeout = setTimeout(() => reject(new Error('Temporary source CLI did not announce its local URL. ' + output)), 20_000);
      const receive = (chunk: Buffer) => {
        output = (output + chunk.toString()).slice(-8000);
        const match = output.match(/http:\/\/127\.0\.0\.1:\d+/);
        if (match) { clearTimeout(timeout); accept(match[0]); }
      };
      child.stdout!.on('data', receive);
      child.stderr!.on('data', receive);
      child.once('error', error => { clearTimeout(timeout); reject(error); });
      child.once('exit', code => { clearTimeout(timeout); reject(new Error(`Temporary source CLI exited ${code}: ${output}`)); });
    });
    return { url, child, stop };
  } catch (error) { await stop(); throw error; }
}

async function state(page: Page, url: string): Promise<WorkspaceSourceState> {
  const response = await page.request.get(url + '/api/workspace/sources');
  expect(response.ok()).toBe(true);
  return response.json();
}

async function fillPair(page: Page, pair: SourcePair) {
  await page.getByLabel('Ordinary run folder', { exact: true }).fill(pair.ordinaryPath);
  await page.getByLabel('Advantage run folder', { exact: true }).fill(pair.advantagePath);
}

async function openSettings(page: Page) {
  await page.getByRole('button', { name: 'Settings', exact: true }).click();
  await expect(page.getByRole('dialog', { name: 'Report sources' })).toBeVisible();
}

async function loadPair(page: Page, url: string, pair: Pair) {
  const before = await state(page, url);
  await fillPair(page, pair);
  await page.getByRole('button', { name: 'Load reports', exact: true }).click();
  await expect.poll(async () => (await state(page, url)).generation).not.toBe(before.generation);
  await expect(page.getByRole('heading', { name: 'Assessment overview', exact: true })).toBeVisible();
  await expect(page.getByRole('dialog', { name: 'Report sources' })).not.toBeVisible();
  await expect(page.locator('.scope-cards')).toContainText(pair.ordinaryId);
  await expect(page.getByRole('heading', { name: 'Assessment overview', exact: true })).toBeFocused();
  return state(page, url);
}

function deepLink(url: string, pair: Pair) {
  return url + '/?view=findings&finding=' + encodeURIComponent(JSON.stringify(['finding', pair.ordinaryId, 'F-001']));
}

async function assertAllViews(page: Page, url: string, pair: Pair) {
  const nav = page.getByRole('navigation', { name: 'Main navigation' });
  await nav.getByRole('button', { name: 'Overview', exact: true }).click();
  await expect(page.locator('.priority-list')).toContainText(pair.title);
  await nav.getByRole('button', { name: /^Findings\b/ }).click();
  await page.getByRole('button', { name: 'Open F-001', exact: true }).click();
  await expect(page.getByRole('heading', { level: 1 })).toHaveText(pair.title);
  await page.getByRole('tab', { name: 'Evidence', exact: true }).click();
  await page.getByRole('button', { name: supportReference, exact: true }).first().click();
  await expect(page.getByRole('dialog')).toContainText(`${pair.label} canonical support.`);
  await expect(page.getByRole('dialog')).toContainText(`Owning execution: ${pair.ordinaryId}`);
  await page.keyboard.press('Escape');
  await nav.getByRole('button', { name: 'Attack explorer', exact: true }).click();
  await expect(page.getByRole('region', { name: 'Attack overview' })).toBeVisible();
  await expect(page.locator('.ep-canvas')).toContainText(pair.title);
  await nav.getByRole('button', { name: 'Code map', exact: true }).click();
  await expect(page.getByRole('region', { name: 'Cited code map' })).toBeVisible();
  await page.locator('.code-file-button').filter({ hasText: pair.ordinaryId }).click();
  await expect(page.locator('.code-map-detail')).toContainText(pair.title);
  await nav.getByRole('button', { name: 'Remediation', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Plan the change. Trace the repair.' })).toBeVisible();
  await expect(page.locator('.rm-queue-item').filter({ hasText: `${pair.label}: bind the approval session` })).toHaveCount(1);
  await nav.getByRole('button', { name: 'Assessment', exact: true }).click();
  await page.getByLabel('Assessment', { exact: true }).selectOption(pair.ordinaryId);
  await expect(page.getByRole('region', { name: 'Selected assessment' })).toContainText(pair.ordinaryId);
  const current = await state(page, url);
  expect(current.sources.map(source => source.runId).sort()).toEqual([pair.advantageId, pair.ordinaryId].sort());
}

async function evidenceToken(page: Page, url: string, pair: Pair, generation: string) {
  const response = await page.request.get(url + '/api/reference', { params: { runId: pair.ordinaryId, ref: JSON.stringify(supportReference) }, headers: { 'X-Stake-Workspace': generation } });
  expect(response.ok()).toBe(true);
  return (await response.json()).token as string;
}

test('empty CLI setup loads and switches every view, rolls back failures, and restarts from paths only', async ({ page, context }) => {
  test.setTimeout(90_000);
  const root = await temporaryRoot(), configDir = join(root, 'settings');
  const alpha = await pairFixture(join(root, 'alpha'), 'Alpha');
  const beta = await pairFixture(join(root, 'beta'), 'Beta');
  const before = await inventory([alpha, beta]), external = await localTraffic(context);
  const children: RunningCli[] = [];
  try {
    let cli = await startCli(configDir, root); children.push(cli);
    await page.goto(cli.url);
    await expect(page.getByRole('heading', { name: 'Load your reports' })).toBeVisible();
    await expect(page.locator('.metric-grid')).toHaveCount(0);
    await expect(page.getByLabel('Ordinary run folder', { exact: true })).toHaveValue('');
    await page.screenshot({ path: '/private/tmp/atstake-source-setup-desktop.png' });
    const alphaState = await loadPair(page, cli.url, alpha);
    expect(alphaState.persistence.status).toBe('remembered');
    expect(JSON.parse(await readFile(join(configDir, 'sources.json'), 'utf8'))).toEqual({ version: 1, ordinaryPath: alpha.ordinaryPath, advantagePath: alpha.advantagePath });
    await assertAllViews(page, cli.url, alpha);

    const savedAlpha = await readFile(join(configDir, 'sources.json'), 'utf8');
    await openSettings(page);
    await fillPair(page, { ordinaryPath: beta.ordinaryPath, advantagePath: join(root, 'missing advantage') });
    await page.getByRole('button', { name: 'Load reports', exact: true }).click();
    await expect(page.getByLabel('Advantage run folder', { exact: true })).toHaveAttribute('aria-invalid', 'true');
    await expect(page.getByLabel('Advantage run folder', { exact: true })).toBeFocused();
    await expect(page.getByLabel('Ordinary run folder', { exact: true })).toHaveValue(beta.ordinaryPath);
    expect((await state(page, cli.url)).generation).toBe(alphaState.generation);
    expect(await readFile(join(configDir, 'sources.json'), 'utf8')).toBe(savedAlpha);
    await page.keyboard.press('Escape');
    await page.goto(deepLink(cli.url, alpha) + '&panel=repair&repair=action-1&selected=step-1&q=Alpha');
    await expect(page.getByRole('heading', { level: 1 })).toHaveText(alpha.title);
    await page.getByRole('button', { name: 'Use dark theme', exact: true }).click();
    await openSettings(page);
    await loadPair(page, cli.url, beta);
    expect(new URL(page.url()).search).toBe('?view=overview');
    expect(page.url()).not.toContain('ordinaryPath');
    await expect(page.locator('html')).toHaveClass(/dark/);
    await assertAllViews(page, cli.url, beta);
    await openSettings(page);
    await expect(page.getByRole('region', { name: 'Currently loaded' })).toContainText(beta.ordinaryPath);
    await page.screenshot({ path: '/private/tmp/atstake-sources-desktop.png' });
    await page.keyboard.press('Escape');
    await page.goto(deepLink(cli.url, alpha));
    await expect(page.getByRole('heading', { name: 'Finding unavailable' })).toBeVisible();
    await page.goto(deepLink(cli.url, beta));
    await page.reload();
    await expect(page.getByRole('heading', { level: 1 })).toHaveText(beta.title);
    await cli.stop();

    cli = await startCli(configDir, tmpdir()); children.push(cli);
    await page.goto(deepLink(cli.url, beta));
    await expect(page.getByRole('heading', { level: 1 })).toHaveText(beta.title);
    expect((await state(page, cli.url)).origin).toBe('saved');
    await cli.stop();

    // Direct CLI arguments take precedence; no old saved fallback hides errors.
    cli = await startCli(configDir, root, [relative(root, alpha.ordinaryPath), relative(root, alpha.advantagePath)]); children.push(cli);
    await page.goto(deepLink(cli.url, alpha));
    await expect(page.getByRole('heading', { level: 1 })).toHaveText(alpha.title);
    expect((await state(page, cli.url)).origin).toBe('cli');
    await cli.stop();
    await expect(startCli(configDir, root, [join(root, 'missing explicit run')])).rejects.toThrow(/exited 1/);
    expect(JSON.parse(await readFile(join(configDir, 'sources.json'), 'utf8')).ordinaryPath).toBe(alpha.ordinaryPath);

    // A remembered unavailable folder opens recovery, never a partial dashboard.
    const unavailable = { version: 1, ordinaryPath: alpha.ordinaryPath, advantagePath: join(root, 'unavailable remembered run') };
    await writeFile(join(configDir, 'sources.json'), JSON.stringify(unavailable));
    cli = await startCli(configDir, root); children.push(cli);
    await page.goto(cli.url);
    await expect(page.getByRole('heading', { name: 'Load your reports' })).toBeVisible();
    await expect(page.locator('.metric-grid')).toHaveCount(0);
    await expect(page.getByLabel('Ordinary run folder', { exact: true })).toHaveValue(alpha.ordinaryPath);
    await expect(page.getByLabel('Advantage run folder', { exact: true })).toHaveValue(unavailable.advantagePath);
    await expect(page.locator('.sources-notice')).toContainText('remembered report pair could not be loaded');
    expect((await state(page, cli.url)).sources).toEqual([]);
    expect(JSON.parse(await readFile(join(configDir, 'sources.json'), 'utf8'))).toEqual(unavailable);
    expect(external).toEqual([]);
    expect(await inventory([alpha, beta])).toEqual(before);
  } finally { for (const child of children) await child.stop(); await rm(root, { recursive: true, force: true }); }
});

test('tabs keep stale drafts explicit, discard old evidence and finding responses, and reload same paths as a new generation', async ({ page, context }) => {
  const root = await temporaryRoot(), configDir = join(root, 'settings');
  const alpha = await pairFixture(join(root, 'alpha'), 'Alpha'), beta = await pairFixture(join(root, 'beta'), 'Beta');
  const before = await inventory([alpha, beta]), external = await localTraffic(context);
  const server = await createStakeServer({ runs: [alpha.ordinaryPath, alpha.advantagePath], staticRoot, configDir });
  const other = await context.newPage(), evidenceHeld = deferred(), evidenceRelease = deferred(), findingHeld = deferred(), findingRelease = deferred();
  try {
    await page.goto(server.url);
    await openSettings(page);
    await fillPair(page, { ordinaryPath: alpha.ordinaryPath, advantagePath: beta.advantagePath });
    await other.goto(deepLink(server.url, alpha) + '&panel=evidence');
    await other.route('**/api/evidence/*', async route => {
      const response = await route.fetch(); evidenceHeld.resolve();
      await evidenceRelease.promise;
      await route.fulfill({ response }).catch(() => {}); // The replaced component aborts its request.
    });
    await other.getByRole('button', { name: supportReference, exact: true }).first().click();
    await evidenceHeld.promise;
    await expect(other.getByRole('dialog')).toContainText('Resolving evidence');
    const initial = await state(page, server.url);
    const switched = await page.request.post(server.url + '/api/workspace/sources', {
      headers: { Origin: server.url }, data: { ordinaryPath: beta.ordinaryPath, advantagePath: beta.advantagePath, expectedGeneration: initial.generation },
    });
    expect(switched.ok()).toBe(true);
    await page.bringToFront(); await page.evaluate(() => window.dispatchEvent(new Event('focus')));
    await expect(page.getByRole('button', { name: 'Use current sources', exact: true })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Load reports', exact: true })).toBeDisabled();
    await expect(page.getByLabel('Ordinary run folder', { exact: true })).toHaveValue(alpha.ordinaryPath);
    await expect(page.getByLabel('Advantage run folder', { exact: true })).toHaveValue(beta.advantagePath);
    await other.bringToFront(); await other.evaluate(() => window.dispatchEvent(new Event('focus')));
    await expect(other.getByRole('heading', { name: 'Assessment overview', exact: true })).toBeVisible();
    await expect(other.getByRole('dialog')).not.toBeVisible();
    evidenceRelease.resolve();
    await expect(other.locator('#main')).not.toContainText('Alpha canonical support.');
    await expect(other.locator('.scope-cards')).toContainText(beta.ordinaryId);

    await other.route('**/api/findings/*', async route => {
      const response = await route.fetch(); findingHeld.resolve();
      await findingRelease.promise;
      await route.fulfill({ response }).catch(() => {});
    });
    await other.goto(deepLink(server.url, beta));
    await findingHeld.promise;
    const prior = await state(page, server.url);
    const oldToken = await evidenceToken(page, server.url, beta, prior.generation);
    await page.bringToFront();
    await page.getByRole('button', { name: 'Use current sources', exact: true }).click();
    await expect(page.getByLabel('Ordinary run folder', { exact: true })).toHaveValue(beta.ordinaryPath);
    const loaded = await loadPair(page, server.url, beta);
    expect(loaded.generation).not.toBe(prior.generation);
    expect(await evidenceToken(page, server.url, beta, loaded.generation)).not.toBe(oldToken);
    const stale = await page.request.get(server.url + '/api/evidence/' + encodeURIComponent(oldToken), { headers: { 'X-Stake-Workspace': prior.generation } });
    expect(stale.status()).toBe(409);
    const retired = await page.request.get(server.url + '/api/evidence/' + encodeURIComponent(oldToken), { headers: { 'X-Stake-Workspace': loaded.generation } });
    expect(retired.status()).toBe(404);
    await other.bringToFront(); await other.evaluate(() => window.dispatchEvent(new Event('focus')));
    await expect(other.getByRole('heading', { name: 'Assessment overview', exact: true })).toBeVisible();
    findingRelease.resolve();
    await expect(other.locator('.finding-detail')).toHaveCount(0);
    expect(new URL(other.url()).search).toBe('?view=overview');
    expect(external).toEqual([]);
    expect(await inventory([alpha, beta])).toEqual(before);
  } finally {
    evidenceRelease.resolve(); findingRelease.resolve();
    await test.step('Close source test browser clients', async () => { await other.close(); await page.close(); });
    await test.step('Dispose source test response bodies', async () => { await context.request.dispose(); });
    await test.step('Close disposable source listener and connections', async () => {
      // Browser-context request disposal retains its keep-alive agents until
      // the context closes. This isolated test has finished every assertion;
      // stop accepting connections before retiring its remaining test sockets.
      const closed = server.close();
      server.server.closeAllConnections();
      await closed;
    });
    await rm(root, { recursive: true, force: true });
  }
});

test('a dropped load response stays pending without resubmission and recovers a session-only save warning', async ({ page, context }) => {
  const root = await temporaryRoot(), configDir = join(root, 'settings');
  const alpha = await pairFixture(join(root, 'alpha'), 'Alpha'), beta = await pairFixture(join(root, 'beta'), 'Beta');
  const before = await inventory([alpha, beta]), external = await localTraffic(context);
  const entered = deferred(), release = deferred();
  let failSave = false, posts = 0;
  const server = await createStakeServer({ runs: [alpha.ordinaryPath, alpha.advantagePath], staticRoot, configDir,
    sourceHooks: { beforeLoad: async () => { entered.resolve(); await release.promise; }, beforeSave: async () => { if (failSave) throw new Error('Synthetic persistence failure'); } },
  });
  const saved = await readFile(join(configDir, 'sources.json'), 'utf8');
  try {
    await page.route('**/api/workspace/sources', async route => {
      if (route.request().method() !== 'POST') return route.fallback();
      posts++;
      const forwarded = route.fetch();
      await entered.promise;
      await route.abort('failed');
      await forwarded.catch(() => {});
    });
    await page.goto(server.url); await openSettings(page); await fillPair(page, beta);
    await page.getByRole('button', { name: 'Load reports', exact: true }).click();
    await entered.promise;
    await expect.poll(() => server.sourceState.loading).toBe(true);
    await expect(page.locator('.sources-result-status')).toContainText('interrupted');
    await expect(page.getByRole('button', { name: 'Load reports', exact: true })).toBeDisabled();
    await page.getByRole('button', { name: 'Close settings', exact: true }).click();
    await expect(page.locator('.workspace-notice')).toContainText('Loading reports');
    await openSettings(page);
    await expect(page.getByRole('button', { name: 'Load reports', exact: true })).toBeDisabled();
    await page.getByRole('button', { name: 'Close settings', exact: true }).click();
    failSave = true; release.resolve();
    await expect.poll(() => server.sourceState.lastLoad?.status).toBe('success');
    await page.evaluate(() => window.dispatchEvent(new Event('focus')));
    await expect(page.locator('.scope-cards')).toContainText(beta.ordinaryId);
    await expect(page.locator('.warning-banner')).toContainText('Loaded for this session; paths could not be remembered');
    expect(server.sourceState.persistence.status).toBe('session_only');
    expect(server.sourceState.lastLoad?.persistence.status).toBe('session_only');
    expect(await readFile(join(configDir, 'sources.json'), 'utf8')).toBe(saved);
    await openSettings(page);
    await expect(page.locator('.sources-persistence')).toContainText('Loaded for this session');
    await expect(page.getByRole('button', { name: 'Load reports', exact: true })).toBeEnabled();
    expect(posts).toBe(1);
    expect(external).toEqual([]);
    expect(await inventory([alpha, beta])).toEqual(before);
  } finally { release.resolve(); await server.close(); await rm(root, { recursive: true, force: true }); }
});

for (const theme of ['light', 'dark'] as const) test(`${theme} narrow setup supports keyboard errors, long paths, focus and draft dismissal`, async ({ page, context }) => {
  const root = await temporaryRoot(), configDir = join(root, 'settings');
  const pair = await pairFixture(join(root, 'publications'), 'Long', true);
  const before = await inventory([pair]), external = await localTraffic(context);
  const server: StakeServer = await createStakeServer({ runs: [], staticRoot, configDir });
  try {
    await page.setViewportSize({ width: 390, height: 844 });
    await page.addInitScript(value => localStorage.setItem('stake-theme', value), theme);
    await page.goto(server.url);
    await expect(page.getByRole('heading', { name: 'Load your reports' })).toBeVisible();
    const initial = await state(page, server.url);
    await fillPair(page, { ordinaryPath: 'relative/ordinary', advantagePath: pair.advantagePath });
    await page.getByLabel('Advantage run folder', { exact: true }).press('Enter');
    await expect(page.getByLabel('Ordinary run folder', { exact: true })).toBeFocused();
    await expect(page.getByLabel('Ordinary run folder', { exact: true })).toHaveAttribute('aria-invalid', 'true');
    await expect(page.getByRole('alert')).toContainText('Check the marked folder paths');
    expect((await state(page, server.url)).generation).toBe(initial.generation);
    await page.getByLabel('Ordinary run folder', { exact: true }).fill(pair.ordinaryPath);
    await page.evaluate(() => window.scrollTo(0, 0));
    await page.screenshot({ path: `/private/tmp/atstake-source-setup-${theme}-mobile.png` });
    await page.getByLabel('Ordinary run folder', { exact: true }).press('Enter');
    await expect(page.getByRole('heading', { name: 'Assessment overview', exact: true })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Assessment overview', exact: true })).toBeFocused();
    expect(await page.locator('html').evaluate(element => element.classList.contains('dark'))).toBe(theme === 'dark');
    const settings = page.getByRole('button', { name: 'Settings', exact: true });
    await settings.focus(); await page.keyboard.press('Enter');
    await expect(page.getByLabel('Ordinary run folder', { exact: true })).toBeFocused();
    const current = page.getByRole('region', { name: 'Currently loaded' });
    await expect(current).toContainText(pair.ordinaryPath);
    await expect(current).toContainText(pair.advantagePath);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBe(true);
    expect(await current.locator('code').evaluateAll(elements => elements.every(element => element.scrollWidth <= element.clientWidth + 1))).toBe(true);
    await page.getByLabel('Ordinary run folder', { exact: true }).fill('/discard this unsubmitted draft');
    await page.keyboard.press('Escape');
    await expect(settings).toBeFocused();
    await page.keyboard.press('Enter');
    await expect(page.getByLabel('Ordinary run folder', { exact: true })).toHaveValue(pair.ordinaryPath);
    await page.locator('.sources-sheet-body').evaluate(element => { element.scrollTop = 0; });
    await page.screenshot({ path: `/private/tmp/atstake-sources-${theme}-mobile.png` });
    expect(external).toEqual([]);
    expect(await inventory([pair])).toEqual(before);
  } finally { await server.close(); await rm(root, { recursive: true, force: true }); }
});
