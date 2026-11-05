import { test, expect } from '@playwright/test';
import { mkdtemp, rm, readFile, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { createHash } from 'node:crypto';
import { createStakeServer } from '../../server/server.js';
import { makeFinding, writeBundle } from '../fixtures/bundles.js';

test('CLI workspace supports filters, detail history, evidence and inert offline Markdown', async ({ page, context }) => {
  const external: string[] = [];
  const errors: string[] = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.route('**/*', route => {
    const url = new URL(route.request().url());
    if (url.hostname !== '127.0.0.1') { external.push(url.href); return route.abort(); }
    return route.continue();
  });
  await page.goto('/');
  await expect(page).toHaveTitle('VulnOps @stake — Security findings workspace');
  await expect(page.getByRole('link', { name: 'VulnOps @stake home' })).toBeVisible();
  await expect(page.getByRole('img', { name: 'VulnOps Doberman' })).toHaveJSProperty('naturalWidth', 1254);
  await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
  await page.getByRole('navigation').getByRole('button', { name: 'Findings' }).click();
  await page.getByLabel('Select assessment').selectOption('audit-fixture');
  await page.getByLabel('Filter disposition').selectOption('needs_environment');
  await expect(page.getByText('1 matching finding', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Open F-002', exact: true }).click();
  const deepLink = page.url();
  await page.getByRole('tab', { name: /Reproduce/ }).click();
  await expect(page.locator('.procedure-card')).toHaveCount(2);
  await expect(page.locator('.procedure-card').first()).toContainText('environment required');
  await expect(page.getByText('not executed', { exact: true })).toBeVisible();
  await context.grantPermissions(['clipboard-read', 'clipboard-write']);
  await page.getByRole('button', { name: 'Copy example', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Copied', exact: true })).toBeVisible();
  expect(await page.evaluate(() => navigator.clipboard.readText())).toContain('SYNTHETIC_ORDER');
  await expect(page.getByText('not executed', { exact: true })).toBeVisible();
  await page.getByRole('tab', { name: 'Verify', exact: true }).click();
  await expect(page.locator('.verification-card')).toContainText('proposed');
  await page.goBack();
  await expect(page.getByRole('tab', { name: /Reproduce/ })).toHaveAttribute('data-state', 'active');
  await page.goForward();
  await expect(page.getByRole('tab', { name: 'Verify', exact: true })).toHaveAttribute('data-state', 'active');
  await page.goto(deepLink);
  await expect(page.getByRole('heading', { level: 1 })).toHaveText('External order callback requires deployment evidence');
  await page.getByRole('navigation').getByRole('button', { name: 'Assessment', exact: true }).click();
  await page.getByRole('tab', { name: 'Evidence', exact: true }).click();
  await page.getByRole('button', { name: 'Report Markdown', exact: true }).click();
  const dialog = page.getByRole('dialog');
  await expect(dialog).toContainText('Synthetic assessment');
  await expect(dialog.locator('img, script, a[href^="https:"]')).toHaveCount(0);
  expect(await page.evaluate(() => (window as Window & { STAKE_INJECTED?: boolean }).STAKE_INJECTED)).toBeUndefined();
  await page.keyboard.press('Escape');
  await expect(dialog).not.toBeVisible();
  await page.goto('/?view=findings&finding=missing');
  await expect(page.getByRole('heading', { name: 'Finding unavailable' })).toBeVisible();
  await page.goto('/?view=findings&run=missing');
  await expect(page.getByRole('heading', { name: 'Assessment unavailable' })).toBeVisible();
  expect(external).toEqual([]);
  expect(errors).toEqual([]);
});

test('historical navigation identifies the original execution inside Advantage context', async ({ page }) => {
  await page.goto('/?view=findings&run=advantage-fixture&status=historical');
  await expect(page.getByText('3 matching findings', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Open F-001', exact: true }).click();
  const banner = page.locator('.finding-detail .info-banner');
  await expect(banner).toContainText('Historical baseline context for advantage-fixture');
  await expect(banner).toContainText('Owning execution: audit-fixture');
  await expect(page.getByRole('button', { name: /^Assessment context/ })).toHaveAttribute('aria-expanded', 'false');
  await page.getByRole('button', { name: /^Assessment context/ }).click();
  await expect(page.locator('.finding-header').getByText('audit-fixture', { exact: true })).toBeVisible();
});

test('cited-code navigation and remediation retain the finding and repair identity', async ({ page }) => {
  await page.goto('/?view=code&run=audit-fixture');
  await expect(page.getByRole('region', { name: 'Cited code map' })).toBeVisible();
  await page.locator('.code-file-button').first().click();
  await expect(page.locator('.code-map-detail')).toContainText('storefront/src/orders.ts');
  await expect(page.locator('.code-map-detail')).toContainText('Proposed repair location');
  await page.locator('.code-location-list').getByRole('button', { name: 'Line 42', exact: true }).first().click();
  await expect(page.getByRole('dialog')).toContainText('source');
  await expect(page.getByRole('dialog')).not.toContainText('This reference is not registered');
  await page.keyboard.press('Escape');
  await page.locator('.code-related-findings button').first().click();
  await expect(page.locator('.finding-detail')).toBeVisible();
  await page.getByRole('navigation').getByRole('button', { name: 'Remediation', exact: true }).click();
  await expect(page.locator('.repair-row')).toHaveCount(3);
  await page.getByRole('button', { name: 'Review repair' }).first().click();
  await expect(page.getByRole('tab', { name: /Repair/ })).toHaveAttribute('data-state', 'active');
  await expect(page.locator('.repair-implementation-card[data-repair-id="action-1"]')).toBeVisible();
  await expect(page.getByRole('region', { name: 'Attack explorer', exact: true })).toHaveCount(0);
  await page.getByRole('tab', { name: 'Attack map', exact: true }).click();
  await expect(page.getByLabel('Show proposed repair', { exact: true })).toHaveValue('action-1');
  await expect(page.locator('.graph-evidence-node.repair-highlight')).toHaveCount(2);
});

test('narrow layout, themes, reduced motion and keyboard navigation remain usable', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.goto('/');
  await page.keyboard.press('Tab');
  await expect(page.getByRole('link', { name: 'Skip to content' })).toBeFocused();
  await page.keyboard.press('Enter');
  await expect(page.locator('#main')).toBeFocused();
  await page.getByRole('button', { name: 'Toggle navigation' }).click();
  await page.getByRole('navigation').getByRole('button', { name: 'Findings' }).click();
  await expect(page.getByRole('heading', { name: 'Findings, in context.' })).toBeVisible();
  await page.getByLabel('Search findings').fill('no-such-synthetic-finding');
  await expect(page.getByRole('heading', { name: 'No matching findings' })).toBeVisible();
  await page.getByRole('button', { name: 'Reset filters', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Open F-001', exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Use dark theme' }).click();
  await expect(page.locator('html')).toHaveClass('dark');
  await page.reload();
  await expect(page.locator('html')).toHaveClass('dark');
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await page.screenshot({ path: '/private/tmp/stake-narrow.png', fullPage: true });
  await page.route('**/api/findings/*', async route => {
    const response = await route.fetch();
    const finding = await response.json();
    finding.raw.impact_limits = ['Synthetic long scope constraint ' + 'recorded '.repeat(100)];
    finding.raw.root_causes[0].file = 'storefront/' + 'nested-module/'.repeat(20) + 'orders.ts';
    await route.fulfill({ response, json: finding });
  });
  await page.getByRole('button', { name: 'Open F-001', exact: true }).click();
  await expect(page.locator('.finding-detail')).toBeVisible();
  await page.getByRole('button', { name: 'Impact and limits', exact: true }).click();
  await expect(page.locator('.finding-detail')).toContainText('Synthetic long scope constraint');
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
});

test('large legacy publication with a failed second input preserves complete rows, detail and bytes', async ({ page }) => {
  const root = await mkdtemp(join(tmpdir(), 'stake-large-browser-'));
  const records = Array.from({ length: 145 }, (_, i) => makeFinding({ id: `F-${String(i + 1).padStart(3, '0')}`, title: `Synthetic order boundary ${String(i + 1).padStart(3, '0')}`, impact: i === 144 ? 'Long accepted detail. '.repeat(1200) + 'COMPLETE_DOSSIER_END' : 'Recorded synthetic scope.' }));
  const bundle = await writeBundle(join(root, 'relocated bundle'), { legacy: true, findings: records, reportOverrides: { hardening_notes: ['context '.repeat(2_200_000)] } });
  await rm(join(bundle.root, 'sast'), { recursive: true });
  const reportPath = join(bundle.root, 'report/security-report.json');
  const before = createHash('sha256').update(await readFile(reportPath)).digest('hex');
  expect((await stat(reportPath)).size).toBeGreaterThan(16 * 1024 * 1024);
  const instance = await createStakeServer({ runs: [bundle.root, join(root, 'missing')], staticRoot: resolve('dist'), configDir: join(root, 'settings') });
  try {
    await page.goto(instance.url + '/?view=findings');
    await expect(page.getByRole('alert')).toContainText('Input unavailable');
    await expect(page.getByText('145 matching findings', { exact: true })).toBeVisible();
    for (let i = 1; i < 13; i++) await page.getByRole('button', { name: 'Next page', exact: true }).click();
    await expect(page.getByText('Page 13 of 13')).toBeVisible();
    await page.getByRole('button', { name: 'Open F-145', exact: true }).click();
    await page.getByRole('button', { name: 'Impact and limits', exact: true }).click();
    await expect(page.locator('.finding-detail')).toContainText('COMPLETE_DOSSIER_END');
    await page.getByRole('tab', { name: 'Evidence', exact: true }).click();
    await page.getByText('Contributors and complete accepted record', { exact: true }).click();
    await expect(page.locator('.finding-detail details[open]')).toContainText('COMPLETE_DOSSIER_END');
    expect(createHash('sha256').update(await readFile(reportPath)).digest('hex')).toBe(before);
  } finally { await instance.close(); await rm(root, { recursive: true, force: true }); }
});
