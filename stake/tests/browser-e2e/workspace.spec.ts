import { expect, test, type Page } from '@playwright/test';
import { makeBrowserZip as zip } from '../fixtures/browser-zip';

const key = JSON.stringify(['finding', 'audit-fixture', 'F-001']);
async function load(page: Page, payload = zip()) {
  await page.getByRole('button', { name: 'Settings', exact: true }).click();
  await page.getByLabel('Assessment ZIP', { exact: true }).setInputFiles(await payload);
  await page.getByRole('button', { name: /^(Load|Replace) assessment$/, exact: true }).last().click();
}
const route = (page: Page) => new URLSearchParams(new URL(page.url()).hash.slice(2));

test('black first visit imports, visits six views, restores and removes without API traffic', async ({ page }) => {
  const requests: string[] = [], errors: string[] = [];
  page.on('request', req => requests.push(req.url() + JSON.stringify(req.headers()) + (req.postData() ?? '')));
  page.on('pageerror', error => errors.push(error.message));
  await page.goto('/');
  await expect(page.locator('.browser-empty-shell')).toHaveCSS('background-color', 'rgb(0, 0, 0)');
  await expect(page.getByRole('navigation', { name: 'Main navigation' })).toHaveCount(0);
  await load(page);
  await expect(page.getByRole('heading', { name: 'Assessment overview', exact: true })).toBeVisible();
  await expect(page.getByRole('dialog')).toHaveCount(0);
  for (const name of ['Findings', 'Attack explorer', 'Code map', 'Remediation', 'Assessment', 'Overview']) {
    await page.getByRole('navigation', { name: 'Main navigation' }).getByRole('button', { name: new RegExp('^' + name) }).click();
    await expect(page.getByRole('status').filter({ hasText: /Loading|Mapping|Indexing/ })).toHaveCount(0);
    if (name === 'Attack explorer') await expect(page.locator('.ep-canvas')).toHaveAttribute('data-layout-status', 'ready');
    await expect(page.locator('main')).not.toContainText(/unavailable|could not be loaded/i);
  }
  await page.reload(); await expect(page.getByRole('heading', { name: 'Assessment overview', exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Settings', exact: true }).click();
  await expect(page.getByRole('region', { name: 'Current archive' })).toContainText('synthetic.zip');
  await page.getByRole('button', { name: 'Remove local assessment', exact: true }).click();
  await expect(page.locator('.browser-empty-shell')).toBeVisible(); await page.reload();
  await expect(page.locator('.browser-empty-shell')).toBeVisible();
  expect(requests.some(url => /\/api\/|audit-fixture|SYNTHETIC_|synthetic.zip|F-001/.test(url))).toBe(false);
  expect(errors).toEqual([]);
});

test('initial finding link reaches exact repair instructions and retains evidence, examples and history', async ({ page }) => {
  await page.goto('/#?' + new URLSearchParams({ view: 'findings', finding: key, panel: 'repair', repair: 'action-1' }));
  await load(page);
  const card = page.locator('.repair-implementation-card[data-repair-id="action-1"]');
  await expect(card).toBeVisible();
  expect(route(page).get('finding')).toBe(key); expect(new URL(page.url()).search).toBe('');
  const location = card.getByRole('region', { name: 'Repair location orders.ts:42', exact: true });
  await expect(location).toContainText('SYNTHETIC_REPAIR_SOURCE');
  await expect(card).toContainText('Bind the session to its initiating account');
  await page.getByRole('link', { name: 'Skip to content' }).focus(); await page.keyboard.press('Enter');
  expect(route(page).get('finding')).toBe(key);
  await page.reload(); await expect(card).toBeVisible();
  await card.getByRole('button', { name: /^Read reproduction step step-2:/ }).click();
  await expect(page.getByRole('region', { name: 'Request approval of another synthetic account’s order.', exact: true })).toBeFocused();
  await page.goBack(); await expect(card).toBeVisible();
  await card.getByRole('button', { name: 'Open technical example example-1', exact: true }).click();
  await expect(page.getByRole('region', { name: 'Recorded technical example example-1', exact: true })).toContainText('SYNTHETIC_ORDER');
  await page.getByRole('tablist', { name: 'Finding detail', exact: true }).getByRole('tab', { name: 'Evidence', exact: true }).click();
  const evidence = page.getByRole('button', { name: 'sast/verified-findings.json:C-001', exact: true }).first();
  await evidence.click(); await expect(page.getByRole('dialog')).toContainText('SYNTHETIC_EVIDENCE_audit');
  await page.keyboard.press('Escape');
  await page.getByRole('tablist', { name: 'Finding detail', exact: true }).getByRole('tab', { name: /^Repair/ }).click();
  await card.getByRole('button', { name: 'Open repair map', exact: true }).click();
  await expect(page.locator('.rc-canvas')).toHaveAttribute('data-layout-status', 'ready');
  await page.reload(); await expect(page.locator('.rc-canvas')).toHaveAttribute('data-layout-status', 'ready');
  const workspace = page.getByRole('region', { name: 'Repair workspace', exact: true });
  const picker = workspace.getByRole('combobox', { name: 'Select repair map record', exact: true });
  const option = picker.locator('option').filter({ hasText: /^Proposed repair · action-1 ·/ });
  await picker.selectOption((await option.getAttribute('value'))!);
  await workspace.getByRole('region', { name: 'Repair record details', exact: true }).getByRole('button', { name: 'Open repair details', exact: true }).click();
  await page.getByRole('button', { name: 'Review verification checks', exact: true }).click();
  const verification = page.getByRole('region', { name: 'Fix verification', exact: true });
  await expect(verification).toContainText('The unauthorized approval is rejected without mutation.');
  await expect(verification).toContainText('The authorized approval succeeds.');
  await expect(verification).toContainText('proposed');
  await page.getByRole('tab', { name: 'Attack map', exact: true }).click();
  const alert = page.getByRole('region', { name: 'Proposed repair action-1', exact: true });
  await alert.getByRole('button', { name: 'Read implementation instructions for storefront/src/orders.ts:42 of action-1', exact: true }).click();
  await expect(location).toBeFocused();
  await expect(location).toContainText('SYNTHETIC_REPAIR_SOURCE');
  await expect(page.getByRole('dialog')).toHaveCount(0);
});

test('invalid replacement retains the saved pair, valid replacement resets route, and tabs reconcile removal', async ({ page, context }) => {
  await page.goto('/'); await load(page); await expect(page.getByRole('heading', { name: 'Assessment overview', exact: true })).toBeVisible();
  await load(page, zip({ broken: true }));
  await expect(page.getByRole('alert')).toContainText('report/security-report.md: Referenced artifact was not delivered.');
  await page.getByRole('button', { name: 'Close settings' }).click();
  await page.reload(); await expect(page.getByRole('heading', { name: 'Assessment overview', exact: true })).toBeVisible();
  const peer = await context.newPage(); await peer.goto('/'); await expect(peer.getByRole('heading', { name: 'Assessment overview', exact: true })).toBeVisible();
  await load(page, zip({ suffix: '-replacement' }));
  await expect(page.getByRole('dialog')).toHaveCount(0); expect(route(page).get('view')).toBe('overview');
  await page.getByRole('button', { name: 'Settings', exact: true }).click(); await page.getByRole('button', { name: 'Remove local assessment', exact: true }).click();
  await peer.bringToFront(); await expect(peer.locator('.browser-empty-shell')).toBeVisible();
});

test('a zero-finding pair is loaded data and narrow dark mode remains usable', async ({ page }) => {
  await page.addInitScript(() => localStorage.setItem('stake-theme', 'dark'));
  await page.setViewportSize({ width: 390, height: 844 }); await page.goto('/'); await load(page, zip({ zero: true }));
  await expect(page.locator('.browser-empty-shell')).toHaveCount(0);
  await expect(page.locator('html')).toHaveClass(/dark/);
  await page.getByRole('button', { name: 'Settings', exact: true }).click();
  await expect(page.getByRole('region', { name: 'Current archive' })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
});
