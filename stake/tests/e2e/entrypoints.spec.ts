import { expect, test, type Page } from '@playwright/test';

async function openOverview(page: Page) {
  await page.goto('/?view=attacks');
  await expect(page.getByRole('region', { name: 'Attack overview', exact: true })).toBeVisible();
  await expect(page.getByRole('heading', { level: 1, name: 'Follow the entry. Understand the chain.', exact: true })).toBeVisible();
  await expect(page.locator('.ep-canvas')).toHaveAttribute('data-layout-status', 'ready');
}

test('entrypoint overview associates shared exact labels within each owning scope', async ({ page }) => {
  await openOverview(page);
  await expect(page.locator('.ep-node-entrypoint')).toHaveCount(2);
  await expect(page.locator('.ep-node-finding')).toHaveCount(4);
  await expect(page.locator('.ep-canvas .react-flow__edge')).toHaveCount(4);
  await expect(page.locator('.ep-overview-stats')).toContainText('1shared entrypoint');
  const shared = page.locator('.react-flow__node').filter({ has: page.locator('.ep-node-entrypoint', { hasText: '3 findings' }) });
  await shared.click();
  const inspector = page.getByRole('complementary', { name: 'Entrypoint evidence inspector' });
  await expect(inspector.getByRole('heading', { name: 'POST /orders/approve', exact: true })).toBeVisible();
  await expect(inspector.locator('.ep-finding-link')).toHaveCount(3);
  await expect(inspector.locator('.ep-scope')).toContainText('audit-fixture');
  await expect(inspector.locator('.ep-scope')).not.toContainText('advantage-fixture');
  await expect(inspector).toContainText('does not establish an attack chain');
  const selection = new URL(page.url()).searchParams.get('entrySelected');
  expect(selection).toBeTruthy();
  await page.reload();
  await expect(page.locator('.ep-canvas')).toHaveAttribute('data-layout-status', 'ready');
  await expect(page.locator('.react-flow__node.selected .ep-node-entrypoint')).toContainText('3 findings');
  expect(new URL(page.url()).searchParams.get('entrySelected')).toBe(selection);
  await page.locator('.entrypoint-explorer').screenshot({ path: '/private/tmp/atstake-entrypoints.png' });
});

test('cluster focus and keyboard linear navigation preserve scope, evidence and finding handoff', async ({ page }) => {
  await openOverview(page);
  const option = page.getByLabel('Focus entrypoint', { exact: true }).locator('option').filter({ hasText: 'audit-fixture' }).first();
  const clusterId = await option.getAttribute('value');
  await page.getByLabel('Focus entrypoint', { exact: true }).selectOption(clusterId!);
  await expect(page.locator('.ep-node-entrypoint')).toHaveCount(1);
  await expect(page.locator('.ep-node-finding')).toHaveCount(3);
  await expect(page.locator('.ep-canvas .react-flow__edge')).toHaveCount(3);
  await page.getByRole('button', { name: 'Linear entrypoint view', exact: true }).focus();
  await page.keyboard.press('Enter');
  await expect(page.locator('.ep-linear-cluster')).toHaveCount(1);
  await page.locator('.ep-linear-heading').focus();
  await page.keyboard.press('Enter');
  expect(new URL(page.url()).searchParams.get('entrySelected')).toBe(clusterId);
  const inspector = page.getByRole('complementary', { name: 'Entrypoint evidence inspector' });
  await expect(inspector.locator('.ep-finding-link')).toHaveCount(3);
  await inspector.getByRole('button', { name: 'sast/verified-findings.json:C-001', exact: true }).first().focus();
  await page.keyboard.press('Enter');
  await expect(page.getByRole('dialog')).toContainText('Synthetic canonical support.');
  await page.keyboard.press('Escape');
  await page.getByRole('button', { name: 'Open finding F-001', exact: true }).click();
  await expect(page.getByRole('region', { name: 'Attack explorer', exact: true })).toBeVisible();
  expect(new URL(page.url()).searchParams.get('view')).toBe('attacks');
  await page.getByRole('button', { name: 'Back to attack overview', exact: true }).click();
  await expect(page.getByRole('region', { name: 'Attack overview', exact: true })).toBeVisible();
  expect(new URL(page.url()).searchParams.get('entrySelected')).toBe(clusterId);
});

test('all composed attacks render independent qualified chains and open the selected full composition', async ({ page }) => {
  await page.route('**/api/findings?*', async route => {
    const response = await route.fetch();
    const payload = await response.json();
    const first = payload.items.find((finding: { id: string }) => finding.id === 'F-001');
    const second = payload.items.find((finding: { id: string }) => finding.id === 'F-060');
    second.kind = second.raw.finding_kind = 'chain';
    second.raw.primitive_steps = structuredClone(first.raw.primitive_steps);
    second.raw.transitions = structuredClone(first.raw.transitions);
    second.raw.transitions[0].resolution = { outcome: 'locally_unresolved', missing_fact: 'The downstream consumer identity still requires deployment evidence.' };
    const withoutGeometry = payload.items.find((finding: { id: string }) => finding.id === 'F-003');
    withoutGeometry.kind = withoutGeometry.raw.finding_kind = 'chain';
    await route.fulfill({ response, json: payload });
  });
  await openOverview(page);
  await page.getByRole('tab', { name: /^Composed attacks/ }).click();
  await expect(page.locator('.ep-chain-card')).toHaveCount(3);
  const all = page.locator('.ep-all-compositions');
  await expect(all.locator('.ep-canvas')).toHaveAttribute('data-layout-status', 'ready');
  await expect(all.locator('.react-flow__node-overview')).toHaveCount(5);
  await expect(all.locator('.react-flow__node-context')).toHaveCount(3);
  await expect(all.locator('.react-flow__edge')).toHaveCount(2);
  await expect(all).toContainText('4 primitives · 2 recorded edges · 1 without primitive details');
  const nodeIds = await all.locator('.react-flow__node-overview').evaluateAll(nodes => nodes.map(node => node.getAttribute('data-id')));
  expect(new Set(nodeIds).size).toBe(5);
  await all.locator('.react-flow__node-overview').filter({ has: page.locator('.ep-node-title', { hasText: 'Approval identity' }) }).filter({ hasText: 'F-060' }).focus();
  await page.keyboard.press('Enter');
  const selected = page.getByRole('region', { name: 'Selected composed attack', exact: true });
  await expect(selected).toContainText('F-060 · advantage-fixture');
  await expect(selected.getByRole('complementary', { name: 'Selected evidence inspector' })).toContainText('Browser to account identity');
  const primitiveSelection = new URL(page.url()).searchParams.get('entrySelected');
  await page.getByRole('button', { name: 'Linear compositions view', exact: true }).click();
  await expect(page.locator('.ep-composition-list>section')).toHaveCount(3);
  expect(new URL(page.url()).searchParams.get('entrySelected')).toBe(primitiveSelection);
  await page.locator('.ep-composition-list').getByRole('button', { name: /P-2.*locally unresolved.*Inspect recorded transition/ }).focus();
  await page.keyboard.press('Enter');
  await expect(selected.getByRole('complementary', { name: 'Selected evidence inspector' })).toContainText('The downstream consumer identity still requires deployment evidence.');
  await page.getByRole('button', { name: 'Show all compositions graph', exact: true }).click();
  await expect(all.locator('.react-flow__edge.selected')).toHaveCount(1);
  await page.locator('.ep-composed').screenshot({ path: '/private/tmp/atstake-compositions.png' });
  await selected.getByRole('button', { name: 'Open full finding', exact: true }).click();
  expect(new URL(page.url()).searchParams.get('mode')).toBe('composition');
  expect(new URL(page.url()).searchParams.get('view')).toBe('attacks');
  await expect(page.getByRole('region', { name: 'Attack explorer', exact: true })).toBeVisible();
});

test('unassigned findings are counted, grouped and fully reachable without fabricated route labels', async ({ page }) => {
  await page.route('**/api/findings?*', async route => {
    const response = await route.fetch();
    const payload = await response.json();
    for (const finding of payload.items) if (['F-002', 'F-003'].includes(finding.id)) finding.raw.affected_components[0].entrypoints = [];
    await route.fulfill({ response, json: payload });
  });
  await openOverview(page);
  await expect(page.locator('.ep-overview-stats')).toContainText('2unassigned findings');
  await expect(page.locator('.ep-canvas .react-flow__edge')).toHaveCount(2);
  const unassigned = page.locator('.react-flow__node-overview').filter({ hasText: 'Unassigned entrypoints' });
  await expect(unassigned).toHaveCount(1);
  await unassigned.focus();
  await page.keyboard.press('Enter');
  await expect(page.locator('.ep-linear-finding')).toHaveCount(2);
  await expect(page.locator('.ep-linear-finding').filter({ hasText: 'F-002' })).toHaveCount(1);
  await expect(page.locator('.ep-linear-finding').filter({ hasText: 'F-003' })).toHaveCount(1);
  await expect(page.getByRole('complementary', { name: 'Entrypoint evidence inspector' }).locator('.ep-finding-link')).toHaveCount(2);
  await page.getByRole('button', { name: 'Open finding F-002', exact: true }).click();
  await expect(page.locator('.finding-detail h1')).toHaveText('External order callback requires deployment evidence');
});

test('overview remains usable on a narrow viewport with reduced motion', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await openOverview(page);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBe(true);
  await page.getByRole('button', { name: 'Linear entrypoint view', exact: true }).click();
  await page.locator('.ep-linear-heading').first().click();
  await expect(page.getByRole('complementary', { name: 'Entrypoint evidence inspector' }).getByRole('heading', { name: 'POST /orders/approve', exact: true })).toBeVisible();
  await page.screenshot({ path: '/private/tmp/atstake-entrypoints-mobile.png', fullPage: true });
});
