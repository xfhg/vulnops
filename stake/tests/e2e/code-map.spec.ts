import { expect, test, type Page } from '@playwright/test';

async function openCodeMap(page: Page, query = 'run=audit-fixture') {
  await page.goto('/?view=code&' + query);
  await expect(page.getByRole('region', { name: 'Cited code map', exact: true })).toBeVisible();
  await expect(page.locator('.cg-node-location').first()).toBeVisible();
  await expect(page.getByRole('button', { name: 'Fit View', exact: true })).toBeEnabled();
}

test('code relationships retain finding and repair provenance and open the selected range', async ({ page }) => {
  // Browser-only synthetic alternate citation: it sorts before the real range.
  // The selected range must still open line 42, never unrelated support line 10.
  await page.route('**/api/findings?*', async route => {
    const response = await route.fetch();
    const payload = await response.json();
    const finding = payload.items.find((item: { id: string; runId: string }) => item.id === 'F-001' && item.runId === 'audit-fixture');
    if (finding) finding.raw.remediation.actions[0].evidence_refs.unshift('storefront/src/orders.ts:10');
    await route.fulfill({ response, json: payload });
  });
  await openCodeMap(page);
  await expect(page.locator('.cg-node-finding')).toHaveCount(3);
  await expect(page.locator('.cg-node-repair')).toHaveCount(3);
  await expect(page.locator('.cg-source-group')).toContainText('orders.ts');
  await expect(page.locator('.cg-graph-heading')).toContainText('not call or execution flow');
  await expect(page.locator('.cg-canvas .react-flow__edge-text')).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Open citation', exact: true })).toHaveCount(0);
  expect(await page.locator('.cg-canvas .cg-edge-incident').count()).toBeGreaterThan(0);
  expect(await page.locator('.cg-canvas .cg-edge-background').count()).toBeGreaterThan(0);
  const range = page.locator('.cg-canvas .react-flow__node-codeEntity').filter({ has: page.locator('.cg-node-location') }).filter({ hasText: 'Line 42' });
  await range.focus();
  await page.keyboard.press('Enter');
  const referenceRequest = page.waitForRequest(request => new URL(request.url()).pathname === '/api/reference');
  await page.getByRole('button', { name: 'Open citation', exact: true }).click();
  const reference = new URL((await referenceRequest).url());
  expect(JSON.parse(reference.searchParams.get('ref')!)).toBe('storefront/src/orders.ts:42');
  expect(reference.searchParams.get('runId')).toBe('audit-fixture');
  await expect(page.getByRole('dialog')).not.toContainText('This reference is not registered');
  await page.keyboard.press('Escape');
  const repair = page.locator('.cg-canvas .react-flow__node-codeEntity').filter({ has: page.locator('.cg-node-repair') }).filter({ hasText: 'F-001' });
  await repair.focus();
  await page.keyboard.press('Enter');
  const inspector = page.getByRole('region', { name: 'Code connection details' });
  await expect(inspector).toContainText('step-1');
  await expect(inspector).toContainText('step-2');
  await expect(inspector).toContainText('Preserve identity and object scope at both boundaries.');
  await expect(inspector).toContainText('does not establish that a change was applied or verified');
  await page.locator('.cg-connection-list > summary').click();
  await page.locator('.cg-connection-list button').filter({ hasText: 'Proposed change here' }).filter({ hasText: 'F-001' }).focus();
  await page.keyboard.press('Enter');
  await expect(inspector).toContainText('explicitly lists this coordinate');
  await expect(page.locator('.cg-canvas .react-flow__edge.selected')).toHaveCount(1);
  await expect(page.locator('.cg-canvas .react-flow__edge-text')).toHaveCount(1);
  await page.getByRole('button', { name: 'Focus selected nodes', exact: true }).click();
  await page.getByRole('button', { name: 'Fit View', exact: true }).click();
  await page.getByRole('button', { name: 'Previous cited ranges', exact: true }).click();
  await expect(page.locator('.cg-window-controls')).toContainText('Ranges 1–5');
  await expect(page.locator('.cg-node-location')).toHaveCount(5);
  await page.getByRole('button', { name: 'Locations', exact: true }).click();
  await expect(page.locator('.cg-canvas')).toHaveCount(0);
  await expect(page.locator('.code-location-list')).toContainText('Line 42');
  await expect(page.locator('.code-related-findings button')).toHaveCount(3);
});

test('code file selection preserves owning scope and invalid deep links remain unavailable', async ({ page }) => {
  await openCodeMap(page, '');
  await page.locator('.code-file-button').filter({ hasText: 'advantage-fixture' }).click();
  await expect(page.locator('.cg-node-finding')).toHaveCount(1);
  await expect(page.locator('.cg-node-finding')).toContainText('F-060');
  await expect(page.locator('.code-scope')).toContainText('advantage-fixture');
  const selection = new URL(page.url()).searchParams.get('location');
  expect(selection).toBeTruthy();
  await page.reload();
  await expect(page.locator('.cg-node-finding')).toContainText('F-060');
  expect(new URL(page.url()).searchParams.get('location')).toBe(selection);
  await page.goto('/?view=code&location=unavailable-file-identity');
  await expect(page.getByRole('heading', { name: 'Selected file unavailable', exact: true })).toBeVisible();
  await expect(page.locator('.cg-canvas')).toHaveCount(0);
});

for (const theme of ['light', 'dark'] as const) for (const narrow of [false, true]) {
  test(`code relationship graph remains navigable in ${theme} ${narrow ? 'narrow' : 'desktop'} view`, async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', error => errors.push(error.message));
    await page.setViewportSize({ width: narrow ? 390 : 1440, height: narrow ? 844 : 1000 });
    await page.emulateMedia({ reducedMotion: 'reduce', colorScheme: theme });
    await page.addInitScript(value => localStorage.setItem('stake-theme', value), theme);
    await openCodeMap(page);
    if (narrow) {
      await expect(page.locator('.cg-canvas')).toHaveAttribute('data-framing', 'range');
      const selectedRange = await page.locator('.cg-node-location.cg-node-selected').boundingBox();
      expect(selectedRange!.width).toBeGreaterThan(180);
    }
    const navigation = page.getByRole('group', { name: 'Code map navigation', exact: true });
    await expect(navigation).toBeVisible();
    await navigation.getByRole('button', { name: 'Zoom In', exact: true }).focus();
    await page.keyboard.press('Enter');
    await page.keyboard.press('ArrowRight');
    await page.keyboard.press('Home');
    await expect(navigation.getByRole('button', { name: 'Focus selected nodes', exact: true })).toBeEnabled();
    const showMap = navigation.getByRole('button', { name: 'Show minimap', exact: true });
    if (await showMap.count()) await showMap.click();
    await expect(page.locator('.cg-canvas .react-flow__minimap')).toBeVisible();
    if (narrow) {
      await navigation.getByRole('button', { name: 'Hide minimap', exact: true }).click();
      await navigation.getByRole('button', { name: 'Focus selected nodes', exact: true }).click();
    }
    const bounds = await page.locator('.cg-canvas').boundingBox();
    expect(bounds!.width).toBeLessThanOrEqual(narrow ? 390 : 1440);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
    await page.locator('.cg-workspace').screenshot({ path: `/private/tmp/atstake-code-map-${theme}-${narrow ? 'narrow' : 'desktop'}.png` });
    expect(errors).toEqual([]);
  });
}
