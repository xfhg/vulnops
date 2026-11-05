import { expect, test } from '@playwright/test';

test('dense entrypoint maps start at a ranked route and keep the complete atlas and search reachable', async ({ page }) => {
  await page.route('**/api/findings?*', async route => {
    const response = await route.fetch();
    const payload = await response.json();
    const finding = payload.items.find((item: { id: string }) => item.id === 'F-001');
    finding.raw.affected_components[0].entrypoints = Array.from({ length: 30 }, (_, i) => `POST /synthetic/${i + 1}`);
    await route.fulfill({ response, json: payload });
  });
  await page.goto('/?view=attacks');
  await expect(page.locator('.ep-canvas')).toHaveAttribute('data-layout-status', 'ready');
  await expect(page.locator('.ep-node-entrypoint')).toHaveCount(1);
  await expect(page.locator('.ep-auto-focus-note')).toContainText('highest-ranked of 32 entrypoints');
  await expect(page.getByLabel('Focus entrypoint', { exact: true })).toHaveValue('auto');
  await page.getByLabel('Focus entrypoint', { exact: true }).selectOption('');
  await expect(page.locator('.ep-canvas')).toHaveAttribute('data-layout-status', 'ready');
  await expect(page.locator('.ep-node-entrypoint')).toHaveCount(32);
  await expect(page.locator('.ep-canvas .react-flow__edge')).toHaveCount(33);
  await page.getByLabel('Focus entrypoint', { exact: true }).selectOption('auto');
  await page.getByLabel('Find entrypoint or finding', { exact: true }).fill('POST /synthetic/7');
  await expect(page.locator('.ep-node-entrypoint')).toHaveCount(1);
  await expect(page.locator('.ep-node-entrypoint')).toContainText('POST /synthetic/7');
  await page.getByLabel('Find entrypoint or finding', { exact: true }).clear();
  await expect(page.locator('.ep-auto-focus-note')).toBeVisible();
  await expect(page.locator('.ep-node-entrypoint')).toContainText('2 findings');
});
