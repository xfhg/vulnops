import { expect, test, type Locator, type Page } from '@playwright/test';

async function openOverview(page: Page) {
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.goto('/?view=attacks');
  await expect(page.getByRole('region', { name: 'Attack overview', exact: true })).toBeVisible();
  const canvas = page.locator('.ep-canvas');
  await expect(canvas).toHaveAttribute('data-layout-status', 'ready');
  await expect(canvas.locator('.react-flow__node-overview')).toHaveCount(6);
  await expect(canvas.locator('.react-flow__node-context')).toHaveCount(2);
  await expect(canvas.getByRole('button', { name: 'Fit View', exact: true })).toBeEnabled();
  return canvas;
}

function records(canvas: Locator) {
  return canvas.locator('.react-flow__node-overview');
}

function singleFindingRoute(page: Page, canvas: Locator) {
  return records(canvas).filter({ has: page.locator('.ep-node-entrypoint') })
    .filter({ has: page.getByText('1 finding', { exact: true }) });
}

async function selectWithKeyboard(page: Page, node: Locator) {
  const id = await node.getAttribute('data-id');
  expect(id).toBeTruthy();
  await node.focus();
  await page.keyboard.press('Enter');
  await expect(node).toHaveClass(/selected/);
  expect(new URL(page.url()).searchParams.get('entrySelected')).toBe(id);
  return id;
}

async function viewport(canvas: Locator) {
  return canvas.locator('.react-flow__viewport').evaluate(element => {
    const matrix = new DOMMatrixReadOnly(getComputedStyle(element).transform);
    return { x: matrix.e, y: matrix.f, zoom: matrix.a };
  });
}

async function graphIdentity(canvas: Locator) {
  return {
    nodes: await records(canvas).evaluateAll(nodes => nodes.map(node => node.getAttribute('data-id')).sort()),
    edges: await canvas.locator('.react-flow__edge').evaluateAll(edges => edges.map(edge => edge.getAttribute('data-id')).sort()),
  };
}

test('keyboard selection focuses recorded neighbors without changing graph records and opens the owning finding', async ({ page }) => {
  const canvas = await openOverview(page);
  const original = await graphIdentity(canvas);
  expect(original.edges).toHaveLength(4);
  const route = singleFindingRoute(page, canvas);
  await expect(route.locator('.ep-node-title')).toHaveText('POST /orders/approve');
  await selectWithKeyboard(page, route);
  const inspector = page.getByRole('complementary', { name: 'Entrypoint evidence inspector' });
  await expect(inspector.locator('.ep-scope')).toContainText('advantage-fixture');
  await expect(inspector.locator('.ep-finding-link')).toHaveCount(1);

  const highlight = canvas.getByRole('button', { name: /^Highlight connections/ });
  await expect(highlight).toHaveAttribute('aria-pressed', 'false');
  await highlight.click();
  await expect(canvas.getByRole('button', { name: /^Show all context/ })).toHaveAttribute('aria-pressed', 'true');
  await expect(records(canvas).filter({ has: page.locator('.ep-node-entrypoint') }).filter({ hasText: '3 findings' })).toHaveClass(/ep-context-muted/);
  await expect(canvas.locator('.react-flow__node-overview.ep-context-muted')).toHaveCount(4);
  expect(await graphIdentity(canvas)).toEqual(original);
  await canvas.getByRole('button', { name: /^Show all context/ }).click();
  await expect(canvas.locator('.react-flow__node-overview.ep-context-muted')).toHaveCount(0);

  const fullZoom = (await viewport(canvas)).zoom;
  await canvas.locator('.ep-node-toolbar').getByRole('button', { name: 'Focus connections', exact: true }).click();
  await expect.poll(async () => (await viewport(canvas)).zoom).toBeGreaterThan(fullZoom + 0.01);
  await expect(canvas.locator('.react-flow__node-overview.ep-context-muted')).toHaveCount(4);
  expect(await graphIdentity(canvas)).toEqual(original);
  await canvas.getByRole('button', { name: 'Fit View', exact: true }).click();
  await expect.poll(async () => Math.abs((await viewport(canvas)).zoom - fullZoom)).toBeLessThan(0.001);
  await canvas.getByRole('button', { name: /^Show all context/ }).click();

  const finding = records(canvas).filter({ has: page.locator('.ep-node-finding') }).filter({ hasText: 'F-060' });
  await selectWithKeyboard(page, finding);
  await canvas.locator('.ep-node-toolbar').getByRole('button', { name: 'Open finding', exact: true }).focus();
  await page.keyboard.press('Enter');
  await expect(page.locator('.finding-detail h1')).toHaveText('Order approval reaches the fulfillment consumer');
  expect(JSON.parse(new URL(page.url()).searchParams.get('finding')!)).toEqual(['finding', 'advantage-fixture', 'F-060']);
});

test('navigator zoom, selected focus, keyboard pan and minimap preserve all recorded graph identities', async ({ page }) => {
  const canvas = await openOverview(page);
  const navigator = canvas.getByRole('group', { name: 'Entrypoint findings graph', exact: true });
  const identity = await graphIdentity(canvas);
  await expect(navigator.locator('.graph-navigator-counts')).toHaveText('6 nodes · 4 links');
  await expect(navigator.getByRole('button', { name: 'Focus selected nodes', exact: true })).toBeDisabled();
  await expect(canvas.locator('.graph-navigator-minimap')).toBeVisible();
  // Display-only parent groups provide context, never opaque minimap records.
  await expect.poll(() => canvas.locator('.react-flow__minimap-node').evaluateAll(nodes => nodes.filter(node => getComputedStyle(node).fill === 'rgba(0, 0, 0, 0)').length)).toBe(2);

  const initial = await viewport(canvas);
  await navigator.getByRole('button', { name: 'Zoom In', exact: true }).focus();
  await page.keyboard.press('Enter');
  await expect.poll(async () => (await viewport(canvas)).zoom).toBeGreaterThan(initial.zoom);
  await expect(navigator.getByLabel('Zoom level', { exact: true })).toHaveText(`${Math.round((await viewport(canvas)).zoom * 100)}%`);
  await navigator.getByRole('button', { name: 'Zoom Out', exact: true }).click();
  await expect.poll(async () => Math.abs((await viewport(canvas)).zoom - initial.zoom)).toBeLessThan(0.001);
  await navigator.getByRole('button', { name: 'Fit View', exact: true }).focus();
  const beforePan = await viewport(canvas);
  await page.keyboard.press('ArrowRight');
  await expect.poll(async () => (await viewport(canvas)).x).toBeCloseTo(beforePan.x - 48, 1);
  expect((await viewport(canvas)).zoom).toBeCloseTo(beforePan.zoom, 4);
  await page.keyboard.press('Home');
  await expect.poll(async () => Math.abs((await viewport(canvas)).x - initial.x)).toBeLessThan(0.1);
  await expect.poll(async () => Math.abs((await viewport(canvas)).y - initial.y)).toBeLessThan(0.1);

  await selectWithKeyboard(page, singleFindingRoute(page, canvas));
  await navigator.getByRole('button', { name: 'Focus selected nodes', exact: true }).click();
  await expect.poll(async () => (await viewport(canvas)).zoom).toBeGreaterThan(initial.zoom + 0.01);
  await navigator.getByRole('button', { name: 'Hide minimap', exact: true }).click();
  await expect(canvas.locator('.graph-navigator-minimap')).toHaveCount(0);
  await navigator.getByRole('button', { name: 'Show minimap', exact: true }).focus();
  await page.keyboard.press('Enter');
  await expect(canvas.getByRole('img', { name: /Entrypoint findings graph: minimap/ })).toBeVisible();
  expect(await graphIdentity(canvas)).toEqual(identity);
});

for (const theme of ['light', 'dark'] as const) test(`narrow ${theme} graph keeps navigation reachable without horizontal overflow`, async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.addInitScript(value => localStorage.setItem('stake-theme', value), theme);
  const canvas = await openOverview(page);
  if (theme === 'dark') await expect(page.locator('html')).toHaveClass('dark');
  const navigator = canvas.getByRole('group', { name: 'Entrypoint findings graph', exact: true });
  await expect(canvas.locator('.graph-navigator-minimap')).toHaveCount(0);
  await navigator.scrollIntoViewIfNeeded();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBe(true);
  await expect.poll(() => navigator.evaluate(element => {
    const frame = element.closest('.ep-canvas')!.getBoundingClientRect();
    return [...element.querySelectorAll('button')].every(button => {
      const rect = button.getBoundingClientRect();
      return rect.width >= 34 && rect.height >= 34 && rect.left >= frame.left && rect.right <= frame.right && rect.bottom <= frame.bottom;
    });
  })).toBe(true);
  await selectWithKeyboard(page, singleFindingRoute(page, canvas));
  await navigator.getByRole('button', { name: 'Focus selected nodes', exact: true }).focus();
  await page.keyboard.press('Enter');
  await navigator.getByRole('button', { name: 'Show minimap', exact: true }).focus();
  await page.keyboard.press('Enter');
  await expect(canvas.locator('.graph-navigator-minimap')).toBeVisible();
  await expect.poll(() => canvas.evaluate(element => {
    const frame = element.getBoundingClientRect();
    const controls = element.querySelector('.graph-navigator-controls')!.getBoundingClientRect();
    const map = element.querySelector('.graph-navigator-minimap')!.getBoundingClientRect();
    return map.left >= frame.left && map.right <= frame.right && map.top >= frame.top && map.bottom <= controls.top;
  })).toBe(true);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBe(true);
  await navigator.getByRole('button', { name: 'Fit View', exact: true }).focus();
  await page.keyboard.press('Enter');
  await expect(records(canvas)).toHaveCount(6);
  await expect(canvas.locator('.react-flow__edge')).toHaveCount(4);
  await canvas.screenshot({ path: `/private/tmp/atstake-graph-navigation-${theme}-mobile.png` });
});
