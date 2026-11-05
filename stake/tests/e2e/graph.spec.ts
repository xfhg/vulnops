import { expect, test, type Page } from '@playwright/test';

const firstAction = 'Present the unbound approval session.';
const secondAction = 'Request approval of another synthetic account’s order.';

async function openFinding(page: Page, id = 'F-001') {
  const response = await page.request.get('/api/workspace');
  expect(response.ok()).toBeTruthy();
  const workspace = await response.json();
  const finding = workspace.findings.find((entry: { id: string; runId: string }) => entry.id === id && entry.runId === 'audit-fixture');
  expect(finding, `Synthetic ordinary finding ${id} is available`).toBeTruthy();
  await page.goto('/?' + new URLSearchParams({ view: 'findings', finding: finding.key, mode: 'procedure', panel: 'graph' }));
  await expect(page.getByRole('region', { name: 'Attack explorer', exact: true })).toBeVisible();
  await expect(page.locator('.graph-evidence-node')).toHaveCount(2);
  return finding.key as string;
}

function node(page: Page, title: string) {
  return page.locator('.react-flow__node').filter({ has: page.locator('.graph-node-title', { hasText: title }) });
}

function selectedId(page: Page) {
  return new URL(page.url()).searchParams.get('selected');
}

test('procedure, assessed trace and explicit composition expose independent records', async ({ page }) => {
  await page.goto('/');
  await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
  await page.screenshot({ path: '/private/tmp/stake-desktop.png', fullPage: true });
  await openFinding(page);
  await expect(page.locator('.graph-context-bar')).toContainText('2 recorded steps');
  await expect(page.locator('.react-flow__edge')).toHaveCount(1);
  await expect(page.locator('.graph-node-title')).toHaveText([firstAction, secondAction]);
  await node(page, firstAction).click();
  await page.locator('.stake-explorer').screenshot({ path: '/private/tmp/stake-graph.png' });

  await page.getByRole('tab', { name: 'Code trace', exact: true }).click();
  await expect(page.locator('.graph-evidence-node')).toHaveCount(8);
  await expect(page.locator('.react-flow__edge')).toHaveCount(7);
  await expect(page.locator('.graph-context-bar')).toContainText('Assessed trace · not a complete call graph');
  await node(page, 'commitApproval').click();
  const inspector = page.getByRole('complementary', { name: 'Selected evidence inspector' });
  await expect(inspector.getByRole('heading', { name: 'commitApproval', exact: true })).toBeVisible();
  await expect(inspector).toContainText('storefront/src/orders.ts:41');
  await expect(inspector).toContainText('sink');

  await page.getByRole('tab', { name: 'Composition', exact: true }).click();
  await expect(page.locator('.graph-evidence-node')).toHaveCount(2);
  await expect(page.locator('.react-flow__edge')).toHaveCount(1);
  await expect(page.locator('.graph-context-bar')).toContainText('Explicit capability transitions only');
  await node(page, 'Approval identity').click();
  await expect(inspector).toContainText('Browser to account identity');
  await expect(inspector).toContainText('Session selector');
  await page.getByRole('button', { name: 'Linear view', exact: true }).click();
  const transition = page.getByRole('button', { name: /P-2.*established.*Inspect transition/ });
  await transition.focus();
  await page.keyboard.press('Enter');
  await expect(inspector).toContainText('Capability transition');
  await expect(inspector).toContainText('The recorded identity is consumed by the approval handler.');
  await expect(inspector).toContainText('The caller chooses the selectors.');
  const selectedTransition = selectedId(page);
  expect(selectedTransition).toBeTruthy();
  await page.getByRole('button', { name: 'Show graph', exact: true }).click();
  expect(selectedId(page)).toBe(selectedTransition);
  await expect(page.locator('.react-flow__edge.selected')).toHaveCount(1);
});

test('proposed repair overlays interrupt exactly both referenced steps and clear cleanly', async ({ page }) => {
  await openFinding(page);
  await expect(page.locator('.graph-evidence-node.repair-highlight')).toHaveCount(0);
  await page.getByLabel('Show proposed repair', { exact: true }).selectOption('action-1');
  await expect(page.locator('.graph-evidence-node.repair-highlight')).toHaveCount(2);
  await expect(page.locator('.graph-evidence-node.repair-highlight .graph-node-title')).toHaveText([firstAction, secondAction]);
  await expect(page.locator('.graph-repair-summary')).toContainText('Proposed repair · action-1');
  await expect(page.locator('.graph-repair-summary').getByRole('button', { name: 'Read implementation instructions for storefront/src/orders.ts:42 of action-1', exact: true })).toBeVisible();
  await expect(page.locator('.graph-repair-summary')).toContainText('no applied or passing fix is implied');
  expect(new URL(page.url()).searchParams.get('repair')).toBe('action-1');

  await page.getByRole('button', { name: 'Linear view', exact: true }).click();
  await expect(page.locator('.graph-linear-item.repair-highlight')).toHaveCount(2);
  await expect(page.locator('.graph-linear-item .graph-repair-indicator')).toHaveText(['Proposed repair point', 'Proposed repair point']);
  await page.getByLabel('Show proposed repair', { exact: true }).selectOption('');
  await expect(page.locator('.graph-linear-item.repair-highlight')).toHaveCount(0);
  await expect(page.locator('.graph-repair-summary')).toHaveCount(0);
  expect(new URL(page.url()).searchParams.has('repair')).toBe(false);
  await page.getByRole('button', { name: 'Show graph', exact: true }).click();
  await expect(page.locator('.graph-evidence-node.repair-highlight')).toHaveCount(0);
  await expect(page.locator('.detail-badges')).toContainText('confirmed');
});

test('layout, group expansion, zoom, fit and browser history retain opaque selected identities', async ({ page }) => {
  const findingKey = await openFinding(page);
  await node(page, firstAction).click();
  const originalSelection = selectedId(page);
  expect(JSON.parse(originalSelection!)).toEqual(['entity', findingKey, 'procedure', 'step-1']);
  const inspector = page.getByRole('complementary', { name: 'Selected evidence inspector' });
  await page.locator('.graph-groups button').click();
  await expect(page.locator('.graph-evidence-node')).toHaveCount(1);
  await expect(page.locator('.graph-node-meta')).toContainText('2 RECORDS');
  expect(selectedId(page)).toBe(originalSelection);
  await expect(inspector.getByRole('heading', { name: firstAction, exact: true })).toBeVisible();
  await page.locator('.graph-evidence-node').click();
  await expect(page.locator('.graph-evidence-node')).toHaveCount(2);
  await expect(page.locator('.react-flow__node.selected .graph-node-title')).toHaveText(firstAction);

  const viewport = page.locator('.react-flow__viewport');
  const beforeZoom = await viewport.getAttribute('style');
  await page.getByRole('button', { name: 'Zoom In', exact: true }).click();
  await expect.poll(() => viewport.getAttribute('style')).not.toBe(beforeZoom);
  const canvas = await page.locator('.graph-canvas').boundingBox();
  expect(canvas).toBeTruthy();
  const beforePan = await viewport.getAttribute('style');
  await page.mouse.move(canvas!.x + 150, canvas!.y + canvas!.height - 75);
  await page.mouse.down();
  await page.mouse.move(canvas!.x + 195, canvas!.y + canvas!.height - 105, { steps: 5 });
  await page.mouse.up();
  await expect.poll(() => viewport.getAttribute('style')).not.toBe(beforePan);
  await page.getByRole('button', { name: 'Fit View', exact: true }).click();
  const slider = page.getByRole('slider', { name: 'Evidence inspector width' });
  await slider.focus();
  await page.keyboard.press('End');
  await expect(slider).toHaveValue('55');
  expect(selectedId(page)).toBe(originalSelection);
  await expect(inspector.getByRole('heading', { name: firstAction, exact: true })).toBeVisible();
  await expect(page.locator('.graph-layout-note')).toHaveCount(0);

  await node(page, secondAction).click();
  expect(selectedId(page)).not.toBe(originalSelection);
  await page.goBack();
  expect(selectedId(page)).toBe(originalSelection);
  await expect(inspector.getByRole('heading', { name: firstAction, exact: true })).toBeVisible();
  await page.reload();
  await expect(page.locator('.react-flow__node.selected .graph-node-title')).toHaveText(firstAction);
  expect(selectedId(page)).toBe(originalSelection);
  await node(page, secondAction).focus();
  await page.keyboard.press('Enter');
  await expect(inspector.getByRole('heading', { name: secondAction, exact: true })).toBeVisible();
});

test('linear keyboard selection preserves canvas evidence, status, examples and repair links', async ({ page }) => {
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await openFinding(page);
  await node(page, firstAction).click();
  const originalSelection = selectedId(page);
  const inspector = page.getByRole('complementary', { name: 'Selected evidence inspector' });
  const canvasEvidence = await inspector.locator('.graph-inspector-content').innerText();
  await page.getByRole('button', { name: 'Linear view', exact: true }).focus();
  await page.keyboard.press('Enter');
  await expect(page.locator('.graph-linear-item')).toHaveCount(2);
  await expect(page.locator('.graph-linear-item.active')).toContainText(firstAction);
  expect(selectedId(page)).toBe(originalSelection);
  await expect(inspector.locator('.graph-inspector-content')).toHaveText(canvasEvidence, { useInnerText: true });
  await expect(page.locator('.graph-linear-item .graph-status')).toHaveText(['source established', 'source established']);

  await page.locator('.graph-linear-item').first().focus();
  await page.keyboard.press('Tab');
  await expect(page.locator('.graph-linear-item').nth(1)).toBeFocused();
  await page.keyboard.press('Enter');
  await expect(inspector.getByRole('heading', { name: secondAction, exact: true })).toBeVisible();
  await expect(inspector).toContainText('No observation recorded');
  await expect(inspector).toContainText('not executed');
  await expect(inspector.locator('pre')).toContainText('SYNTHETIC_ORDER');
  await expect(inspector.locator('.graph-repair-card')).toContainText('action-1 · Proposed repair');
  const secondSelection = selectedId(page);
  await page.getByRole('button', { name: 'Show graph', exact: true }).click();
  expect(selectedId(page)).toBe(secondSelection);
  await expect(page.locator('.react-flow__node.selected .graph-node-title')).toHaveText(secondAction);
  await inspector.getByRole('button', { name: 'sast/verified-findings.json:C-001', exact: true }).focus();
  await page.keyboard.press('Enter');
  await expect(page.getByRole('dialog')).toBeVisible();
  await expect(page.getByRole('dialog')).toContainText('Synthetic canonical support.');
});

test('environment-required steps remain labeled and empty composition never invents a chain', async ({ page }) => {
  await openFinding(page, 'F-002');
  await expect(page.locator('.graph-evidence-node .graph-status')).toHaveText(['environment required', 'environment required']);
  await page.getByRole('button', { name: 'Linear view', exact: true }).click();
  await expect(page.locator('.graph-linear-item .graph-status')).toHaveText(['environment required', 'environment required']);
  await page.locator('.graph-linear-item').first().focus();
  await page.keyboard.press('Enter');
  const inspector = page.getByRole('complementary', { name: 'Selected evidence inspector' });
  await expect(inspector).toContainText('No observation recorded');
  await expect(inspector).toContainText('environment required');
  await page.getByRole('tab', { name: 'Composition', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'No composition recorded', exact: true })).toBeVisible();
  await expect(page.locator('.react-flow__edge')).toHaveCount(0);
  await expect(page.locator('.graph-linear-item')).toHaveCount(0);
  await page.getByRole('tab', { name: 'Code trace', exact: true }).click();
  await expect(page.locator('.graph-linear-item')).toHaveCount(8);
});

test('explicit reproduction map links select exact graph identities while repair links open the recorded step', async ({ page }) => {
  const findingKey = await openFinding(page);
  await page.getByRole('tab', { name: /^Reproduce/ }).click();
  await page.getByRole('button', { name: 'Show in attack map', exact: true }).nth(1).click();
  const inspector = page.getByRole('complementary', { name: 'Selected evidence inspector' });
  await expect(inspector.getByRole('heading', { name: secondAction, exact: true })).toBeVisible();
  expect(JSON.parse(selectedId(page)!)).toEqual(['entity', findingKey, 'procedure', 'step-2']);
  await page.getByRole('tab', { name: /^Repair/ }).click();
  await page.getByRole('button', { name: /^Read reproduction step step-1:/ }).click();
  await expect(page.getByRole('tab', { name: /^Reproduce/ })).toHaveAttribute('data-state', 'active');
  const step = page.locator('.reproduce-panel').getByRole('region', { name: firstAction, exact: true });
  await expect(step).toBeFocused();
  expect(JSON.parse(new URL(page.url()).searchParams.get('detailRecord')!)).toEqual(['step', 'step-1']);
  expect(selectedId(page)).toBeNull();
  await step.getByRole('button', { name: 'Show in attack map', exact: true }).click();
  await expect(inspector.getByRole('heading', { name: firstAction, exact: true })).toBeVisible();
  expect(JSON.parse(selectedId(page)!)).toEqual(['entity', findingKey, 'procedure', 'step-1']);
  await expect(page.getByRole('heading', { name: 'Selection unavailable', exact: true })).toHaveCount(0);
});

test('a large graph keeps every collapsed record reachable without changing selection', async ({ page }) => {
  await page.route('**/api/findings/*', async route => {
    const response = await route.fetch();
    const finding = await response.json();
    if (finding.id === 'F-001') {
      const step = finding.raw.exploitation.steps[0];
      finding.raw.exploitation.steps = Array.from({ length: 120 }, (_, index) => ({
        ...step, id: `large-step-${index + 1}`, action: `Synthetic procedure action ${index + 1}`,
      }));
      finding.stepCount = 120;
    }
    await route.fulfill({ response, json: finding });
  });
  const response = await page.request.get('/api/workspace');
  const workspace = await response.json();
  const finding = workspace.findings.find((entry: { id: string; runId: string }) => entry.id === 'F-001' && entry.runId === 'audit-fixture');
  await page.goto('/?' + new URLSearchParams({ view: 'findings', finding: finding.key, mode: 'procedure', panel: 'graph' }));
  await expect(page.locator('.graph-evidence-node')).toHaveCount(120);
  await expect(page.locator('.react-flow__edge')).toHaveCount(119);
  await page.getByRole('button', { name: 'Linear view', exact: true }).click();
  await expect(page.locator('.graph-linear-item')).toHaveCount(120);
  await page.locator('.graph-linear-item').last().focus();
  await page.keyboard.press('Enter');
  const selection = selectedId(page);
  await expect(page.getByRole('complementary', { name: 'Selected evidence inspector' })).toContainText('large-step-120');
  await page.getByRole('button', { name: 'Show graph', exact: true }).click();
  await page.locator('.graph-groups button').click();
  await expect(page.locator('.graph-evidence-node')).toHaveCount(1);
  await expect(page.locator('.graph-node-meta')).toContainText('120 RECORDS');
  expect(selectedId(page)).toBe(selection);
  await page.locator('.graph-evidence-node').click();
  await expect(page.locator('.graph-evidence-node')).toHaveCount(120);
  await expect(page.locator('.react-flow__node.selected .graph-node-title')).toHaveText('Synthetic procedure action 120');
  expect(selectedId(page)).toBe(selection);
  await expect(page.locator('.graph-layout-note')).toHaveCount(0);
});
