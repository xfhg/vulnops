import { expect, test, type Locator, type Page } from '@playwright/test';
import type { FindingRecord } from '../../src/domain';

const longCapability = 'A recorded approval capability preserves the initiating account and the complete order ownership boundary through every downstream consumer. '.repeat(12).trim();

async function mutateOverview(page: Page, mutate: (findings: FindingRecord[]) => void) {
  await page.route('**/api/findings?*', async route => {
    const response = await route.fetch();
    const payload = await response.json() as { items: FindingRecord[] };
    mutate(payload.items);
    await route.fulfill({ response, json: payload });
  });
}

async function openOverview(page: Page) {
  await page.goto('/?view=attacks');
  await expect(page.getByRole('region', { name: 'Attack overview', exact: true })).toBeVisible();
  await expect(page.locator('.ep-canvas')).toHaveAttribute('data-layout-status', 'ready');
}

function selectedOverviewId(page: Page) {
  return new URL(page.url()).searchParams.get('entrySelected');
}

async function installThreeChains(page: Page) {
  await mutateOverview(page, findings => {
    const template = findings.find(finding => finding.id === 'F-001')!;
    for (const finding of findings.filter(finding => ['F-001', 'F-003', 'F-060'].includes(finding.id))) {
      finding.kind = finding.raw.finding_kind = 'chain';
      finding.raw.primitive_steps = structuredClone(template.raw.primitive_steps);
      finding.raw.transitions = structuredClone(template.raw.transitions);
      finding.severity = finding.id === 'F-060' ? 'critical' : finding.id === 'F-003' ? 'low' : 'high';
      finding.raw.severity = finding.severity;
      if (finding.id === 'F-060') {
        finding.title = finding.raw.title = 'A separate fulfillment attack with a deliberately long recorded title. '.repeat(10).trim();
        finding.raw.primitive_steps![0].output_capability = longCapability;
      }
    }
  });
}

/** Inspect screen geometry after fitting; neither the test nor the graph may invent edges. */
async function compositionGeometry(canvas: Locator) {
  return canvas.evaluate(element => {
    const rect = (node: Element) => {
      const bounds = node.getBoundingClientRect();
      return { left: bounds.left, right: bounds.right, top: bounds.top, bottom: bounds.bottom, width: bounds.width, height: bounds.height };
    };
    const viewport = rect(element);
    const lanes = [...element.querySelectorAll('.ep-graph-lane')].map(lane => ({ id: lane.getAttribute('data-lane-id'), bounds: rect(lane), header: rect(lane.querySelector('.ep-lane-heading')!) }));
    const nodes = [...element.querySelectorAll('.react-flow__node-overview')].map(node => ({ id: node.getAttribute('data-id')!, bounds: rect(node) }));
    const within = (inner: ReturnType<typeof rect>, outer: ReturnType<typeof rect>) => inner.width > 0 && inner.height > 0
      && inner.left >= outer.left - 1 && inner.right <= outer.right + 1 && inner.top >= outer.top - 1 && inner.bottom <= outer.bottom + 1;
    const overlaps = (a: ReturnType<typeof rect>, b: ReturnType<typeof rect>) => Math.min(a.right, b.right) - Math.max(a.left, b.left) > 1
      && Math.min(a.bottom, b.bottom) - Math.max(a.top, b.top) > 1;
    return {
      laneCount: lanes.length,
      nodeCount: nodes.length,
      allFitted: lanes.every(lane => within(lane.bounds, viewport)) && nodes.every(node => within(node.bounds, viewport)),
      nodesInsideOwningLane: nodes.every(node => {
        // Entity IDs contain their execution-qualified finding key, never just P-1 or P-2.
        const findingKey = JSON.parse(node.id)[1];
        const lane = lanes.find(lane => lane.id === findingKey);
        return lane !== undefined && within(node.bounds, lane.bounds) && node.bounds.top >= lane.header.bottom - 1;
      }),
      laneOverlap: lanes.some((lane, index) => lanes.slice(index + 1).some(other => overlaps(lane.bounds, other.bounds))),
      nodeOverlap: nodes.some((node, index) => nodes.slice(index + 1).some(other => overlaps(node.bounds, other.bounds))),
    };
  });
}

test('entrypoint ordering is meaningful, URL-backed, and retains selection across reload and history', async ({ page }) => {
  await mutateOverview(page, findings => {
    for (const finding of findings) {
      const route = finding.id === 'F-002' ? 'GET /a-single' : finding.id === 'F-060' ? 'POST /m-priority' : 'POST /z-shared';
      finding.raw.affected_components![0].entrypoints = [route];
      if (finding.id === 'F-060' || finding.id === 'F-002') finding.severity = finding.raw.severity = 'critical';
    }
  });
  await openOverview(page);
  await expect(page.getByText('Evidence stays local', { exact: true })).toHaveCount(0);
  await expect(page.locator('.sidebar-note')).toHaveCount(0);
  const order = page.getByRole('combobox', { name: 'Order entrypoints', exact: true });
  await expect(order).toHaveValue('shared');
  await page.getByRole('button', { name: 'Linear entrypoint view', exact: true }).click();
  const routes = page.locator('.ep-linear-heading code');
  await expect(routes).toHaveText(['POST /z-shared', 'POST /m-priority', 'GET /a-single']);
  await page.locator('.ep-linear-heading').filter({ hasText: 'POST /z-shared' }).click();
  const selected = selectedOverviewId(page);
  expect(selected).toBeTruthy();

  await order.selectOption('priority');
  await expect(routes).toHaveText(['POST /m-priority', 'POST /z-shared', 'GET /a-single']);
  expect(new URL(page.url()).searchParams.get('entrySort')).toBe('priority');
  expect(selectedOverviewId(page)).toBe(selected);
  await order.selectOption('shared');
  expect(new URL(page.url()).searchParams.get('entrySort')).toBe('shared');
  await expect(routes).toHaveText(['POST /z-shared', 'POST /m-priority', 'GET /a-single']);
  await order.selectOption('route');
  await expect(routes).toHaveText(['GET /a-single', 'POST /m-priority', 'POST /z-shared']);
  expect(new URL(page.url()).searchParams.get('entrySort')).toBe('route');
  expect(selectedOverviewId(page)).toBe(selected);

  await page.reload();
  await expect(order).toHaveValue('route');
  await expect(page.locator('.ep-canvas')).toHaveAttribute('data-layout-status', 'ready');
  await expect(page.locator('.react-flow__node.selected .ep-node-title')).toHaveText('POST /z-shared');
  expect(selectedOverviewId(page)).toBe(selected);
  await page.goBack();
  await expect(order).toHaveValue('shared');
  expect(new URL(page.url()).searchParams.get('entrySort')).toBe('shared');
  expect(selectedOverviewId(page)).toBe(selected);
  await page.goBack();
  await expect(order).toHaveValue('priority');
  expect(selectedOverviewId(page)).toBe(selected);
  await expect(page.getByRole('complementary', { name: 'Entrypoint evidence inspector' }).getByRole('heading', { name: 'POST /z-shared', exact: true })).toBeVisible();
});

test('separate composed attacks fit within distinct lanes and sorting retains the qualified selected primitive', async ({ page }) => {
  await installThreeChains(page);
  await openOverview(page);
  await page.getByRole('tab', { name: /^Composed attacks/ }).click();
  const all = page.locator('.ep-all-compositions');
  const canvas = all.locator('.ep-canvas');
  const order = page.getByRole('combobox', { name: 'Order attacks', exact: true });
  const laneIds = () => all.locator('.ep-graph-lane').evaluateAll(lanes => lanes.map(lane => JSON.parse(lane.getAttribute('data-lane-id')!)[2] as string));
  await expect(canvas).toHaveAttribute('data-layout-status', 'ready');
  await expect(order).toHaveValue('priority');
  await expect.poll(laneIds).toEqual(['F-060', 'F-001', 'F-003']);
  await expect(all.locator('.react-flow__edge')).toHaveCount(3);
  await expect.poll(() => compositionGeometry(canvas)).toEqual({ laneCount: 3, nodeCount: 6, allFitted: true, nodesInsideOwningLane: true, laneOverlap: false, nodeOverlap: false });

  const primitive = all.locator('.react-flow__node').filter({ has: page.locator('.ep-node-title', { hasText: longCapability }) });
  await primitive.focus();
  await page.keyboard.press('Enter');
  const selected = selectedOverviewId(page);
  expect(JSON.parse(selected!)).toEqual(['entity', JSON.stringify(['finding', 'advantage-fixture', 'F-060']), 'composition', 'P-1']);
  await order.selectOption('id');
  await expect(canvas).toHaveAttribute('data-layout-status', 'ready');
  await expect.poll(laneIds).toEqual(['F-001', 'F-003', 'F-060']);
  expect(new URL(page.url()).searchParams.get('chainSort')).toBe('id');
  expect(selectedOverviewId(page)).toBe(selected);
  await order.selectOption('priority');
  expect(new URL(page.url()).searchParams.get('chainSort')).toBe('priority');
  await order.selectOption('id');

  await page.reload();
  await expect(order).toHaveValue('id');
  await expect(canvas).toHaveAttribute('data-layout-status', 'ready');
  await expect.poll(laneIds).toEqual(['F-001', 'F-003', 'F-060']);
  expect(selectedOverviewId(page)).toBe(selected);
  await expect(all.locator('.react-flow__node.selected .ep-node-title')).toHaveText(longCapability);
  await page.goBack();
  await expect(order).toHaveValue('priority');
  await expect.poll(laneIds).toEqual(['F-060', 'F-001', 'F-003']);
  expect(selectedOverviewId(page)).toBe(selected);
  await expect(page.getByRole('region', { name: 'Selected composed attack', exact: true })).toContainText('F-060 · advantage-fixture');
});

test('long node titles stay above their footer and remain complete in the evidence inspector', async ({ page }) => {
  await installThreeChains(page);
  await openOverview(page);
  await page.getByRole('tab', { name: /^Composed attacks/ }).click();
  const all = page.locator('.ep-all-compositions');
  await expect(all.locator('.ep-canvas')).toHaveAttribute('data-layout-status', 'ready');
  const primitive = all.locator('.react-flow__node').filter({ has: page.locator('.ep-node-title', { hasText: longCapability }) });
  const title = primitive.locator('.ep-node-title');
  await expect(title).toHaveAttribute('title', longCapability);
  await expect.poll(() => primitive.evaluate(node => {
    const title = node.querySelector('.ep-node-title')!;
    const caption = node.querySelector('.ep-node-caption')!;
    const footer = node.querySelector('.ep-node-status')!;
    return title.getBoundingClientRect().bottom <= caption.getBoundingClientRect().top + 1
      && caption.getBoundingClientRect().bottom <= footer.getBoundingClientRect().top + 1
      && footer.getBoundingClientRect().bottom <= node.getBoundingClientRect().bottom + 1
      && title.scrollHeight > title.clientHeight;
  })).toBe(true);
  await primitive.focus();
  await page.keyboard.press('Enter');
  const selected = page.getByRole('region', { name: 'Selected composed attack', exact: true });
  await expect(selected.getByRole('complementary', { name: 'Selected evidence inspector' }).getByRole('heading', { name: longCapability, exact: true })).toBeVisible();
  const detailed = selected.locator('.react-flow__node').filter({ has: page.locator('.graph-node-title', { hasText: longCapability }) });
  await expect(detailed.locator('.graph-node-title')).toHaveAttribute('title', longCapability);
  await expect.poll(() => detailed.evaluate(node => {
    const title = node.querySelector('.graph-node-title')!;
    const footer = node.querySelector('.graph-node-caption')!;
    return title.getBoundingClientRect().bottom <= footer.getBoundingClientRect().top + 1
      && footer.getBoundingClientRect().bottom <= node.getBoundingClientRect().bottom + 1;
  })).toBe(true);
});

test('detailed procedure and trace use recorded sequence, not identifier or source-line sorting', async ({ page }) => {
  const stepIds = ['step-20', 'step-3', 'step-10', 'step-1', 'step-7'];
  const traceLines = [91, 11, 81, 21, 71, 31, 61, 41];
  await page.route('**/api/findings/*', async route => {
    const response = await route.fetch();
    const payload = await response.json() as FindingRecord;
    if (payload.id === 'F-001') {
      const template = payload.raw.exploitation!.steps[0];
      payload.raw.exploitation!.steps = stepIds.map((id, index) => ({ ...template, id, action: `Recorded action ${index + 1} retains ${id}.` }));
      payload.raw.remediation!.actions[0].breaks_steps = stepIds;
      payload.raw.trace = payload.raw.trace!.map((entry, index) => ({ ...entry, line: traceLines[index], scope: `Recorded trace ${index + 1}` }));
    }
    await route.fulfill({ response, json: payload });
  });
  const finding = JSON.stringify(['finding', 'audit-fixture', 'F-001']);
  await page.goto('/?' + new URLSearchParams({ view: 'attacks', finding, mode: 'procedure', panel: 'graph' }));
  const graph = page.getByRole('region', { name: 'Attack explorer', exact: true });
  await expect(graph).toBeVisible();
  const nodes = graph.locator('.react-flow__node');
  await expect(graph.locator('.graph-node-title')).toHaveText(stepIds.map((id, index) => `Recorded action ${index + 1} retains ${id}.`));
  const recordedOrder = () => nodes.evaluateAll(nodes => nodes.map(node => ({ id: JSON.parse(node.getAttribute('data-id')!)[3] as string, x: node.getBoundingClientRect().x })));
  await expect.poll(async () => {
    const positions = await recordedOrder();
    return positions.length === stepIds.length && positions.every((node, index) => node.id === stepIds[index] && (index === 0 || node.x > positions[index - 1].x));
  }).toBe(true);

  await graph.getByRole('tab', { name: 'Code trace', exact: true }).click();
  await expect(graph.locator('.graph-node-title')).toHaveText(traceLines.map((_, index) => `Recorded trace ${index + 1}`));
  await expect.poll(async () => {
    const positions = await recordedOrder();
    return positions.length === traceLines.length && positions.every((node, index) => node.id === `trace-${index + 1}` && (index === 0 || node.x > positions[index - 1].x));
  }).toBe(true);
  await expect(graph.locator('.graph-node-caption')).toHaveText(traceLines.map(line => `storefront/src/orders.ts:${line}`));
  await expect(graph.locator('.graph-layout-note')).toHaveCount(0);
});
