import { expect, test, type Page } from '@playwright/test';
import type { FindingRecord } from '../../src/domain';

const findingKey = JSON.stringify(['finding', 'audit-fixture', 'F-001']);
const limitation = 'Synthetic fixture: no service or deployment binding was established for this component.';
const selectedId = (page: Page) => new URL(page.url()).searchParams.get('selected');

async function openGraph(page: Page, mode = 'procedure') {
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.goto('/?' + new URLSearchParams({ view: 'attacks', finding: findingKey, mode, panel: 'graph' }));
  const graph = page.getByRole('region', { name: 'Attack explorer', exact: true });
  await expect(graph).toBeVisible();
  await expect(graph.locator('.graph-canvas')).toHaveAttribute('data-layout-status', 'ready');
  return graph;
}

test('opening connected records before selecting a node fits the complete metadata shelf inside the canvas', async ({ page }) => {
  const graph = await openGraph(page);
  expect(selectedId(page)).toBeNull();
  await graph.getByRole('button', { name: 'Connected records', exact: true }).click();
  await expect(graph.locator('.graph-connected-node')).toHaveCount(6);
  const canvas = graph.locator('.graph-canvas');
  await expect.poll(() => canvas.evaluate(element => {
    const viewport = element.getBoundingClientRect();
    const records = [...element.querySelectorAll('.graph-connected-node')];
    return records.length === 6 && records.every(record => {
      const bounds = record.getBoundingClientRect();
      return bounds.width > 0 && bounds.height > 0 && bounds.left >= viewport.left - 1 && bounds.right <= viewport.right + 1
        && bounds.top >= viewport.top - 1 && bounds.bottom <= viewport.bottom + 1;
    });
  })).toBe(true);
  await canvas.screenshot({ path: '/private/tmp/stake-connected-records-fitted.png', animations: 'disabled' });
});

test('connected records retain exact associations, keyboard selection, URL restoration and linear evidence access', async ({ page }) => {
  await page.route('**/api/findings/*', async route => {
    const response = await route.fetch(); const finding: FindingRecord = await response.json();
    if (finding.runId === 'audit-fixture' && finding.id === 'F-001') {
      finding.raw.affected_components![0].service = { name: null, binding: 'unknown', limitation, evidence_refs: [] };
    }
    await route.fulfill({ response, json: finding });
  });
  const graph = await openGraph(page);
  await graph.locator('.react-flow__node').first().focus(); await page.keyboard.press('Enter');
  const primary = selectedId(page);
  await graph.getByRole('button', { name: 'Connected records', exact: true }).focus(); await page.keyboard.press('Space');
  await expect(graph.locator('.graph-evidence-node')).toHaveCount(2);
  await expect(graph.locator('.graph-connected-node')).toHaveCount(6);
  await expect(graph.locator('.react-flow__edge')).toHaveCount(7);
  for (const label of ['References component', 'References primitive', 'References example', 'Proposes interrupting step']) {
    const edge = graph.locator('.react-flow__edge').filter({ hasText: label });
    await expect(edge).toHaveCount(1);
    expect(await edge.locator('.react-flow__edge-path').evaluate(path => ({ dash: getComputedStyle(path).strokeDasharray, arrow: path.getAttribute('marker-end') })))
      .toEqual({ dash: '3px, 5px', arrow: null });
  }
  await expect(graph.locator('.graph-context-bar')).toContainText('dotted links are associations, not execution flow');
  const component = graph.locator('.react-flow__node').filter({ has: page.locator('.graph-kind-component') });
  await component.focus(); await page.keyboard.press('Enter');
  const metadata = selectedId(page);
  expect(metadata).not.toBe(primary);
  const identity = JSON.parse(metadata!);
  expect(identity.slice(0, 3)).toEqual(['entity', findingKey, 'connected']);
  expect(JSON.parse(identity[3])).toEqual(['procedure', primary, 'component', 'component-1']);
  const inspector = graph.getByRole('complementary', { name: 'Selected evidence inspector' });
  await expect(inspector.getByRole('heading', { name: 'Storefront', exact: true })).toBeVisible();
  await expect(inspector).toContainText(limitation); await expect(inspector).toContainText('unknown');
  const canvasEvidence = await inspector.locator('.graph-inspector-content').innerText();

  await page.reload();
  await expect(graph.getByRole('button', { name: 'Connected records', exact: true })).toHaveAttribute('aria-pressed', 'true');
  await expect(graph.locator('.react-flow__node.selected .graph-node-title')).toHaveText('Storefront');
  expect(selectedId(page)).toBe(metadata);
  await graph.getByRole('button', { name: 'Linear view', exact: true }).click();
  await expect(inspector.locator('.graph-inspector-content')).toHaveText(canvasEvidence, { useInnerText: true });
  const linear = graph.getByRole('region', { name: 'Connected records', exact: true });
  await expect(linear.locator('.graph-connection-link')).toHaveCount(6);
  const example = linear.locator('.graph-connection-link').filter({ hasText: 'example-1 · request' });
  await example.focus(); await page.keyboard.press('Enter');
  await expect(inspector).toContainText('not executed'); await expect(inspector).toContainText('SYNTHETIC_ORDER');
  const evidence = linear.locator('.graph-connection-link').filter({ hasText: 'sast/verified-findings.json:C-001' });
  await evidence.focus(); await page.keyboard.press('Space');
  await inspector.getByRole('button', { name: 'sast/verified-findings.json:C-001', exact: true }).click();
  await expect(page.getByRole('dialog')).toContainText('Synthetic canonical support.');
  await page.getByRole('button', { name: 'Close evidence', exact: true }).click();

  await graph.getByRole('button', { name: 'Connected records', exact: true }).click();
  expect(selectedId(page)).toBe(primary);
  await expect(graph.locator('.graph-connected-list')).toHaveCount(0);
  await graph.getByRole('button', { name: 'Show graph', exact: true }).click();
  await expect(graph.locator('.graph-connected-node')).toHaveCount(0);
  await expect(graph.locator('.react-flow__edge')).toHaveCount(1);
});

test('selected neighborhood preserves original trace edges and returns to all records without changing URL selection', async ({ page }) => {
  const graph = await openGraph(page, 'trace');
  await expect(graph.locator('.graph-evidence-node')).toHaveCount(8);
  await graph.locator('.react-flow__node').nth(3).focus(); await page.keyboard.press('Enter');
  const selected = selectedId(page);
  const focus = graph.getByRole('button', { name: 'Selected neighborhood', exact: true });
  await focus.click();
  await expect(graph.locator('.graph-evidence-node')).toHaveCount(3);
  await expect(graph.locator('.react-flow__edge')).toHaveCount(2);
  await expect(graph.locator('.graph-context-bar')).toContainText('Showing 3 of 8 records · 5 outside this neighborhood');
  expect(await graph.locator('.react-flow__node').evaluateAll(nodes => nodes.map(node => JSON.parse(node.getAttribute('data-id')!)[3])))
    .toEqual(['trace-3', 'trace-4', 'trace-5']);
  expect(selectedId(page)).toBe(selected);
  await graph.getByRole('button', { name: 'Focus selected nodes', exact: true }).click();
  await expect(graph.locator('.react-flow__node.selected .graph-node-title')).toHaveText('approvalStage4');
  await focus.click();
  await expect(graph.locator('.graph-evidence-node')).toHaveCount(8);
  await expect(graph.locator('.react-flow__edge')).toHaveCount(7);
  expect(selectedId(page)).toBe(selected);
  await graph.getByRole('button', { name: 'Linear view', exact: true }).click();
  await expect(graph.locator('.graph-linear-item')).toHaveCount(8);
  await expect(graph.locator('.graph-linear-item.active')).toContainText('approvalStage4');
});

test('composition callouts expose contradicted obligations without implying a successful transition', async ({ page }) => {
  await page.route('**/api/findings/*', async route => {
    const response = await route.fetch(); const finding: FindingRecord = await response.json();
    if (finding.runId === 'audit-fixture' && finding.id === 'F-001') {
      finding.raw.transitions![0].resolution = { outcome: 'contradicted', reason: 'Synthetic consumer rejects the recorded capability.' };
      finding.raw.transitions![0].obligations = {
        actor_control: { outcome: 'established', evidence_refs: ['sast/verified-findings.json:C-001'] },
        consumer_authority: { outcome: 'contradicted', reason: 'Synthetic authority check rejects the handoff.' },
        external_binding: {},
      };
    }
    await route.fulfill({ response, json: finding });
  });
  const graph = await openGraph(page, 'composition');
  const transition = graph.getByRole('button', { name: 'Inspect transition: contradicted. 3 recorded obligations · 2 not established', exact: true });
  await expect(transition).toHaveClass(/uncertain/);
  await expect(transition).toContainText('3 recorded obligations · 2 not established');
  await transition.focus(); await page.keyboard.press('Enter');
  const inspector = graph.getByRole('complementary', { name: 'Selected evidence inspector' });
  await expect(inspector).toContainText('Synthetic consumer rejects the recorded capability.');
  await expect(inspector).toContainText('Synthetic authority check rejects the handoff.');
  await expect(inspector.locator('.graph-status')).toHaveText('contradicted');
  await graph.getByRole('button', { name: 'Connected records', exact: true }).click();
  await expect(graph.locator('.graph-connected-node.graph-kind-transition')).toHaveCount(1);
  await expect(graph.locator('.graph-evidence-node')).toHaveCount(2);
  await expect(graph.locator('.graph-transition-label')).toHaveCount(1);
  await expect(graph.locator('.graph-context-bar')).toContainText('Explicit capability transitions only');
});
