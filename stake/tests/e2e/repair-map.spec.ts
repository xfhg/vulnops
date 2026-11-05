import { expect, test, type Locator, type Page } from '@playwright/test';
import type { FindingRecord } from '../../src/domain';
import type { WorkspaceResponse } from '../../src/domain/sources';

const auditFinding = JSON.stringify(['finding', 'audit-fixture', 'F-001']);
const advantageFinding = JSON.stringify(['finding', 'advantage-fixture', 'F-060']);
const longChange = 'Bind the recorded approval session to its initiating account before authorizing the selected order. '.repeat(7).trim();
const longRationale = 'The proposed control preserves account identity through the recorded ownership decision. '.repeat(8).trim();

async function mutateFindings(page: Page, mutate: (finding: FindingRecord) => void) {
  await page.route('**/api/findings**', async route => {
    const response = await route.fetch();
    const payload = await response.json() as FindingRecord | { items: FindingRecord[] };
    if ('items' in payload) payload.items.forEach(mutate);
    else mutate(payload);
    await route.fulfill({ response, json: payload });
  });
}

async function openRepairs(page: Page, query: Record<string, string> = {}, map = true) {
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.goto('/?' + new URLSearchParams({ view: 'remediation', ...query }));
  const workspace = page.getByRole('region', { name: 'Repair workspace', exact: true });
  await expect(workspace).toBeVisible();
  if (map) await showMap(page);
  return workspace;
}

async function showMap(page: Page) {
  await page.getByRole('tab', { name: 'Repair map', exact: true }).click();
  await expect(page.locator('.rc-canvas')).toBeVisible();
  await expect(page.locator('.rc-canvas')).toHaveAttribute('data-layout-status', 'ready');
}

async function chooseAction(page: Page, findingId: string, runId = 'audit-fixture', actionId = 'action-1', map = true) {
  const toggle = page.getByRole('button', { name: 'Choose a repair', exact: true });
  if (await toggle.isVisible() && await toggle.getAttribute('aria-expanded') === 'false') await toggle.click();
  await actionButton(page, findingId, runId, actionId).click();
  await expect(page.getByRole('tab', { name: 'Repair brief', exact: true })).toHaveAttribute('aria-selected', 'true');
  if (map) await showMap(page);
}

function actionButton(page: Page, findingId: string, runId = 'audit-fixture', actionId = 'action-1') {
  return page.getByRole('complementary', { name: 'Repair actions', exact: true })
    .getByRole('button', { name: `Select repair ${findingId} / ${actionId} · ${runId}`, exact: true });
}

async function selectRecord(page: Page, label: RegExp) {
  const picker = page.getByRole('combobox', { name: 'Select repair map record', exact: true });
  const option = picker.locator('option').filter({ hasText: label });
  await expect(option).toHaveCount(1);
  const id = await option.getAttribute('value');
  expect(id).toBeTruthy();
  await picker.selectOption(id!);
  await expect(picker).toHaveValue(id!);
  expect(new URL(page.url()).searchParams.get('repairSelected')).toBe(id);
  return id!;
}

function inspector(page: Page) {
  return page.getByRole('region', { name: 'Repair record details', exact: true });
}

function metric(workspace: Locator, label: string) {
  return workspace.locator('.rm-metrics > div').filter({ hasText: label }).locator('strong');
}

test('repair brief is the default and explicit presentation choices take precedence over selected-record deep links', async ({ page }) => {
  const workspace = await openRepairs(page, {}, false);
  const brief = workspace.getByRole('region', { name: 'Repair brief', exact: true });
  const briefTab = workspace.getByRole('tab', { name: 'Repair brief', exact: true });
  await expect(briefTab).toHaveAttribute('aria-selected', 'true');
  await expect(brief).toBeVisible();
  await expect(workspace.locator('.rc-canvas')).not.toBeVisible();
  await expect(inspector(page)).not.toBeVisible();
  for (const name of ['Why this change', 'Locate the change', 'Understand interruption', 'Review verification']) {
    await expect(brief.getByRole('heading', { name, exact: true })).toBeVisible();
  }
  await page.getByRole('searchbox', { name: 'Search repair actions', exact: true }).fill('F-060');
  await expect(workspace.locator('.rm-queue-item')).toHaveCount(1);
  await expect(workspace.locator('.rm-active-header')).toContainText('F-060 / action-1');
  await brief.getByRole('button', { name: 'Open full repair dossier', exact: true }).click();
  await expect(page.locator('.finding-detail h1')).toHaveText('Order approval reaches the fulfillment consumer');
  await expect(page.getByRole('tab', { name: /^Repair/ })).toHaveAttribute('data-state', 'active');
  expect(new URL(page.url()).searchParams.get('finding')).toBe(advantageFinding);
  expect(new URL(page.url()).searchParams.get('repair')).toBe('action-1');
  await page.getByRole('button', { name: 'Back to repair brief', exact: true }).click();
  await expect(briefTab).toHaveAttribute('aria-selected', 'true');
  await expect(workspace.locator('.rm-active-header')).toContainText('F-060 / action-1');
  expect(JSON.parse(new URL(page.url()).searchParams.get('repairAction')!)[1]).toBe(advantageFinding);
  // Re-enter a filter without explicit selection to exercise the independent tab/reload route.
  await page.getByRole('searchbox', { name: 'Search repair actions', exact: true }).fill('F-060');
  expect(new URL(page.url()).searchParams.get('repairAction')).toBeNull();
  await showMap(page);
  const filteredAction = new URL(page.url()).searchParams.get('repairAction');
  expect(JSON.parse(filteredAction!)[1]).toBe(advantageFinding);
  await page.reload();
  await expect(workspace.locator('.rm-active-header')).toContainText('F-060 / action-1');
  await expect(workspace.getByRole('tab', { name: 'Repair map', exact: true })).toHaveAttribute('aria-selected', 'true');
  await workspace.getByRole('tab', { name: /^All repair records/ }).click();
  await page.reload();
  expect(new URL(page.url()).searchParams.get('repairAction')).toBe(filteredAction);
  await expect(workspace.locator('.rm-active-header')).toContainText('F-060 / action-1');
  await expect(workspace.getByRole('tab', { name: /^All repair records/ })).toHaveAttribute('aria-selected', 'true');
  await chooseAction(page, 'F-060', 'advantage-fixture', 'action-1', false);
  const action = new URL(page.url()).searchParams.get('repairAction')!;
  // An action alone opens its brief; only a record selection implies a map.
  await page.goto('/?' + new URLSearchParams({ view: 'remediation', repairAction: action }));
  await expect(briefTab).toHaveAttribute('aria-selected', 'true');
  await expect(workspace.locator('.rc-canvas')).not.toBeVisible();
  await page.getByRole('searchbox', { name: 'Search repair actions', exact: true }).fill('F-001');
  await expect(workspace.locator('.rm-queue-item')).toHaveCount(1);
  await page.goBack();
  await expect(workspace.locator('.rm-active-header')).toContainText('F-060 / action-1');
  await expect(page.getByRole('searchbox', { name: 'Search repair actions', exact: true })).toHaveValue('F-001');
  await expect(workspace.getByRole('heading', { name: 'Selected repair unavailable', exact: true })).toHaveCount(0);
  await showMap(page);
  const step = await selectRecord(page, /^Procedure step · step-1 ·/);
  await page.goto('/?' + new URLSearchParams({ view: 'remediation', repairAction: action, repairSelected: step }));
  await expect(workspace.getByRole('tab', { name: 'Repair map', exact: true })).toHaveAttribute('aria-selected', 'true');
  await expect(workspace.locator('.rc-canvas')).toBeVisible();
  await expect(inspector(page)).toBeVisible();
  await briefTab.click();
  expect(new URL(page.url()).searchParams.get('repairView')).toBe('brief');
  expect(new URL(page.url()).searchParams.get('repairSelected')).toBe(step);
  await expect(brief).toBeVisible();
  await expect(workspace.locator('.rc-canvas')).not.toBeVisible();
  await expect(inspector(page)).not.toBeVisible();
  await page.reload();
  await expect(briefTab).toHaveAttribute('aria-selected', 'true');
  await expect(inspector(page)).not.toBeVisible();
  await workspace.getByRole('tab', { name: /^All repair records/ }).click();
  await workspace.locator('.rm-record').filter({ has: page.getByText('step-2', { exact: true }) }).click();
  await expect(workspace.getByRole('tab', { name: /^All repair records/ })).toHaveAttribute('aria-selected', 'true');
  expect(new URL(page.url()).searchParams.get('repairView')).toBe('records');
  await expect(inspector(page).getByRole('heading', { level: 3 })).toHaveText('Request approval of another synthetic account’s order.');
  await chooseAction(page, 'F-001', 'audit-fixture', 'action-1', false);
  expect(new URL(page.url()).searchParams.get('repairSelected')).toBeNull();
  await expect(inspector(page)).not.toBeVisible();
  await expect(brief).toBeVisible();
  await workspace.screenshot({ path: '/private/tmp/atstake-repair-brief-desktop.png' });
});

test('qualified repair and record selection survives history and opens the exact owning attack step', async ({ page }) => {
  const workspace = await openRepairs(page);
  await expect(workspace.locator('.rm-queue-item')).toHaveCount(4);
  await expect(metric(workspace, 'proposed actions')).toHaveText('4');
  await expect(metric(workspace, 'finding-level checks')).toHaveText('4');
  const advantage = actionButton(page, 'F-060', 'advantage-fixture');
  await advantage.focus();
  await page.keyboard.press('Enter');
  await expect(advantage).toHaveAttribute('aria-pressed', 'true');
  const action = new URL(page.url()).searchParams.get('repairAction');
  expect(JSON.parse(action!)).toEqual(['repair-entry', advantageFinding, 'advantage-fixture', 'scope-1', 'base', 'action-1']);
  await showMap(page);
  const step = await selectRecord(page, /^Procedure step · step-2 ·/);
  await expect(inspector(page).getByRole('heading', { level: 3 })).toHaveText('Request approval of another synthetic account’s order.');
  await page.reload();
  await expect(workspace.locator('.rc-canvas')).toHaveAttribute('data-layout-status', 'ready');
  expect(new URL(page.url()).searchParams.get('repairAction')).toBe(action);
  expect(new URL(page.url()).searchParams.get('repairSelected')).toBe(step);
  await expect(advantage).toHaveAttribute('aria-pressed', 'true');
  await expect(page.getByLabel('Select repair map record', { exact: true })).toHaveValue(step);
  await chooseAction(page, 'F-001', 'audit-fixture', 'action-1', false);
  expect(new URL(page.url()).searchParams.get('repairSelected')).toBeNull();
  expect(JSON.parse(new URL(page.url()).searchParams.get('repairAction')!)[1]).toBe(auditFinding);
  await page.goBack();
  await expect(advantage).toHaveAttribute('aria-pressed', 'true');
  await expect(page.getByLabel('Select repair map record', { exact: true })).toHaveValue(step);
  await inspector(page).getByRole('button', { name: 'Open attack step', exact: true }).focus();
  await page.keyboard.press('Enter');
  await expect(page.locator('.finding-detail h1')).toHaveText('Order approval reaches the fulfillment consumer');
  const route = new URL(page.url()).searchParams;
  expect(route.get('finding')).toBe(advantageFinding);
  expect(route.get('repair')).toBe('action-1');
  expect(route.get('panel')).toBe('reproduce');
  expect(route.get('selected')).toBeNull();
  expect(JSON.parse(route.get('detailRecord')!)).toEqual(['step', 'step-2']);
  await expect(page.locator('.reproduce-panel').getByRole('region', { name: 'Request approval of another synthetic account’s order.', exact: true })).toBeFocused();
});

test('repair source navigation preserves the selected coordinate and its assessment scope', async ({ page }) => {
  await mutateFindings(page, finding => {
    if (finding.key === auditFinding) finding.raw.remediation!.actions[0].evidence_refs!.unshift('storefront/src/orders.ts:10');
  });
  const workspace = await openRepairs(page, { run: 'audit-fixture' });
  await chooseAction(page, 'F-001');
  const location = await selectRecord(page, /^Source location · location-1 ·/);
  const graphNode = workspace.locator('.react-flow__node-repairRecord').filter({ has: page.locator('.rc-record-location') });
  await expect(graphNode).toHaveAttribute('data-id', location);
  await graphNode.focus();
  await page.keyboard.press('Enter');
  await workspace.locator('.rc-record-toolbar').getByRole('button', { name: 'Read implementation instructions', exact: true }).click();
  const guide = page.getByRole('region', { name: 'Repair location orders.ts:42', exact: true });
  await expect(guide).toBeFocused();
  expect(new URL(page.url()).searchParams.get('finding')).toBe(auditFinding);
  expect(JSON.parse(new URL(page.url()).searchParams.get('detailRecord')!)).toEqual(['repair-location', 'action-1', 0]);
  await expect(guide).toContainText('Line 42');
  await expect(guide).toContainText('storefront/src/orders.ts');
  await expect(page.getByRole('dialog')).toHaveCount(0);
  await page.getByRole('button', { name: 'Back to repair map', exact: true }).click();
  await expect(page.getByLabel('Select repair map record', { exact: true })).toHaveValue(location);
  await inspector(page).getByRole('button', { name: 'Open in Code Map', exact: true }).click();
  await expect(page.getByRole('region', { name: 'Cited code map', exact: true })).toBeVisible();
  expect(JSON.parse(new URL(page.url()).searchParams.get('location')!)).toEqual(['audit-fixture', 'scope-1', 'base', 'storefront/src/orders.ts']);
  await expect(page.locator('.code-scope')).toContainText('audit-fixture');
  await expect(page.locator('.code-path-title')).toHaveText('storefront/src/orders.ts');
});

test('an embedded historical repair opens its code without selecting an unloaded owning assessment', async ({ page }) => {
  await page.route('**/api/workspace', async route => {
    const response = await route.fetch();
    const payload = await response.json() as WorkspaceResponse;
    payload.assessments = payload.assessments.filter(assessment => assessment.id === 'advantage-fixture');
    for (const finding of payload.findings) if (finding.runId === 'audit-fixture') finding.origin = 'historical';
    await route.fulfill({ response, json: payload });
  });
  await mutateFindings(page, finding => { if (finding.runId === 'audit-fixture') finding.origin = 'historical'; });
  await openRepairs(page);
  await expect(page.getByRole('combobox', { name: 'Select assessment', exact: true }).locator('option[value="audit-fixture"]')).toHaveCount(0);
  await chooseAction(page, 'F-001');
  await selectRecord(page, /^Source location · location-1 ·/);
  await inspector(page).getByRole('button', { name: 'Open in Code Map', exact: true }).click();
  await expect(page.getByRole('region', { name: 'Cited code map', exact: true })).toBeVisible();
  const route = new URL(page.url()).searchParams;
  expect(route.get('run')).toBeNull();
  expect(JSON.parse(route.get('location')!)).toEqual(['audit-fixture', 'scope-1', 'base', 'storefront/src/orders.ts']);
  await expect(page.locator('.code-scope')).toContainText('Execution: audit-fixture');
  await expect(page.locator('.code-path-title')).toHaveText('storefront/src/orders.ts');
  await expect(page.getByRole('heading', { name: 'Assessment unavailable', exact: true })).toHaveCount(0);
  await expect(page.getByRole('heading', { name: 'Selected file unavailable', exact: true })).toHaveCount(0);
});

test('dense repair windows retain every record and reveal the exact selected interruption connection', async ({ page }) => {
  await mutateFindings(page, finding => {
    if (finding.key !== auditFinding) return;
    const action = finding.raw.remediation!.actions[0];
    const location = action.locations![0];
    action.locations = Array.from({ length: 5 }, (_, index) => ({ ...location, line: 42 + index }));
    const step = finding.raw.exploitation!.steps[0];
    finding.raw.exploitation!.steps = Array.from({ length: 6 }, (_, index) => ({ ...structuredClone(step), id: `step-${index + 1}`, action: `Recorded synthetic procedure action ${index + 1}.` }));
    action.breaks_steps = finding.raw.exploitation!.steps.map(step => step.id);
  });
  const workspace = await openRepairs(page, { run: 'audit-fixture' });
  await chooseAction(page, 'F-001', 'audit-fixture', 'action-1', false);
  const brief = workspace.getByRole('region', { name: 'Repair brief', exact: true });
  await expect(brief.locator('.rb-location-preview')).toHaveCount(3);
  await brief.getByRole('button', { name: 'Explore all 5 change locations', exact: true }).click();
  await expect(workspace.getByRole('tab', { name: 'Repair map', exact: true })).toHaveAttribute('aria-selected', 'true');
  await expect(workspace.locator('.rc-canvas')).toHaveAttribute('data-layout-status', 'ready');
  await expect(workspace.locator('.rc-visible-count')).toHaveText('7 of 17 records · 6 of 16 connections');
  await expect(workspace.locator('.rc-record-location')).toHaveCount(3);
  await expect(workspace.locator('.rc-record-step')).toHaveCount(3);
  await workspace.getByRole('button', { name: 'Next repair targets page', exact: true }).click();
  await expect(workspace.locator('.rc-record-location')).toHaveCount(2);
  await expect(workspace.locator('.rc-record-component')).toHaveCount(1);
  await expect(workspace.getByRole('button', { name: 'Next repair targets page', exact: true })).toBeDisabled();
  await workspace.getByRole('button', { name: 'Next steps and examples page', exact: true }).click();
  await expect(workspace.locator('.rc-record-step .rc-record-title')).toHaveText([
    'Recorded synthetic procedure action 4.', 'Recorded synthetic procedure action 5.', 'Recorded synthetic procedure action 6.',
  ]);
  await workspace.getByRole('tab', { name: 'Repair brief', exact: true }).click();
  await expect(workspace.locator('.rc-canvas')).not.toBeVisible();
  await showMap(page);
  await expect(workspace.locator('.rc-record-location')).toHaveCount(2);
  await expect(workspace.getByRole('button', { name: 'Next repair targets page', exact: true })).toBeDisabled();
  await expect(workspace.locator('.rc-record-step .rc-record-title')).toHaveText([
    'Recorded synthetic procedure action 4.', 'Recorded synthetic procedure action 5.', 'Recorded synthetic procedure action 6.',
  ]);
  const selectedStep = await selectRecord(page, /^Procedure step · step-6 ·/);
  const interruption = inspector(page).locator('.rm-related button').filter({ hasText: 'Proposed interruption' });
  await interruption.focus();
  await page.keyboard.press('Enter');
  await expect(inspector(page).getByRole('heading', { name: 'Proposed interruption', exact: true })).toBeVisible();
  await expect(inspector(page).locator('.rm-edge-description')).toContainText('explicitly names step-6 in breaks_steps');
  const selectedEdge = new URL(page.url()).searchParams.get('repairSelected')!;
  const edgeIdentity = JSON.parse(selectedEdge) as string[];
  expect(edgeIdentity[3]).toBe(selectedStep);
  expect(edgeIdentity[4]).toBe('interruption');
  expect(JSON.parse(edgeIdentity[2])[2]).toBe('action');
  await expect(workspace.locator('.rc-canvas .react-flow__edge.selected')).toHaveAttribute('data-id', selectedEdge);
  await workspace.getByRole('group', { name: 'Repair map navigation', exact: true }).getByRole('button', { name: 'Focus selected nodes', exact: true }).click();
  await expect.poll(() => workspace.locator('.rc-canvas').evaluate((canvas, ids) => {
    const bounds = canvas.getBoundingClientRect();
    const endpoints = [...canvas.querySelectorAll('.react-flow__node-repairRecord')].filter(node => ids.includes(node.getAttribute('data-id')!));
    return endpoints.length === 2 && endpoints.every(node => {
      const rect = node.getBoundingClientRect();
      return rect.width > 0 && rect.left >= bounds.left - 1 && rect.right <= bounds.right + 1 && rect.top >= bounds.top - 1 && rect.bottom <= bounds.bottom + 1;
    });
  }, [edgeIdentity[2], selectedStep])).toBe(true);
  await workspace.getByRole('button', { name: 'Show steps and examples', exact: true }).click();
  await expect(workspace.locator('.rc-hidden-selection')).toContainText('outside this window');
  await workspace.getByRole('button', { name: 'Show selected', exact: true }).click();
  await expect(workspace.locator('.rc-canvas .react-flow__edge.selected')).toHaveAttribute('data-id', selectedEdge);
  await workspace.getByRole('tab', { name: /^All repair records/ }).click();
  await expect(workspace.locator('.rm-record')).toHaveCount(17);
  await expect(workspace.locator('.rm-record').filter({ hasText: 'Recorded synthetic procedure action 6.' })).toHaveCount(1);
});

test('checks remain finding-level context across multiple actions and executed does not mean passed', async ({ page }) => {
  await mutateFindings(page, finding => {
    if (finding.key !== auditFinding) return;
    const remediation = finding.raw.remediation!;
    remediation.actions.push({ ...structuredClone(remediation.actions[0]), id: 'action-2', change: 'Authorize the owner before committing the synthetic approval.', breaks_steps: ['step-2'] });
    remediation.verification_checks!.push({ ...structuredClone(remediation.verification_checks![0]), id: 'check-2',
      description: 'A recorded synthetic check was executed without a recorded pass or fail outcome.', status: 'executed', evidence_refs: [] });
  });
  const workspace = await openRepairs(page);
  await expect(metric(workspace, 'proposed actions')).toHaveText('5');
  await expect(metric(workspace, 'findings with guidance')).toHaveText('4');
  await expect(metric(workspace, 'finding-level checks')).toHaveText('5');
  await chooseAction(page, 'F-001', 'audit-fixture', 'action-2');
  const check = await selectRecord(page, /^Finding-level check · check-1 ·/);
  await expect(inspector(page).locator('.rm-context-label')).toContainText('Finding-level context · recorded for F-001; no action-specific link is recorded.');
  await expect(inspector(page).locator('header .badge')).toHaveText('proposed');
  await expect(inspector(page)).toContainText('The unauthorized approval is rejected without mutation.');
  await expect(inspector(page)).toContainText('The authorized approval succeeds.');
  await expect(workspace.getByRole('button', { name: 'Show finding context', exact: true })).toHaveAttribute('aria-pressed', 'true');
  const incoming = await workspace.locator('.rc-canvas .react-flow__edge').evaluateAll((edges, target) => edges
    .map(edge => JSON.parse(edge.getAttribute('data-id')!) as string[]).filter(edge => edge[3] === target), check);
  expect(incoming).toHaveLength(1);
  expect(JSON.parse(incoming[0][2])[2]).toBe('finding');
  expect(incoming[0][4]).toBe('context');
  await selectRecord(page, /^Finding-level check · check-2 ·/);
  await expect(inspector(page).locator('header .badge')).toHaveText('executed');
  await expect(inspector(page).locator('.rm-no-evidence')).toHaveText('No supporting references recorded for this item.');
  await expect(inspector(page).locator('header .badge')).not.toHaveText(/passed|fixed|verified/i);
  await expect(metric(workspace, 'finding-level checks')).toHaveText('5');
  await workspace.locator('.rm-detail').screenshot({ path: '/private/tmp/atstake-repair-map-desktop.png' });
  await inspector(page).getByRole('button', { name: 'Open verification', exact: true }).click();
  expect(new URL(page.url()).searchParams.get('finding')).toBe(auditFinding);
  await expect(page.getByRole('tab', { name: 'Verify', exact: true })).toHaveAttribute('data-state', 'active');
  await expect(page.getByRole('region', { name: 'Fix verification', exact: true })).toContainText('executed');
});

test('missing explicit bindings remain inspectable without a fabricated available record or handoff', async ({ page }) => {
  await mutateFindings(page, finding => {
    if (finding.key !== auditFinding) return;
    const action = finding.raw.remediation!.actions[0];
    action.locations = [];
    action.component_ids = ['missing-component'];
    action.breaks_steps = ['step-1', 'missing-step'];
    action.example_ids = ['missing-example'];
  });
  const workspace = await openRepairs(page);
  await page.getByRole('combobox', { name: 'Filter repair actions', exact: true }).selectOption('no_locations');
  await expect(workspace.locator('.rm-queue-item')).toHaveCount(1);
  await expect(actionButton(page, 'F-001')).toHaveAttribute('aria-pressed', 'true');
  const brief = workspace.getByRole('region', { name: 'Repair brief', exact: true });
  await expect(brief).toContainText('No change locations recorded.');
  await expect(brief.getByRole('button', { name: 'Inspect 1 unavailable target reference', exact: true })).toBeVisible();
  await brief.getByRole('button', { name: 'Inspect 2 unavailable interruption references', exact: true }).click();
  await expect(workspace.getByRole('tab', { name: 'Repair map', exact: true })).toHaveAttribute('aria-selected', 'true');
  await expect(inspector(page).getByRole('heading', { level: 3 })).toHaveText('Unavailable step: missing-step');
  await workspace.getByRole('tab', { name: /^All repair records/ }).click();
  const unavailable = workspace.locator('.rm-record').filter({ hasText: 'Unavailable step: missing-step' });
  await unavailable.focus();
  await page.keyboard.press('Enter');
  await expect(workspace.getByRole('tab', { name: /^All repair records/ })).toHaveAttribute('aria-selected', 'true');
  expect(new URL(page.url()).searchParams.get('repairView')).toBe('records');
  await expect(inspector(page).getByRole('heading', { level: 3 })).toHaveText('Unavailable step: missing-step');
  await expect(inspector(page).locator('header .badge')).toHaveText('Unavailable record');
  await expect(inspector(page)).toContainText('No step with this ID is available in the owning finding.');
  await expect(inspector(page).getByRole('button', { name: 'Open attack step', exact: true })).toHaveCount(0);
  await expect(workspace.locator('.rm-record').filter({ hasText: 'Unavailable component: missing-component' })).toHaveCount(1);
  await expect(workspace.locator('.rm-record').filter({ hasText: 'Unavailable example: missing-example' })).toHaveCount(1);
  await workspace.getByRole('tab', { name: 'Repair map', exact: true }).click();
  await expect(workspace.locator('.rc-record-step.rc-record-unavailable')).toContainText('missing-step');
  await selectRecord(page, /^Procedure step · missing-step ·/);
  await expect(workspace.locator('.rc-record-toolbar').getByRole('button', { name: 'Open record', exact: true })).toBeDisabled();
  await expect(workspace.locator('.rm-diagnostics summary')).toContainText('3 unresolved record references');
  await page.getByRole('searchbox', { name: 'Search repair actions', exact: true }).fill('no matching synthetic action');
  await expect(workspace.getByText('No actions match these filters.', { exact: true })).toBeVisible();
  await workspace.getByRole('button', { name: 'Reset repair filters', exact: true }).click();
  await expect(workspace.locator('.rm-queue-item')).toHaveCount(4);
});

for (const theme of ['light', 'dark'] as const) test(`narrow ${theme} repair map retains complete guidance and keyboard-accessible navigation`, async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.setViewportSize({ width: 390, height: 844 });
  await page.addInitScript(value => localStorage.setItem('stake-theme', value), theme);
  await mutateFindings(page, finding => {
    if (finding.key !== auditFinding) return;
    finding.raw.remediation!.actions[0].change = longChange;
    finding.raw.remediation!.actions[0].rationale = longRationale;
  });
  const workspace = await openRepairs(page, { run: 'audit-fixture' }, false);
  if (theme === 'dark') await expect(page.locator('html')).toHaveClass('dark');
  const brief = workspace.getByRole('region', { name: 'Repair brief', exact: true });
  await expect(brief).toBeVisible();
  await expect(inspector(page)).not.toBeVisible();
  const chooser = page.getByRole('button', { name: 'Choose a repair', exact: true });
  await expect(chooser).toHaveAttribute('aria-expanded', 'false');
  await chooser.focus();
  await page.keyboard.press('Enter');
  await expect(chooser).toHaveAttribute('aria-expanded', 'true');
  await actionButton(page, 'F-001').focus();
  await page.keyboard.press('Enter');
  await expect(chooser).toHaveAttribute('aria-expanded', 'false');
  await expect(workspace.locator('.rm-active-header h2')).toHaveText(longChange);
  await brief.getByRole('button', { name: 'Show full rationale', exact: true }).focus();
  await page.keyboard.press('Enter');
  await expect(brief.getByText(longRationale, { exact: true })).toBeVisible();
  await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBe(true);
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.screenshot({ path: `/private/tmp/atstake-repair-brief-${theme}-mobile.png` });
  await showMap(page);
  await selectRecord(page, /^Proposed repair · action-1 ·/);
  const rationale = inspector(page).locator('.rm-detail-field').filter({ has: page.getByText('Rationale', { exact: true }) });
  await rationale.locator('summary').focus();
  await page.keyboard.press('Enter');
  await expect(rationale.locator('details > p')).toHaveText(longRationale);
  const navigator = workspace.getByRole('group', { name: 'Repair map navigation', exact: true });
  await navigator.getByRole('button', { name: 'Zoom In', exact: true }).focus();
  await page.keyboard.press('Enter');
  await page.keyboard.press('ArrowRight');
  await page.keyboard.press('Home');
  await selectRecord(page, /^Procedure step · step-1 ·/);
  await expect(workspace.locator('.rc-canvas')).toHaveAttribute('data-framing', 'record');
  await expect(inspector(page).getByRole('heading', { level: 3 })).toHaveText('Present the unbound approval session.');
  await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBe(true);
  await expect.poll(() => navigator.evaluate(element => {
    const bounds = element.closest('.rc-canvas')!.getBoundingClientRect();
    return [...element.querySelectorAll('button')].every(button => {
      const rect = button.getBoundingClientRect();
      return rect.width > 0 && rect.left >= bounds.left && rect.right <= bounds.right && rect.bottom <= bounds.bottom;
    });
  })).toBe(true);
  await workspace.locator('.repair-map-canvas').screenshot({ path: `/private/tmp/atstake-repair-map-${theme}-mobile.png` });
  expect(errors).toEqual([]);
});
