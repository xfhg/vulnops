import { expect, test } from '@playwright/test';
import type { FindingRecord } from '../../src/domain';

const findingKey = JSON.stringify(['finding', 'audit-fixture', 'F-001']);
const change = 'Bind the approval session to its initiating account. ' +
  'Authorize the selected order against that account before changing approval state, and retain the legitimate owner workflow. '.repeat(4) +
  'Preserve the complete recorded authorization change through the final commit.';
const additional = 'Synthetic additional implementation context is retained with the original action.';
const stepAction = 'Request approval of another synthetic account’s order.';

test('finding instructions lead to exact reproduction text, qualified repair map, complete dossier and verification', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.route('**/api/findings**', async route => {
    const response = await route.fetch();
    const payload = await response.json() as FindingRecord | { items: FindingRecord[] };
    const findings = 'items' in payload ? payload.items : [payload];
    for (const finding of findings) if (finding.key === findingKey) {
      const action = finding.raw.remediation!.actions[0];
      action.change = change;
      action.additional_guidance = additional;
    }
    await route.fulfill({ response, json: payload });
  });
  await page.goto('/?' + new URLSearchParams({ view: 'findings', finding: findingKey }));
  const detail = page.locator('.finding-detail');
  const tabs = detail.getByRole('tablist', { name: 'Finding detail', exact: true });
  await expect(tabs.getByRole('tab', { name: 'Summary', exact: true })).toHaveAttribute('data-state', 'active');
  await expect(page.getByRole('region', { name: 'Attack explorer', exact: true })).toHaveCount(0);
  await expect.poll(async () => {
    const header = await detail.locator('.finding-header').boundingBox();
    const tabList = await tabs.boundingBox();
    return Boolean(header && tabList && tabList.y >= header.y + header.height - 1 && tabList.y - header.y - header.height < 80);
  }).toBe(true);
  await detail.locator('.finding-header').getByRole('button', { name: 'Read repair instructions', exact: true }).focus();
  await page.keyboard.press('Enter');
  await expect(tabs.getByRole('tab', { name: /^Repair/ })).toHaveAttribute('data-state', 'active');
  const action = detail.locator('.repair-implementation-card[data-repair-id="action-1"]');
  await expect(action.locator('.repair-complete-change p')).toHaveText(change);
  await expect(action.locator('.repair-complete-change p')).toBeVisible();
  await expect(action.getByRole('region', { name: 'Repair location orders.ts:42', exact: true })).toContainText('42');
  await expect(page.getByRole('region', { name: 'Attack explorer', exact: true })).toHaveCount(0);
  await action.getByRole('button', { name: `Read reproduction step step-2: ${stepAction}`, exact: true }).focus();
  await page.keyboard.press('Enter');
  await expect(tabs.getByRole('tab', { name: /^Reproduce/ })).toHaveAttribute('data-state', 'active');
  expect(JSON.parse(new URL(page.url()).searchParams.get('detailRecord')!)).toEqual(['step', 'step-2']);
  expect(new URL(page.url()).searchParams.get('selected')).toBeNull();
  const step = detail.getByRole('region', { name: stepAction, exact: true });
  await expect(step).toBeFocused();
  await expect(step).toContainText('No observation recorded; no execution claimed.');
  await page.reload();
  await expect(step).toBeFocused();
  await step.getByRole('button', { name: 'Read repair action-1', exact: true }).click();
  await expect(tabs.getByRole('tab', { name: /^Repair/ })).toHaveAttribute('data-state', 'active');
  expect(new URL(page.url()).searchParams.get('repair')).toBe('action-1');
  await expect(action).toBeFocused();
  await action.getByRole('button', { name: 'Open technical example example-1', exact: true }).click();
  const example = detail.getByRole('region', { name: 'Recorded technical example example-1', exact: true });
  await expect(example).toBeFocused();
  expect(JSON.parse(new URL(page.url()).searchParams.get('detailRecord')!)).toEqual(['example', 'example-1']);
  await expect(example).toContainText('SYNTHETIC_ORDER');
  await expect(example).toContainText('not executed');
  await tabs.getByRole('tab', { name: /^Repair/ }).click();
  await action.getByText('Complete action record', { exact: true }).click();
  await expect(action.getByText(additional, { exact: true })).toBeVisible();
  await action.getByRole('button', { name: 'Open repair map', exact: true }).click();

  const workspace = page.getByRole('region', { name: 'Repair workspace', exact: true });
  await expect(workspace.getByRole('tab', { name: 'Repair map', exact: true })).toHaveAttribute('aria-selected', 'true');
  await expect(workspace.locator('.rc-canvas')).toHaveAttribute('data-layout-status', 'ready');
  const repairRoute = new URL(page.url()).searchParams;
  expect(repairRoute.get('repairView')).toBe('map');
  expect(JSON.parse(repairRoute.get('repairAction')!)).toEqual(['repair-entry', findingKey, 'audit-fixture', 'scope-1', 'base', 'action-1']);
  await expect(workspace.locator('.rm-active-header h2')).toHaveText(change);
  const picker = workspace.getByRole('combobox', { name: 'Select repair map record', exact: true });
  const actionOption = picker.locator('option').filter({ hasText: /^Proposed repair · action-1 ·/ });
  await picker.selectOption((await actionOption.getAttribute('value'))!);
  await workspace.getByRole('region', { name: 'Repair record details', exact: true }).getByRole('button', { name: 'Open repair details', exact: true }).click();
  await expect(tabs.getByRole('tab', { name: /^Repair/ })).toHaveAttribute('data-state', 'active');
  expect(new URL(page.url()).searchParams.get('finding')).toBe(findingKey);
  expect(new URL(page.url()).searchParams.get('repair')).toBe('action-1');
  await expect(action.locator('.repair-complete-change p')).toHaveText(change);
  await detail.getByRole('button', { name: 'Review verification checks', exact: true }).click();
  const verification = detail.getByRole('region', { name: 'Fix verification', exact: true });
  await expect(tabs.getByRole('tab', { name: 'Verify', exact: true })).toHaveAttribute('data-state', 'active');
  await expect(verification).toContainText('The unauthorized approval is rejected without mutation.');
  await expect(verification).toContainText('The authorized approval succeeds.');
  await expect(verification).toContainText('proposed');
  await expect(verification.locator('.verification-card .badge')).not.toHaveText(/passed|fixed/i);
  await expect(page.getByRole('region', { name: 'Attack explorer', exact: true })).toHaveCount(0);
  expect(errors).toEqual([]);
});

test('proposed repair location alerts open the exact owning action guide and restore it on reload without an evidence drawer', async ({ page }) => {
  const evidenceRequests: string[] = [];
  page.on('request', request => {
    const pathname = new URL(request.url()).pathname;
    if (pathname === '/api/reference' || pathname.startsWith('/api/evidence/')) evidenceRequests.push(pathname);
  });
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.route('**/api/findings/*', async route => {
    const response = await route.fetch();
    const finding = await response.json() as FindingRecord;
    const first = finding.raw.remediation!.actions[0];
    finding.raw.remediation!.actions.push({ ...structuredClone(first), id: 'action-2',
      change: `Authorize the fulfillment consumer for the recorded ${finding.runId} account boundary.`,
      example_ids: ['source-target', 'source-other-range'],
      locations: [
        { file: 'storefront/src/orders.ts', line: 42, mechanism: `First location for ${finding.runId}.` },
        { file: 'storefront/src/fulfillment-consumer.ts', start_line: 64, end_line: 68, scope: 'completeApproval', mechanism: `Preserve the exact ${finding.runId} ownership decision at the fulfillment commit.` },
      ],
    });
    finding.raw.technical_examples!.push(
      { id: 'source-target', kind: 'source', content: `ORIGINAL_SOURCE_${finding.runId}\nretain_recorded_account_boundary();`, execution_status: 'not_executed', evidence_refs: ['storefront/src/fulfillment-consumer.ts:64-68'] },
      { id: 'source-other-range', kind: 'source', content: 'UNRELATED_SOURCE_RANGE', execution_status: 'not_executed', evidence_refs: ['storefront/src/fulfillment-consumer.ts:1-10'] },
    );
    await route.fulfill({ response, json: finding });
  });

  for (const [run, id] of [['audit-fixture', 'F-001'], ['advantage-fixture', 'F-060']] as const) {
    const narrow = run === 'advantage-fixture';
    if (narrow) {
      await page.setViewportSize({ width: 390, height: 844 });
      await page.addInitScript(() => localStorage.setItem('stake-theme', 'dark'));
    }
    const key = JSON.stringify(['finding', run, id]);
    const reference = 'storefront/src/fulfillment-consumer.ts:64-68';
    const record = JSON.stringify(['repair-location', 'action-2', 1]);
    await page.goto('/?' + new URLSearchParams({ view: 'findings', finding: key, panel: 'graph', repair: 'action-2' }));
    const alert = page.getByRole('region', { name: 'Proposed repair action-2', exact: true });
    await expect(alert).toContainText(`recorded ${run} account boundary`);
    await alert.getByRole('button', { name: `Read implementation instructions for ${reference} of action-2`, exact: true }).focus();
    await page.keyboard.press('Enter');
    const route = new URL(page.url()).searchParams;
    expect(route.get('finding')).toBe(key);
    expect(route.get('panel')).toBe('repair');
    expect(route.get('repair')).toBe('action-2');
    expect(route.get('detailRecord')).toBe(record);
    const guide = page.locator('[data-detail-record]').filter({ hasText: `Preserve the exact ${run} ownership decision at the fulfillment commit.` });
    await expect(guide).toHaveCount(1);
    await expect(guide).toHaveAttribute('data-detail-record', record);
    await expect(guide).toBeFocused();
    await expect(guide).toContainText('storefront/src/fulfillment-consumer.ts');
    await expect(guide).toContainText('completeApproval');
    await expect(guide).toContainText(`ORIGINAL_SOURCE_${run}`);
    await expect(guide).not.toContainText('UNRELATED_SOURCE_RANGE');
    await expect(guide).toContainText('not executed');
    await expect(page.locator('.repair-implementation-card[data-repair-id="action-2"]').getByRole('region', { name: 'Repair location orders.ts:42', exact: true }))
      .toContainText('No source excerpt is recorded for this location.');
    await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBe(true);
    await guide.screenshot({ path: `/private/tmp/atstake-repair-source-guide-${narrow ? 'mobile-dark' : 'desktop-light'}.png` });
    await expect(page.getByRole('dialog')).toHaveCount(0);
    await page.reload();
    await expect(guide).toBeFocused();
    await expect(page.getByRole('dialog')).toHaveCount(0);
    expect(new URL(page.url()).searchParams.get('finding')).toBe(key);
    expect(evidenceRequests).toEqual([]);

    await page.getByRole('tab', { name: 'Attack map', exact: true }).click();
    await alert.getByRole('button', { name: 'Read implementation instructions', exact: true }).click();
    expect(new URL(page.url()).searchParams.get('detailRecord')).toBeNull();
    await expect(page.locator('.repair-implementation-card[data-repair-id="action-2"]')).toBeFocused();
    await expect(page.getByRole('dialog')).toHaveCount(0);
  }
  expect(evidenceRequests).toEqual([]);
});
